package verdifaxmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The MCP server: tools/list serves the contract's tools exactly; tools/call
// checks the arguments against the contract's input schema, applies the
// key's reported grants, runs the handler, cleans and redacts the answer,
// and checks it against the contract's output schema before it is sent.

// Grants are the tools the server reported the member key may use; nil
// means the server reported no list.
type Grants struct {
	APIKey []string
}

// InstructionsFor is the contract's instructions with the grants line.
func InstructionsFor(grants Grants) string {
	line := contract.Server.GrantsLineNone
	if grants.APIKey != nil {
		names := "none"
		if len(grants.APIKey) > 0 {
			names = strings.Join(grants.APIKey, ", ")
		}
		line = strings.Replace(contract.Server.GrantsLineReported, "{tools}", names, 1)
	}
	return contract.Server.Instructions + " " + line
}

type schemas struct {
	input, output *jsonschema.Resolved
}

var resolved = map[string]schemas{}

func init() {
	for _, t := range tools {
		resolved[t.Name] = schemas{input: mustResolve(t.InputSchema), output: mustResolve(t.OutputSchema)}
	}
}

func mustResolve(schema map[string]any) *jsonschema.Resolved {
	data, marshalErr := json.Marshal(schema)
	if marshalErr != nil {
		panic(marshalErr)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(data, &s); err != nil {
		panic(err)
	}
	r, resolveErr := s.Resolve(nil)
	if resolveErr != nil {
		panic(resolveErr)
	}
	return r
}

func contains(list []string, name string) bool {
	for _, item := range list {
		if item == name {
			return true
		}
	}
	return false
}

// NewServer builds the MCP server over cfg with the reported grants.
func NewServer(cfg *Config, grants Grants) *mcp.Server {
	redactor := NewRedactor(cfg.Secrets())
	server := mcp.NewServer(
		&mcp.Implementation{Name: contract.Server.Name, Version: contract.Server.Version, Title: contract.Server.Title},
		&mcp.ServerOptions{Instructions: InstructionsFor(grants)},
	)
	failure := func(message string) *mcp.CallToolResult {
		text, _ := json.Marshal(map[string]any{"error": redactor.Text(message)})
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(text)}}}
	}
	for i, raw := range contract.Tools {
		var tool mcp.Tool
		if err := json.Unmarshal(raw, &tool); err != nil {
			panic(err)
		}
		name := tools[i].Name
		run := handlers[name]
		if run == nil {
			panic("no handler for " + name)
		}
		server.AddTool(&tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var args map[string]any
			if len(req.Params.Arguments) > 0 {
				if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
					return failure("Refused: the arguments are not a JSON object"), nil
				}
			}
			if args == nil {
				args = map[string]any{}
			}
			if err := resolved[name].input.Validate(args); err != nil {
				return failure("Refused: " + err.Error()), nil
			}
			if contract.Implementation.Uses[name] == "api_key" && grants.APIKey != nil && !contains(grants.APIKey, name) {
				return failure("Refused: the Verdifax server reports that this key's owner did not grant " + name), nil
			}
			info := runtimeInfo{cfg: cfg}
			if ci := req.ClientInfo(); ci != nil {
				info.clientName, info.clientVersion = ci.Name, ci.Version
			}
			answer, runErr := run(ctx, args, info)
			if runErr != nil {
				var te *ToolError
				if errors.As(runErr, &te) {
					return failure(te.Message), nil
				}
				return failure("The tool failed: " + runErr.Error()), nil
			}
			decoded, plainErr := plain(answer)
			if plainErr != nil {
				return failure("The tool failed: " + plainErr.Error()), nil
			}
			cleaned := redactor.Value(decoded)
			if err := resolved[name].output.Validate(cleaned); err != nil {
				return failure(fmt.Sprintf("This server built an answer its contract does not allow: %v", err)), nil
			}
			text, _ := marshalNoEscape(cleaned)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}, StructuredContent: cleaned}, nil
		})
	}
	return server
}

func marshalNoEscape(v any) (string, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}
