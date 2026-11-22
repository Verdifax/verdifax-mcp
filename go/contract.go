// Package verdifaxmcp is the Verdifax MCP server in Go, held to the tool
// contract in mcp-tools.json. R users run the signed Go binary built from
// cmd/verdifax-mcp.
package verdifaxmcp

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// ContractBytes is the tool contract shipped inside this binary. The
// contract test fails when it differs from the repository's mcp-tools.json.
//
//go:embed mcp-tools.json
var ContractBytes []byte

type argumentRule [3]string

type exitMeaning [2]string

// Contract is the part of mcp-tools.json this server reads.
type Contract struct {
	Server struct {
		Name               string `json:"name"`
		Version            string `json:"version"`
		Title              string `json:"title"`
		Instructions       string `json:"instructions"`
		GrantsLineReported string `json:"grants_line_reported"`
		GrantsLineNone     string `json:"grants_line_none"`
	} `json:"server"`
	Tools          []json.RawMessage `json:"tools"`
	Implementation struct {
		DataNotice         string            `json:"data_notice"`
		Uses               map[string]string `json:"uses"`
		RefusedEnvironment map[string]string `json:"refused_environment"`
		KeyCheck           struct {
			Path               string `json:"path"`
			OwnerKeyError      string `json:"owner_key_error"`
			FeedKeyError       string `json:"feed_key_error"`
			AllowedToolsHeader string `json:"allowed_tools_header"`
		} `json:"key_check"`
		Verifier struct {
			TimeoutSeconds           int                    `json:"timeout_seconds"`
			MaxOutputBytes           int                    `json:"max_output_bytes"`
			StderrMaxChars           int                    `json:"stderr_max_chars"`
			EnvironmentRemovedPrefix string                 `json:"environment_removed_prefix"`
			RecordArguments          []argumentRule         `json:"record_arguments"`
			FeedArguments            []argumentRule         `json:"feed_arguments"`
			RecordExitCodes          map[string]exitMeaning `json:"record_exit_codes"`
			FeedExitCodes            map[string]exitMeaning `json:"feed_exit_codes"`
			UnknownExitCode          exitMeaning            `json:"unknown_exit_code"`
		} `json:"verifier"`
		TextCleaning struct {
			ReplaceWithSpace [][2]rune `json:"replace_with_space"`
			Remove           [][2]rune `json:"remove"`
		} `json:"text_cleaning"`
		Redaction struct {
			Replacement string `json:"replacement"`
			Pattern     string `json:"pattern"`
		} `json:"redaction"`
		Seal struct {
			DeclaredClientLabel    string `json:"declared_client_label"`
			DeclaredClientMaxBytes int    `json:"declared_client_max_bytes"`
		} `json:"seal"`
		FeedReading struct {
			PageLimit int `json:"page_limit"`
			MaxPages  int `json:"max_pages"`
		} `json:"feed_reading"`
		Limits struct {
			MaxAnswerBytes         int `json:"max_answer_bytes"`
			MaxPolicyDocumentBytes int `json:"max_policy_document_bytes"`
			RequestTimeoutSeconds  int `json:"request_timeout_seconds"`
		} `json:"limits"`
		HTTPMode struct {
			DefaultHost   string `json:"default_host"`
			DefaultPort   int    `json:"default_port"`
			Path          string `json:"path"`
			TokenMinChars int    `json:"token_min_chars"`
		} `json:"http_mode"`
		PrepareSignoff struct {
			CommandTemplate string   `json:"command_template"`
			Steps           []string `json:"steps"`
		} `json:"prepare_signoff"`
	} `json:"implementation"`
}

// ToolDefinition is one tool as the contract defines it.
type ToolDefinition struct {
	Name         string         `json:"name"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"inputSchema"`
	OutputSchema map[string]any `json:"outputSchema"`
	Annotations  map[string]any `json:"annotations"`
}

var (
	contract Contract
	tools    []ToolDefinition
)

func init() {
	if err := json.Unmarshal(ContractBytes, &contract); err != nil {
		panic(fmt.Sprintf("mcp-tools.json: %v", err))
	}
	for _, raw := range contract.Tools {
		var t ToolDefinition
		if err := json.Unmarshal(raw, &t); err != nil {
			panic(fmt.Sprintf("mcp-tools.json tool: %v", err))
		}
		tools = append(tools, t)
	}
}

// ToolNames lists the contract's tools in order.
func ToolNames() []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name)
	}
	return out
}

func toolDefinition(name string) (ToolDefinition, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t, true
		}
	}
	return ToolDefinition{}, false
}

// outputConst is the fixed text the contract's output schema gives a field.
func outputConst(tool, field string) string {
	t, ok := toolDefinition(tool)
	if !ok {
		panic("mcp-tools.json has no tool " + tool)
	}
	props, _ := t.OutputSchema["properties"].(map[string]any)
	f, _ := props[field].(map[string]any)
	value, ok := f["const"].(string)
	if !ok {
		panic(fmt.Sprintf("mcp-tools.json gives %s.%s no fixed text", tool, field))
	}
	return value
}
