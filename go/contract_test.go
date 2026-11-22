package verdifaxmcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Contract conformance: this implementation serves exactly the tools in
// mcp-tools.json, its copy of the contract is byte-identical to the root
// one, and the shared vectors come out the same as in every other language.

var contractNames = []string{"verify_record", "verify_feed", "get_record", "list_records", "read_feed", "list_pending_signoffs", "get_signoffs", "test_policy", "seal_decision", "prepare_signoff"}

func TestShippedContractIsByteIdenticalToTheRootCopy(t *testing.T) {
	root, err := os.ReadFile(filepath.Join("..", "mcp-tools.json"))
	must(t, err)
	if !bytes.Equal(root, ContractBytes) {
		t.Fatal("go/mcp-tools.json differs from the repository's mcp-tools.json")
	}
}

// normalized fills in the spec's default for an annotation hint left out,
// so a hint the SDK omits because it equals its default compares equal.
func normalized(tool map[string]any) map[string]any {
	ann, _ := tool["annotations"].(map[string]any)
	if ann != nil {
		defaults := map[string]bool{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true}
		for k, v := range defaults {
			if _, ok := ann[k]; !ok {
				ann[k] = v
			}
		}
	}
	return tool
}

func TestToolsListServesExactlyTheContractTools(t *testing.T) {
	var root struct {
		Tools []map[string]any `json:"tools"`
	}
	readJSON(t, filepath.Join("..", "mcp-tools.json"), &root)
	session := testConnect(t, baseConfig())
	listed, err := session.ListTools(context.Background(), nil)
	must(t, err)
	data, err := json.Marshal(listed.Tools)
	must(t, err)
	var served []map[string]any
	must(t, json.Unmarshal(data, &served))
	if len(served) != len(root.Tools) {
		t.Fatalf("served %d tools, the contract has %d", len(served), len(root.Tools))
	}
	// The Go SDK lists tools by name, so each served tool is matched to the
	// contract's tool of the same name.
	byName := map[string]map[string]any{}
	for _, tool := range served {
		byName[tool["name"].(string)] = tool
	}
	for _, want := range root.Tools {
		got, ok := byName[want["name"].(string)]
		if !ok {
			t.Fatalf("tool %s is not served", want["name"])
		}
		if !reflect.DeepEqual(normalized(got), normalized(want)) {
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			t.Fatalf("tool %s differs from the contract:\n got %s\nwant %s", want["name"], g, w)
		}
	}
}

func TestEveryContractToolHasAHandlerAndNoHandlerIsOutsideIt(t *testing.T) {
	want := append([]string(nil), contractNames...)
	sort.Strings(want)
	if got := HandlerNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("handlers %v", got)
	}
	if got := sortedKeys(contract.Implementation.Uses); !reflect.DeepEqual(got, want) {
		t.Fatalf("uses %v", got)
	}
}

func TestNoToolTakesASecretAsInput(t *testing.T) {
	forbidden := regexp.MustCompile(`(?i)key|secret|token|password|credential`)
	allowed := map[string]bool{"approver_public_key_path": true, "signer_public_key_path": true, "owner_request_key_paths": true}
	var walk func(schema map[string]any, path string)
	walk = func(schema map[string]any, path string) {
		props, _ := schema["properties"].(map[string]any)
		for name, sub := range props {
			if !allowed[name] && forbidden.MatchString(name) {
				t.Errorf("%s.%s looks like a secret field", path, name)
			}
			if m, ok := sub.(map[string]any); ok && m["type"] == "object" {
				walk(m, path+"."+name)
			}
		}
	}
	for _, tool := range tools {
		walk(tool.InputSchema, tool.Name)
	}
}

func TestInitializeNamesTheContractServerAndInstructions(t *testing.T) {
	session := testConnect(t, baseConfig())
	init := session.InitializeResult()
	if init.ServerInfo.Name != contract.Server.Name || init.ServerInfo.Version != contract.Server.Version {
		t.Fatalf("server info %+v", init.ServerInfo)
	}
	if !strings.HasPrefix(init.Instructions, contract.Server.Instructions) || !strings.HasSuffix(init.Instructions, contract.Server.GrantsLineNone) {
		t.Fatalf("instructions %q", init.Instructions)
	}
}

func TestSealDecisionBuildsAndSignsTheSharedVectorExactly(t *testing.T) {
	var vector struct {
		RequestKeyHex string `json:"request_key_hex"`
		SignedAt      string `json:"signed_at"`
		Nonce         string `json:"nonce"`
		Cases         []struct {
			Arguments        map[string]any    `json:"arguments"`
			ClientInfo       map[string]string `json:"client_info"`
			SignedRequest    string            `json:"signed_request"`
			RequestSignature map[string]any    `json:"request_signature"`
		} `json:"cases"`
	}
	readJSON(t, filepath.Join(testdata, "seal-vector.json"), &vector)
	key, err := hex.DecodeString(vector.RequestKeyHex)
	must(t, err)
	for i, c := range vector.Cases {
		body := sealBody(c.Arguments, declaredClient(c.ClientInfo["name"], c.ClientInfo["version"]))
		text, err := canonicalJSON(body)
		must(t, err)
		if text != c.SignedRequest {
			t.Fatalf("case %d body:\n got %s\nwant %s", i, text, c.SignedRequest)
		}
		signed, err := signBody(key, text, body, vector.SignedAt, vector.Nonce)
		must(t, err)
		if !reflect.DeepEqual(signed["request_signature"], c.RequestSignature) {
			t.Fatalf("case %d signature %v, want %v", i, signed["request_signature"], c.RequestSignature)
		}
	}
}

func TestPrepareSignoffPrintsTheSharedVectorCommandsExactly(t *testing.T) {
	var vector struct {
		Cases []struct {
			Arguments map[string]any `json:"arguments"`
			Command   string         `json:"command"`
		} `json:"cases"`
	}
	readJSON(t, filepath.Join(testdata, "prepare-signoff-vector.json"), &vector)
	for _, c := range vector.Cases {
		out, err := prepareSignoff(c.Arguments)
		must(t, err)
		if out["command"] != c.Command {
			t.Fatalf("command %q, want %q", out["command"], c.Command)
		}
	}
}

func TestTheEmDashAppearsNowhereInTheContract(t *testing.T) {
	if strings.Contains(string(ContractBytes), "\u2014") {
		t.Fatal("the contract holds an em dash")
	}
}
