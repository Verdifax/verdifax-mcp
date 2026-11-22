package verdifaxmcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Test helpers: a local stand-in for the Verdifax API, a working folder, the
// stand-in verifier, and an MCP client joined to the server in memory. No
// test reaches api.verdifax.com or any paid service.

const (
	ownerError = "an account owner key manages the account and cannot run or read runs itself; use a member key, or the /account routes"
	feedError  = "a feed key reads the account's signal feed at GET /signals and nothing else"
)

var (
	memberKey = "vfx_" + strings.Repeat("1a", 24)
	feedKey   = "vfx_" + strings.Repeat("2b", 24)
	ownerKey  = "vfx_" + strings.Repeat("3c", 24)
	testdata  = filepath.Join("..", "testdata")
)

type recorded struct {
	method, path, key, body string
	query                   url.Values
}

type answer struct {
	status  int
	body    any
	headers map[string]string
}

type fakeAPI struct {
	url      string
	mu       sync.Mutex
	requests []recorded
}

func (f *fakeAPI) all() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func startAPI(t *testing.T, handle func(recorded) *answer) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		e := recorded{method: r.Method, path: r.URL.Path, key: r.Header.Get("X-Verdifax-Key"), body: string(data), query: r.URL.Query()}
		f.mu.Lock()
		f.requests = append(f.requests, e)
		f.mu.Unlock()
		out := handle(e)
		if out == nil {
			out = &answer{status: 404, body: map[string]any{"ok": false, "error": "not found"}}
		}
		for k, v := range out.headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(out.status)
		if s, ok := out.body.(string); ok {
			_, _ = io.WriteString(w, s)
			return
		}
		_ = json.NewEncoder(w).Encode(out.body)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func keyCheck(e recorded, headers map[string]string) *answer {
	if e.method == "GET" && e.path == "/stats" {
		switch e.key {
		case ownerKey:
			return &answer{status: 403, body: map[string]any{"ok": false, "error": ownerError}}
		case feedKey:
			return &answer{status: 403, body: map[string]any{"ok": false, "error": feedError}}
		}
		return &answer{status: 200, body: map[string]any{"ok": true, "total_runs": 0}, headers: headers}
	}
	return nil
}

func makeWorkdir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	must(t, os.MkdirAll(filepath.Join(dir, "records"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "records", "bundle.json"), []byte("{}"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "feed.json"), []byte("{}"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "policy.json"), []byte(`{"policy_id":"p"}`), 0o644))
	return dir
}

type stubVerifier struct{ path, argsFile string }

func makeVerifier(t *testing.T) stubVerifier {
	t.Helper()
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join(testdata, "fake-verdifax-verify"))
	must(t, err)
	path := filepath.Join(dir, "verdifax-verify")
	must(t, os.WriteFile(path, data, 0o755))
	v := stubVerifier{path: path, argsFile: filepath.Join(dir, "args.txt")}
	t.Setenv("FAKE_VERIFY_ARGS_FILE", v.argsFile)
	return v
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func connect(t *testing.T, cfg *Config, grants Grants, name, version string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverSide, clientSide := mcp.NewInMemoryTransports()
	if _, err := NewServer(cfg, grants).Connect(ctx, serverSide, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: name, Version: version}, nil)
	session, err := client.Connect(ctx, clientSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func testConnect(t *testing.T, cfg *Config) *mcp.ClientSession {
	return connect(t, cfg, Grants{}, "test-client", "9.9.9")
}

func call(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func structured(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", textOf(res))
	}
	data, err := json.Marshal(res.StructuredContent)
	must(t, err)
	var out map[string]any
	must(t, json.Unmarshal(data, &out))
	return out
}

func textOf(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func errorText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("expected a tool error, got %s", textOf(res))
	}
	var out map[string]string
	must(t, json.Unmarshal([]byte(textOf(res)), &out))
	return out["error"]
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	must(t, err)
	must(t, json.Unmarshal(data, into))
}

func baseConfig() *Config { return &Config{BaseURL: "http://127.0.0.1:9"} }

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}
