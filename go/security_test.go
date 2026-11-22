package verdifaxmcp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Security tests: owner-key refusal, refused environment, key file
// permissions, path traversal, hostile record strings and secret leaks.

var sealArgs = map[string]any{"program_id": strings.Repeat("a", 64), "route_id": "r", "registry_record_hash": strings.Repeat("b", 64), "payload_text": "x"}

var hiddenChars = regexp.MustCompile(`[\x{0}-\x{8}\x{b}\x{c}\x{e}-\x{1f}\x{7f}-\x{9f}\x{200b}-\x{200f}\x{202a}-\x{202e}\x{2060}-\x{206f}\x{feff}\x{e0000}-\x{e0fff}]`)

func isStartup(err error, pattern string) bool {
	var se *StartupError
	return errors.As(err, &se) && regexp.MustCompile(pattern).MatchString(se.Message)
}

func TestAnOwnerKeyStopsTheServerAtStartupAndNothingIsSealed(t *testing.T) {
	api := startAPI(t, func(e recorded) *answer { return keyCheck(e, nil) })
	_, _, err := Prepare(context.Background(), envOf(map[string]string{"VERDIFAX_BASE_URL": api.url, "VERDIFAX_API_KEY": ownerKey}))
	if !isStartup(err, `VERDIFAX_API_KEY is an account owner key\. This server never holds owner powers`) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), ownerKey) {
		t.Fatal("the error shows the key")
	}
	var seen []string
	for _, r := range api.all() {
		seen = append(seen, r.method+" "+r.path)
	}
	if !reflect.DeepEqual(seen, []string{"GET /stats"}) {
		t.Fatalf("requests %v", seen)
	}
}

func TestOwnerAndWrongKeysInEitherSlotAreRefused(t *testing.T) {
	api := startAPI(t, func(e recorded) *answer { return keyCheck(e, nil) })
	cases := []struct {
		env     map[string]string
		pattern string
	}{
		{map[string]string{"VERDIFAX_API_KEY": memberKey, "VERDIFAX_FEED_KEY": ownerKey}, "VERDIFAX_FEED_KEY is an account owner key"},
		{map[string]string{"VERDIFAX_API_KEY": feedKey}, "VERDIFAX_API_KEY is a feed key"},
		{map[string]string{"VERDIFAX_FEED_KEY": memberKey}, "not a feed key"},
	}
	for _, c := range cases {
		c.env["VERDIFAX_BASE_URL"] = api.url
		if _, _, err := Prepare(context.Background(), envOf(c.env)); !isStartup(err, c.pattern) {
			t.Fatalf("%v: got %v", c.env, err)
		}
	}
}

func TestReportedGrantsLimitTheTools(t *testing.T) {
	api := startAPI(t, func(e recorded) *answer {
		return keyCheck(e, map[string]string{"X-Verdifax-Allowed-Tools": "get_record, list_records, made_up_tool"})
	})
	cfg, grants, err := Prepare(context.Background(), envOf(map[string]string{"VERDIFAX_BASE_URL": api.url, "VERDIFAX_API_KEY": memberKey, "VERDIFAX_FEED_KEY": feedKey}))
	must(t, err)
	if !reflect.DeepEqual(grants.APIKey, []string{"get_record", "list_records"}) {
		t.Fatalf("grants %v", grants.APIKey)
	}
	session := connect(t, cfg, grants, "test-client", "1")
	if !strings.Contains(session.InitializeResult().Instructions, "granted these tools: get_record, list_records.") {
		t.Fatal(session.InitializeResult().Instructions)
	}
	if msg := errorText(t, call(t, session, "seal_decision", sealArgs)); !strings.Contains(msg, "did not grant seal_decision") {
		t.Fatal(msg)
	}
	for _, r := range api.all() {
		if r.path == "/execute" {
			t.Fatal("a refused tool sent a request")
		}
	}
}

func TestApproverAndOwnerKeysInTheEnvironmentStopTheServer(t *testing.T) {
	for _, name := range []string{"VERDIFAX_APPROVER_KEY", "VERDIFAX_APPROVER_KEY_FILE", "VERDIFAX_OWNER_KEY"} {
		if _, err := LoadConfig(envOf(map[string]string{name: "anything"})); !isStartup(err, name) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestRequestKeyFilePermissionsAndForms(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(strings.Repeat("\x07", 32))
	forms := map[string][]byte{"raw.key": raw, "hex.key": []byte(hex.EncodeToString(raw) + "\n"), "b64.key": []byte(base64.StdEncoding.EncodeToString(raw))}
	for name, content := range forms {
		path := filepath.Join(dir, name)
		must(t, os.WriteFile(path, content, 0o644))
		must(t, os.Chmod(path, 0o644))
		if _, err := LoadConfig(envOf(map[string]string{"VERDIFAX_API_KEY": memberKey, "VERDIFAX_REQUEST_KEY_FILE": path})); !isStartup(err, "group or others") {
			t.Fatalf("%s: %v", name, err)
		}
		must(t, os.Chmod(path, 0o600))
		cfg, err := LoadConfig(envOf(map[string]string{"VERDIFAX_API_KEY": memberKey, "VERDIFAX_REQUEST_KEY_FILE": path}))
		must(t, err)
		if string(cfg.RequestKey) != string(raw) {
			t.Fatalf("%s loaded the wrong key", name)
		}
	}
	bad := filepath.Join(dir, "bad.key")
	must(t, os.WriteFile(bad, []byte("not a key"), 0o600))
	if _, err := LoadConfig(envOf(map[string]string{"VERDIFAX_API_KEY": memberKey, "VERDIFAX_REQUEST_KEY_FILE": bad})); !isStartup(err, "32-byte private key") {
		t.Fatal(err)
	}
}

func TestPlainHTTPIsRefusedForAnyHostButThisMachine(t *testing.T) {
	if _, err := LoadConfig(envOf(map[string]string{"VERDIFAX_BASE_URL": "http://api.verdifax.com"})); !isStartup(err, "https") {
		t.Fatal(err)
	}
	if _, err := LoadConfig(envOf(map[string]string{"VERDIFAX_BASE_URL": "https://user:pw@api.verdifax.com"})); !isStartup(err, "user name") {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(envOf(map[string]string{"VERDIFAX_BASE_URL": "http://127.0.0.1:8080/"}))
	must(t, err)
	if cfg.BaseURL != "http://127.0.0.1:8080" {
		t.Fatal(cfg.BaseURL)
	}
}

func TestPathsThatLeaveTheWorkingFolderAreRefusedBeforeTheVerifierRuns(t *testing.T) {
	dir := makeWorkdir(t)
	outside := t.TempDir()
	must(t, os.WriteFile(filepath.Join(outside, "secret.json"), []byte("{}"), 0o644))
	must(t, os.Symlink(filepath.Join(outside, "secret.json"), filepath.Join(dir, "link.json")))
	v := makeVerifier(t)
	session := testConnect(t, &Config{BaseURL: "http://127.0.0.1:9", Workdir: dir, VerifierPath: v.path})
	attempts := []map[string]any{
		{"path": "../outside.json"},
		{"path": "records/../../etc/passwd"},
		{"path": "/etc/passwd"},
		{"path": "link.json"},
		{"path": "records"},
		{"path": "missing.json"},
		{"path": "records/bundle.json", "policy_path": "../policy.json"},
		{"path": "records/bundle.json\u0000.txt"},
	}
	for _, args := range attempts {
		if res := call(t, session, "verify_record", args); !res.IsError {
			t.Fatalf("%v was not refused", args)
		}
	}
	if !call(t, session, "verify_feed", map[string]any{"path": "feed.json", "owner_request_key_paths": []any{"../k.txt"}}).IsError {
		t.Fatal("verify_feed traversal was not refused")
	}
	if !call(t, session, "test_policy", map[string]any{"inputs": map[string]any{}, "document_path": "../policy.json"}).IsError {
		t.Fatal("test_policy traversal was not refused")
	}
	if _, err := os.Stat(v.argsFile); err == nil {
		t.Fatal("the verifier ran")
	}
}

func TestHostileRecordStringsComeBackOnlyAsCleanedQuotedFields(t *testing.T) {
	var hostile struct {
		Cases []struct{ Raw, Cleaned string } `json:"cases"`
	}
	readJSON(t, filepath.Join(testdata, "hostile-strings.json"), &hostile)
	var raws, cleaned []any
	for _, c := range hostile.Cases {
		raws, cleaned = append(raws, c.Raw), append(cleaned, c.Cleaned)
	}
	record := map[string]any{"notes": raws, hostile.Cases[0].Raw: "key with hidden characters"}
	api := startAPI(t, func(e recorded) *answer {
		if e.path == "/runs/7/artifacts" {
			return &answer{status: 200, body: record}
		}
		return keyCheck(e, nil)
	})
	dir := makeWorkdir(t)
	v := makeVerifier(t)
	stdout := filepath.Join(dir, "stdout.json")
	report, _ := json.Marshal(map[string]any{"verdict_tier": "FAILED", "reason": hostile.Cases[2].Raw})
	must(t, os.WriteFile(stdout, report, 0o644))
	t.Setenv("FAKE_VERIFY_STDOUT_FILE", stdout)
	t.Setenv("FAKE_VERIFY_STDERR", hostile.Cases[0].Raw)
	t.Setenv("FAKE_VERIFY_EXIT", "1")
	session := testConnect(t, &Config{BaseURL: api.url, APIKey: memberKey, Workdir: dir, VerifierPath: v.path})
	res := call(t, session, "get_record", map[string]any{"run_id": 7})
	out := structured(t, res)
	rec := out["record"].(map[string]any)
	if !reflect.DeepEqual(rec["notes"], cleaned) {
		t.Fatalf("notes %q", rec["notes"])
	}
	if _, ok := rec[hostile.Cases[0].Cleaned]; !ok {
		t.Fatal("the hostile key was not cleaned")
	}
	var fromText map[string]any
	must(t, json.Unmarshal([]byte(textOf(res)), &fromText))
	if !reflect.DeepEqual(fromText, out) {
		t.Fatal("the text block differs from the structured answer")
	}
	verified := structured(t, call(t, session, "verify_record", map[string]any{"path": "records/bundle.json"}))
	if verified["outcome"] != "failed" || verified["report"].(map[string]any)["reason"] != hostile.Cases[2].Cleaned {
		t.Fatalf("verified %v", verified)
	}
	if strings.TrimSpace(verified["stderr"].(string)) != hostile.Cases[0].Cleaned {
		t.Fatalf("stderr %q", verified["stderr"])
	}
	for _, content := range []map[string]any{out, verified} {
		text, _ := marshalNoEscape(content)
		if hiddenChars.MatchString(text) {
			t.Fatal("a hidden character came back")
		}
	}
}

func TestSealDecisionRefusesHiddenCharactersAndSendsNothing(t *testing.T) {
	api := startAPI(t, func(e recorded) *answer { return keyCheck(e, nil) })
	session := testConnect(t, &Config{BaseURL: api.url, APIKey: memberKey})
	args := map[string]any{}
	for k, v := range sealArgs {
		args[k] = v
	}
	args["payload_text"] = "approve\u200b"
	if msg := errorText(t, call(t, session, "seal_decision", args)); !strings.Contains(msg, "control or zero-width") {
		t.Fatal(msg)
	}
	if len(api.all()) != 0 {
		t.Fatal("a request was sent")
	}
}

func TestNoSecretLeavesTheServer(t *testing.T) {
	requestKey := []byte(strings.Repeat("\x09", 32))
	echo := strings.Join([]string{memberKey, feedKey, hex.EncodeToString(requestKey), base64.StdEncoding.EncodeToString(requestKey), "vfx_00112233445566778899"}, " ")
	api := startAPI(t, func(e recorded) *answer {
		switch e.path {
		case "/runs/1/artifacts":
			return &answer{status: 200, body: map[string]any{"leaked": echo}}
		case "/runs":
			return &answer{status: 500, body: map[string]any{"ok": false, "error": "bad key " + e.key}}
		case "/execute":
			return &answer{status: 400, body: map[string]any{"ok": false, "error": "refused " + echo}}
		case "/signals":
			return &answer{status: 200, body: map[string]any{"events": []any{map[string]any{"id": "1", "data": map[string]any{"kind": "x", "sequence": 1, "entry": map[string]any{"note": echo}}}}, "next_after": 1, "newest": 1}}
		}
		return keyCheck(e, nil)
	})
	dir := makeWorkdir(t)
	v := makeVerifier(t)
	t.Setenv("FAKE_VERIFY_STDERR", echo)
	t.Setenv("VERDIFAX_API_KEY", memberKey)
	t.Setenv("VERDIFAX_FEED_KEY", feedKey)
	cfg := &Config{BaseURL: api.url, APIKey: memberKey, FeedKey: feedKey, RequestKey: requestKey, Workdir: dir, VerifierPath: v.path}
	session := testConnect(t, cfg)
	results := []any{
		call(t, session, "get_record", map[string]any{"run_id": 1}),
		call(t, session, "list_records", map[string]any{}),
		call(t, session, "read_feed", map[string]any{}),
		call(t, session, "verify_record", map[string]any{"path": "records/bundle.json"}),
		call(t, session, "seal_decision", sealArgs),
	}
	all, err := json.Marshal(results)
	must(t, err)
	for _, secret := range []string{memberKey, feedKey, hex.EncodeToString(requestKey), base64.StdEncoding.EncodeToString(requestKey), "vfx_00112233445566778899"} {
		if strings.Contains(string(all), secret) {
			t.Fatalf("a secret leaked: %s", secret[:8])
		}
	}
	if !strings.Contains(string(all), "[redacted]") {
		t.Fatal("nothing was redacted")
	}
	childEnv, err := os.ReadFile(v.argsFile + ".env")
	must(t, err)
	if strings.TrimSpace(string(childEnv)) != "" {
		t.Fatalf("VERDIFAX_ variables reached the verifier: %s", childEnv)
	}
}
