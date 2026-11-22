package verdifaxmcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Each tool against the stand-in API and the stand-in verifier.

var claimArgs = map[string]any{"program_id": strings.Repeat("a", 64), "route_id": "claims/review", "registry_record_hash": strings.Repeat("b", 64), "payload_text": "Approve claim 7."}

func verifySession(t *testing.T) (*mcp.ClientSession, string, stubVerifier) {
	t.Helper()
	dir := makeWorkdir(t)
	for _, name := range []string{"approver.txt", "owner-1.txt", "owner-2.txt"} {
		must(t, os.WriteFile(filepath.Join(dir, name), []byte("AAAA"), 0o644))
	}
	v := makeVerifier(t)
	return testConnect(t, &Config{BaseURL: "http://127.0.0.1:9", Workdir: dir, VerifierPath: v.path}), dir, v
}

func argsSeen(t *testing.T, v stubVerifier) []any {
	t.Helper()
	data, err := os.ReadFile(v.argsFile)
	must(t, err)
	var out []any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		out = append(out, line)
	}
	return out
}

func TestVerifyRecordMapsEveryExitCodeToItsOutcome(t *testing.T) {
	session, _, _ := verifySession(t)
	expected := map[int]string{0: "verified", 1: "failed", 2: "unreadable_input", 3: "partial_coverage", 4: "signoff_not_shown", 9: "unknown_exit_code"}
	for code, outcome := range expected {
		t.Setenv("FAKE_VERIFY_EXIT", strconv.Itoa(code))
		out := structured(t, call(t, session, "verify_record", map[string]any{"path": "records/bundle.json"}))
		if out["exit_code"] != float64(code) || out["outcome"] != outcome || out["outcome_meaning"] != outcomeOf("record", code)[1] {
			t.Fatalf("exit %d: %v", code, out)
		}
		if out["verifier"].(map[string]any)["version"] != "verdifax-verify v0.38.0 (test stand-in)" {
			t.Fatalf("version %v", out["verifier"])
		}
	}
}

func TestVerifyRecordPassesTheContractFlagsInOrder(t *testing.T) {
	session, dir, v := verifySession(t)
	out := structured(t, call(t, session, "verify_record", map[string]any{
		"path": "records/bundle.json", "strict_signoff": true, "signoff_path": "feed.json", "policy_path": "policy.json",
		"approver_public_key_path": "approver.txt", "allow_partial": false, "signoff_head_max_age": "72h",
	}))
	want := []any{
		"--json", "--policy", filepath.Join(dir, "policy.json"), "--signoff", filepath.Join(dir, "feed.json"),
		"--approver-key", filepath.Join(dir, "approver.txt"), "--strict-signoff", "--signoff-head-max-age", "72h",
		filepath.Join(dir, "records", "bundle.json"),
	}
	if got := argsSeen(t, v); !reflect.DeepEqual(got, want) {
		t.Fatalf("verifier saw %v", got)
	}
	if !reflect.DeepEqual(out["arguments"], want) {
		t.Fatalf("answer says %v", out["arguments"])
	}
}

func TestVerifyFeedRunsSignalsWithItsFlags(t *testing.T) {
	session, dir, v := verifySession(t)
	t.Setenv("FAKE_VERIFY_EXIT", "3")
	after := "12:" + strings.Repeat("c", 64)
	out := structured(t, call(t, session, "verify_feed", map[string]any{
		"path": "feed.json", "signals_after": after, "owner_request_key_paths": []any{"owner-1.txt", "owner-2.txt"}, "feed_head_max_age": "48h",
	}))
	if out["outcome"] != "partial_coverage" || out["outcome_meaning"] != contract.Implementation.Verifier.FeedExitCodes["3"][1] {
		t.Fatalf("%v", out)
	}
	want := []any{"--json", "--signals", filepath.Join(dir, "feed.json"), "--signals-after", after,
		"--owner-request-key", filepath.Join(dir, "owner-1.txt") + "," + filepath.Join(dir, "owner-2.txt"), "--feed-head-max-age", "48h"}
	if got := argsSeen(t, v); !reflect.DeepEqual(got, want) {
		t.Fatalf("verifier saw %v", got)
	}
}

func TestArgumentsOutsideTheInputSchemaAreRefused(t *testing.T) {
	session, _, _ := verifySession(t)
	for _, args := range []map[string]any{{}, {"path": "records/bundle.json", "url": "https://example.com"}, {"path": "records/bundle.json", "signoff_head_max_age": "1d"}} {
		if !call(t, session, "verify_record", args).IsError {
			t.Fatalf("%v was not refused", args)
		}
	}
}

func TestTheVerifierMissingIsAPlainRefusal(t *testing.T) {
	session := testConnect(t, &Config{BaseURL: "http://127.0.0.1:9", Workdir: makeWorkdir(t), VerifierPath: "/nonexistent/verdifax-verify"})
	if msg := errorText(t, call(t, session, "verify_record", map[string]any{"path": "records/bundle.json"})); !strings.Contains(msg, "VERDIFAX_VERIFY_PATH") {
		t.Fatal(msg)
	}
}

var testHead = map[string]any{"format": "verdifax.feed-head.v1", "account": "account-7", "sequence": 501, "head_hash": strings.Repeat("a", 64), "head_statement_hash": strings.Repeat("b", 64), "stated_at": "2026-11-17T12:00:00Z"}

func TestTheReadToolsReturnTheAPIAnswersThroughTheSDK(t *testing.T) {
	sealed := func(i int) map[string]any {
		return map[string]any{"specversion": "1.0", "id": strconv.Itoa(i), "data": map[string]any{"kind": "run.sealed", "sequence": i, "entry": map[string]any{"run_id": i, "signoff_required": i == 11 || i == 12}}}
	}
	var first []any
	for i := 1; i <= 500; i++ {
		first = append(first, sealed(i))
	}
	later := []any{map[string]any{"specversion": "1.0", "id": "501", "data": map[string]any{"kind": "signoff.recorded", "sequence": 501, "entry": map[string]any{"target": map[string]any{"kind": "record", "run_id": 11}, "decision": "approve"}}}}
	api := startAPI(t, func(e recorded) *answer {
		switch e.path {
		case "/runs/5/artifacts":
			return &answer{status: 200, body: map[string]any{"bundle_anchor": map[string]any{"anchored_digest": strings.Repeat("d", 64)}}}
		case "/runs":
			return &answer{status: 200, body: map[string]any{"ok": true, "runs": []any{map[string]any{"id": 5, "status": "completed"}}, "total": 1}}
		case "/runs/5/signoffs":
			return &answer{status: 200, body: []any{map[string]any{"decision": "approve", "signoff_hash": strings.Repeat("e", 64)}}}
		case "/signals":
			if e.key != feedKey {
				t.Errorf("the feed was read with another key")
			}
			after, _ := strconv.Atoi(e.query.Get("after"))
			limit, _ := strconv.Atoi(e.query.Get("limit"))
			switch {
			case limit == 500 && after == 0:
				return &answer{status: 200, body: map[string]any{"events": first, "next_after": 500, "newest": 501}}
			case limit == 500 && after == 500:
				return &answer{status: 200, body: map[string]any{"events": later, "next_after": 501, "newest": 501, "head": testHead}}
			}
			return &answer{status: 200, body: map[string]any{"events": first[after : after+limit], "next_after": after + limit, "newest": 501}}
		case "/policies/test":
			var body map[string]any
			_ = json.Unmarshal([]byte(e.body), &body)
			if _, doc := body["document"]; !doc {
				if _, hash := body["document_hash"]; !hash {
					t.Errorf("policy test body %v", body)
				}
			}
			return &answer{status: 200, body: map[string]any{"ok": true, "sealed": false, "outcome": "deny", "fired_rule_id": "r1", "reason_code": "TEST"}}
		}
		return keyCheck(e, nil)
	})
	dir := makeWorkdir(t)
	session := testConnect(t, &Config{BaseURL: api.url, APIKey: memberKey, FeedKey: feedKey, Workdir: dir})
	rec := structured(t, call(t, session, "get_record", map[string]any{"run_id": 5}))
	if rec["record"].(map[string]any)["bundle_anchor"].(map[string]any)["anchored_digest"] != strings.Repeat("d", 64) {
		t.Fatalf("%v", rec)
	}
	listed := structured(t, call(t, session, "list_records", map[string]any{"limit": 5}))
	if listed["total"] != float64(1) || listed["limit"] != float64(5) {
		t.Fatalf("%v", listed)
	}
	for _, r := range api.all() {
		if r.path == "/runs" && r.query.Get("limit") != "5" {
			t.Fatalf("limit sent %q", r.query.Get("limit"))
		}
	}
	signoffs := structured(t, call(t, session, "get_signoffs", map[string]any{"run_id": 5}))
	if signoffs["signoffs"].([]any)[0].(map[string]any)["decision"] != "approve" {
		t.Fatalf("%v", signoffs)
	}
	feed := structured(t, call(t, session, "read_feed", map[string]any{"limit": 1}))
	if len(feed["events"].([]any)) != 1 || feed["next_after"] != float64(1) {
		t.Fatalf("%v", feed)
	}
	pending := structured(t, call(t, session, "list_pending_signoffs", map[string]any{}))
	if !reflect.DeepEqual(pending["run_ids"], []any{float64(12)}) || pending["events_read"] != float64(501) || pending["pages_read"] != float64(2) {
		t.Fatalf("%v", pending["run_ids"])
	}
	if pending["head"].(map[string]any)["sequence"] != float64(501) {
		t.Fatalf("%v", pending["head"])
	}
	tested := structured(t, call(t, session, "test_policy", map[string]any{"inputs": map[string]any{"actor_type": "agent"}, "document_path": "policy.json"}))
	if tested["sealed"] != false || tested["outcome"] != "deny" || tested["fired_rule_id"] != "r1" {
		t.Fatalf("%v", tested)
	}
	structured(t, call(t, session, "test_policy", map[string]any{"inputs": map[string]any{}, "document_hash": strings.Repeat("f", 64)}))
	if !call(t, session, "test_policy", map[string]any{"inputs": map[string]any{}, "document_hash": strings.Repeat("f", 64), "document_path": "policy.json"}).IsError {
		t.Fatal("both documents were accepted")
	}
	for _, r := range api.all() {
		if r.method == "POST" && r.path == "/execute" {
			t.Fatal("a read tool sealed something")
		}
	}
}

func TestAnAPIRefusalComesBackAsAPlainToolError(t *testing.T) {
	api := startAPI(t, func(e recorded) *answer {
		if e.path == "/runs/8/artifacts" {
			return &answer{status: 404, body: map[string]any{"ok": false, "error": "run not found"}}
		}
		return keyCheck(e, nil)
	})
	session := testConnect(t, &Config{BaseURL: api.url, APIKey: memberKey})
	if msg := errorText(t, call(t, session, "get_record", map[string]any{"run_id": 8})); !strings.Contains(msg, "404") {
		t.Fatal(msg)
	}
	if msg := errorText(t, call(t, session, "read_feed", map[string]any{})); !strings.Contains(msg, "VERDIFAX_FEED_KEY is not set") {
		t.Fatal(msg)
	}
}

func TestSealDecisionSignsAndSealsTheDeclaredClient(t *testing.T) {
	var vector struct {
		RequestKeyHex string `json:"request_key_hex"`
	}
	readJSON(t, filepath.Join(testdata, "seal-vector.json"), &vector)
	key, _ := hex.DecodeString(vector.RequestKeyHex)
	api := startAPI(t, func(e recorded) *answer {
		if e.path == "/execute" {
			return &answer{status: 200, body: map[string]any{"ok": true, "run_id": 42, "record_hash": strings.Repeat("9", 64)}}
		}
		return keyCheck(e, nil)
	})
	session := connect(t, &Config{BaseURL: api.url, APIKey: memberKey, RequestKey: key}, Grants{}, "Claude Code", "2.9.0")
	args := map[string]any{"policy_context": map[string]any{"data_use": map[string]any{"purpose": "claims-review", "categories": []any{"health"}}}}
	for k, v := range claimArgs {
		args[k] = v
	}
	out := structured(t, call(t, session, "seal_decision", args))
	if out["sealed"] != true || out["outcome"] != "completed" || out["run_id"] != float64(42) || out["signed"] != true {
		t.Fatalf("%v", out)
	}
	wantClient := map[string]any{"name": "Claude Code", "version": "2.9.0", "label": "declared, not verified"}
	if !reflect.DeepEqual(out["declared_client"], wantClient) {
		t.Fatalf("%v", out["declared_client"])
	}
	var sent map[string]any
	for _, r := range api.all() {
		if r.path == "/execute" {
			must(t, json.Unmarshal([]byte(r.body), &sent))
		}
	}
	if len(sent) != 2 || sent["signed_request"] != out["signed_request"] {
		t.Fatalf("sent %v", sent)
	}
	var inner map[string]any
	must(t, json.Unmarshal([]byte(sent["signed_request"].(string)), &inner))
	wantAttested := map[string]any{"attested": true, "client_name": "Claude Code", "client_version": "2.9.0"}
	if _, ok := inner["reproducibility_context"]; ok || !reflect.DeepEqual(inner["attested_context"], wantAttested) {
		t.Fatalf("%v", inner)
	}
	if !reflect.DeepEqual(inner["policy_context"].(map[string]any)["data_use"], args["policy_context"].(map[string]any)["data_use"]) {
		t.Fatalf("%v", inner["policy_context"])
	}
	sig := sent["request_signature"].(map[string]any)
	preimage := requestSignaturePreimageV2(sha256Hex(sent["signed_request"].(string)), sha256Hex(claimArgs["payload_text"].(string)),
		claimArgs["program_id"].(string), claimArgs["route_id"].(string), claimArgs["registry_record_hash"].(string), "", sig["signed_at"].(string), sig["nonce"].(string))
	signature, _ := base64.StdEncoding.DecodeString(sig["signature"].(string))
	if !ed25519.Verify(ed25519.NewKeyFromSeed(key).Public().(ed25519.PublicKey), preimage, signature) {
		t.Fatal("the signature does not verify")
	}
}

func TestSealDecisionUnsignedReceiptsAndErrors(t *testing.T) {
	status := 422
	api := startAPI(t, func(e recorded) *answer {
		if e.path == "/execute" {
			if status == 422 {
				return &answer{status: 422, body: map[string]any{"ok": false, "error": "policy refused", "run_id": 43, "record_hash": strings.Repeat("8", 64)}}
			}
			return &answer{status: status, body: map[string]any{"ok": false, "error": "unknown field attested_context.client_name"}}
		}
		return keyCheck(e, nil)
	})
	session := testConnect(t, &Config{BaseURL: api.url, APIKey: memberKey})
	out := structured(t, call(t, session, "seal_decision", claimArgs))
	if out["outcome"] != "not_completed" || out["sealed"] != true || out["signed"] != false || out["signed_request"] != nil {
		t.Fatalf("%v", out)
	}
	reqs := api.all()
	var sent map[string]any
	must(t, json.Unmarshal([]byte(reqs[len(reqs)-1].body), &sent))
	if _, ok := sent["reproducibility_context"]; ok || sent["payload_text"] != claimArgs["payload_text"] || sent["attested_context"].(map[string]any)["client_name"] != "test-client" {
		t.Fatalf("%v", sent)
	}
	status = 400
	if msg := errorText(t, call(t, session, "seal_decision", claimArgs)); !strings.Contains(msg, "HTTP 400: unknown field") {
		t.Fatal(msg)
	}
}

func TestPrepareSignoffMakesNoRequestAndRequiresJobIDOnlyForAJob(t *testing.T) {
	session := testConnect(t, baseConfig())
	ok := structured(t, call(t, session, "prepare_signoff", map[string]any{"kind": "record", "run_id": 1, "digest": strings.Repeat("1", 64), "decision": "approve"}))
	if len(ok["steps"].([]any)) != 4 {
		t.Fatalf("%v", ok)
	}
	for _, args := range []map[string]any{
		{"kind": "job", "run_id": 1, "digest": strings.Repeat("1", 64), "decision": "approve"},
		{"kind": "record", "run_id": 1, "digest": strings.Repeat("1", 64), "job_id": "j", "decision": "approve"},
		{"kind": "record", "run_id": 1, "digest": "1'; rm -rf ~; '" + strings.Repeat("a", 49), "decision": "approve"},
	} {
		if !call(t, session, "prepare_signoff", args).IsError {
			t.Fatalf("%v was not refused", args)
		}
	}
}

func TestHTTPModeServesTheSameToolsAndChecksTheBearerToken(t *testing.T) {
	token := strings.Repeat("t", 40)
	handler, err := HTTPHandler(NewServer(baseConfig(), Grants{}), "127.0.0.1", token)
	must(t, err)
	srv := httptest.NewServer(handler)
	defer srv.Close()
	denied, err := http.Post(srv.URL+"/mcp", "application/json", bytes.NewReader([]byte("{}")))
	must(t, err)
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", denied.StatusCode)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "http-test", Version: "1"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{token: token}}}
	session, err := client.Connect(context.Background(), transport, nil)
	must(t, err)
	defer session.Close()
	listed, err := session.ListTools(context.Background(), nil)
	must(t, err)
	if len(listed.Tools) != len(contractNames) {
		t.Fatalf("%d tools", len(listed.Tools))
	}
	if _, err := HTTPHandler(NewServer(baseConfig(), Grants{}), "0.0.0.0", ""); !isStartup(err, "VERDIFAX_MCP_HTTP_TOKEN") {
		t.Fatal(err)
	}
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
