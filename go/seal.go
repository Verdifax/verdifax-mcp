package verdifaxmcp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// seal_decision: builds the request body the contract defines, signs it on
// this machine with signature version 2 when a request key is configured,
// and sends that exact text. The Go SDK keeps its version 2 preimage
// unexported, so it is built here, and the shared vector made by the Python
// SDK's sign_request_v2 holds it equal to the SDK's (contract_test.go).

const (
	requestSignatureFormV2 = "verdifax.request.v2"
	jobForm                = "verdifax.job.v1"
)

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// declaredClient is the client's declared name and version, cleaned to
// printable ASCII, clipped to the byte limit and stripped of leading and
// trailing spaces, as the server accepts them. The label says that nothing
// checked them.
func declaredClient(name, version string) map[string]any {
	short := func(s string) string {
		var b strings.Builder
		for _, r := range CleanString(s) {
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
			}
		}
		out := b.String()
		if max := contract.Implementation.Seal.DeclaredClientMaxBytes; len(out) > max {
			out = out[:max]
		}
		return strings.Trim(out, " ")
	}
	return map[string]any{"name": short(name), "version": short(version), "label": contract.Implementation.Seal.DeclaredClientLabel}
}

// refuseHiddenCharacters refuses a hidden character anywhere in the
// arguments, naming the field.
func refuseHiddenCharacters(value any, field string) error {
	switch x := value.(type) {
	case string:
		if hasRefusedCharacter(x) {
			return toolErr(field + " holds a control or zero-width character; seal plain text only")
		}
	case []any:
		for i, item := range x {
			if err := refuseHiddenCharacters(item, fmt.Sprintf("%s[%d]", field, i)); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			if err := refuseHiddenCharacters(k, field); err != nil {
				return err
			}
			if err := refuseHiddenCharacters(x[k], field+"."+k); err != nil {
				return err
			}
		}
	}
	return nil
}

// sealBody is the body the contract defines.
func sealBody(args map[string]any, client map[string]any) map[string]any {
	body := map[string]any{}
	for _, k := range []string{"payload_text", "program_id", "route_id", "registry_record_hash", "ai_output_text", "policy_context", "expected_policy_hash"} {
		if v, ok := args[k]; ok {
			body[k] = v
		}
	}
	declared := map[string]any{}
	if v, _ := client["name"].(string); v != "" {
		declared["client_name"] = v
	}
	if v, _ := client["version"].(string); v != "" {
		declared["client_version"] = v
	}
	ac, given := args["attested_context"].(map[string]any)
	if given || len(declared) > 0 {
		copied := map[string]any{}
		for k, v := range ac {
			copied[k] = v
		}
		for k, v := range declared {
			copied[k] = v
		}
		copied["attested"] = true
		body["attested_context"] = copied
	}
	return body
}

// canonicalJSON is JSON with keys sorted, no spaces and no escaping of
// non-ASCII characters or of <, > and &, as the other implementations write
// it.
func canonicalJSON(value any) (string, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch x := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeScalar(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return writeScalar(buf, x)
	}
	return nil
}

func writeScalar(buf *bytes.Buffer, value any) error {
	var inner bytes.Buffer
	enc := json.NewEncoder(&inner)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return err
	}
	buf.WriteString(strings.TrimSuffix(inner.String(), "\n"))
	return nil
}

func requestSignaturePreimageV2(bodyHash, payloadHash, programID, routeID, registryRecordHash, aiOutputHash, signedAt, nonce string) []byte {
	parts := []string{requestSignatureFormV2, bodyHash, payloadHash, programID, routeID, registryRecordHash, aiOutputHash,
		jobForm, "", "", "", "", "false", signedAt, nonce}
	return []byte(strings.Join(parts, "\x00"))
}

// signBody signs the exact text with signature version 2.
func signBody(seed []byte, text string, body map[string]any, signedAt, nonce string) (map[string]any, error) {
	if signedAt == "" {
		signedAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	if nonce == "" {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		nonce = hex.EncodeToString(random)
	}
	ai, _ := body["ai_output_text"].(string)
	aiHash := ""
	if ai != "" {
		aiHash = sha256Hex(ai)
	}
	payload, _ := body["payload_text"].(string)
	program, _ := body["program_id"].(string)
	route, _ := body["route_id"].(string)
	registry, _ := body["registry_record_hash"].(string)
	preimage := requestSignaturePreimageV2(sha256Hex(text), sha256Hex(payload), program, route, registry, aiHash, signedAt, nonce)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), preimage)
	return map[string]any{
		"signed_request": text,
		"request_signature": map[string]any{
			"version":   "2",
			"signature": base64.StdEncoding.EncodeToString(signature),
			"signed_at": signedAt,
			"nonce":     nonce,
		},
	}, nil
}
