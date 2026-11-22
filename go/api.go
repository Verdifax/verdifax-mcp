package verdifaxmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// The two requests this server makes without the SDK: the startup key
// check, which must read a response header, and seal_decision's POST of the
// exact body text it signed. Every other request goes through the Verdifax
// SDK.

// UserAgent names this server in every request.
var UserAgent = "verdifax-mcp/" + contract.Server.Version + " (go)"

type rawAnswer struct {
	status  int
	headers http.Header
	body    any
}

var plainClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func request(ctx context.Context, baseURL, key, method, path string, body []byte, timeout time.Duration) (*rawAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, reqErr := http.NewRequestWithContext(ctx, method, baseURL+path, reader)
	if reqErr != nil {
		return nil, toolErr("The Verdifax API at " + baseURL + " could not be reached")
	}
	req.Header.Set("X-Verdifax-Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, doErr := plainClient.Do(req)
	if doErr != nil {
		return nil, toolErr("The Verdifax API at " + baseURL + " could not be reached")
	}
	defer res.Body.Close()
	limit := int64(contract.Implementation.Limits.MaxAnswerBytes)
	data, readErr := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if readErr != nil {
		return nil, toolErr("The Verdifax API at " + baseURL + " could not be reached")
	}
	if int64(len(data)) > limit {
		return nil, toolErr("The Verdifax API's answer is larger than this server accepts")
	}
	var parsed any
	if len(data) > 0 {
		if json.Unmarshal(data, &parsed) != nil {
			parsed = nil
		}
	}
	return &rawAnswer{status: res.StatusCode, headers: res.Header, body: parsed}, nil
}

func serverMessage(body any) string {
	if m, ok := body.(map[string]any); ok {
		if s, ok := m["error"].(string); ok {
			return s
		}
	}
	return ""
}

// grantsFrom is the list of tools the server reports this key's owner
// granted, or nil when the server reports no list. Names outside the
// contract are dropped.
func grantsFrom(headers http.Header) []string {
	values, present := headers[http.CanonicalHeaderKey(contract.Implementation.KeyCheck.AllowedToolsHeader)]
	if !present {
		return nil
	}
	known := map[string]bool{}
	for _, name := range ToolNames() {
		known[name] = true
	}
	out := []string{}
	for _, part := range strings.Split(strings.Join(values, ","), ",") {
		if name := strings.TrimSpace(part); known[name] {
			out = append(out, name)
		}
	}
	return out
}

// CheckMemberKey checks the member key on GET /stats, which seals nothing:
// an owner key is refused with the server's documented owner-key error, and
// this server then refuses to start. It returns the reported grants, or nil.
func CheckMemberKey(ctx context.Context, baseURL, key string, redactor *Redactor) ([]string, error) {
	check := contract.Implementation.KeyCheck
	answer, reqErr := request(ctx, baseURL, key, "GET", check.Path, nil, 15*time.Second)
	if reqErr != nil {
		return nil, startupErr("VERDIFAX_API_KEY could not be checked: " + redactor.Text(reqErr.Error()))
	}
	message := serverMessage(answer.body)
	switch {
	case answer.status == http.StatusOK:
		return grantsFrom(answer.headers), nil
	case answer.status == http.StatusForbidden && message == check.OwnerKeyError:
		return nil, startupErr("VERDIFAX_API_KEY is an account owner key. This server never holds owner powers; give it a member key.")
	case answer.status == http.StatusForbidden && message == check.FeedKeyError:
		return nil, startupErr("VERDIFAX_API_KEY is a feed key. Set a feed key as VERDIFAX_FEED_KEY and a member key as VERDIFAX_API_KEY.")
	}
	return nil, startupErr(refusal("VERDIFAX_API_KEY", answer.status, redactor.Text(message)))
}

// CheckFeedKey checks the feed key on the same route: a feed key is answered
// with the server's feed-key error, an owner key with the owner-key error.
func CheckFeedKey(ctx context.Context, baseURL, key string, redactor *Redactor) error {
	check := contract.Implementation.KeyCheck
	answer, reqErr := request(ctx, baseURL, key, "GET", check.Path, nil, 15*time.Second)
	if reqErr != nil {
		return startupErr("VERDIFAX_FEED_KEY could not be checked: " + redactor.Text(reqErr.Error()))
	}
	message := serverMessage(answer.body)
	switch {
	case answer.status == http.StatusForbidden && message == check.FeedKeyError:
		return nil
	case answer.status == http.StatusForbidden && message == check.OwnerKeyError:
		return startupErr("VERDIFAX_FEED_KEY is an account owner key. This server never holds owner powers; give it a feed key.")
	case answer.status == http.StatusOK:
		return startupErr("VERDIFAX_FEED_KEY is not a feed key: the server let it read runs")
	}
	return startupErr(refusal("VERDIFAX_FEED_KEY", answer.status, redactor.Text(message)))
}

func refusal(name string, status int, message string) string {
	out := fmt.Sprintf("The Verdifax API refused %s (HTTP %d)", name, status)
	if message != "" {
		out += ": " + message
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
