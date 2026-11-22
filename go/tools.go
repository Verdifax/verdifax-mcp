package verdifaxmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	verdifax "github.com/Verdifax/verdifax-sdk-go"
)

// The ten tool handlers. Reads go through the Verdifax SDK with the member
// key or the feed key; the verify tools run the local verifier;
// prepare_signoff makes no request. Each handler returns the structured
// answer the contract's output schema describes; server.go cleans, redacts
// and checks it.

type runtimeInfo struct {
	cfg           *Config
	clientName    string
	clientVersion string
}

type handler func(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error)

func memberClient(rt runtimeInfo) (*verdifax.Client, error) {
	if rt.cfg.APIKey == "" {
		return nil, toolErr("VERDIFAX_API_KEY is not set, so this tool cannot read Verdifax")
	}
	return verdifax.NewClient(verdifax.Config{BaseURL: rt.cfg.BaseURL, APIKey: rt.cfg.APIKey, UserAgent: UserAgent})
}

func feedClient(rt runtimeInfo) (*verdifax.Client, error) {
	if rt.cfg.FeedKey == "" {
		return nil, toolErr("VERDIFAX_FEED_KEY is not set, so this tool cannot read the signal feed")
	}
	return verdifax.NewClient(verdifax.Config{BaseURL: rt.cfg.BaseURL, APIKey: rt.cfg.FeedKey, UserAgent: UserAgent})
}

// sdkError turns an SDK error into a plain tool error.
func sdkError(err error) error {
	var apiErr *verdifax.APIError
	var authErr *verdifax.AuthError
	var notFound *verdifax.NotFoundError
	switch {
	case errors.As(err, &apiErr):
		return toolErr(fmt.Sprintf("The Verdifax API answered HTTP %d: %s", apiErr.Status, apiErr.Message))
	case errors.As(err, &authErr):
		return toolErr(fmt.Sprintf("The Verdifax API answered HTTP %d: %s", authErr.Status, authErr.Message))
	case errors.As(err, &notFound):
		return toolErr("The Verdifax API answered HTTP 404: " + notFound.Message)
	}
	return toolErr(err.Error())
}

// plain is a JSON round trip, so every value is a decoded JSON value.
func plain(v any) (any, error) {
	data, marshalErr := json.Marshal(v)
	if marshalErr != nil {
		return nil, marshalErr
	}
	var out any
	return out, json.Unmarshal(data, &out)
}

func intArg(args map[string]any, name string, fallback int64) int64 {
	if _, ok := args[name]; !ok {
		return fallback
	}
	return wholeNumber(args[name])
}

func getRecord(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error) {
	client, clientErr := memberClient(rt)
	if clientErr != nil {
		return nil, clientErr
	}
	runID := wholeNumber(args["run_id"])
	data, getErr := client.GetRunArtifacts(ctx, runID)
	if getErr != nil {
		return nil, sdkError(getErr)
	}
	var record map[string]any
	if json.Unmarshal(data, &record) != nil || record == nil {
		return nil, toolErr("The Verdifax API's bundle is not a JSON object")
	}
	return map[string]any{"run_id": runID, "record": record, "data_notice": contract.Implementation.DataNotice}, nil
}

func listRecords(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error) {
	client, clientErr := memberClient(rt)
	if clientErr != nil {
		return nil, clientErr
	}
	limit, offset := intArg(args, "limit", 20), intArg(args, "offset", 0)
	runs, total, listErr := client.ListRuns(ctx, &verdifax.ListRunsParams{Limit: int(limit), Offset: int(offset)})
	if listErr != nil {
		return nil, sdkError(listErr)
	}
	listed, plainErr := plain(runs)
	if plainErr != nil {
		return nil, plainErr
	}
	if listed == nil {
		listed = []any{}
	}
	return map[string]any{"runs": listed, "total": total, "limit": limit, "offset": offset, "data_notice": contract.Implementation.DataNotice}, nil
}

func readFeed(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error) {
	client, clientErr := feedClient(rt)
	if clientErr != nil {
		return nil, clientErr
	}
	after, limit := intArg(args, "after", 0), intArg(args, "limit", 100)
	page, getErr := client.GetSignals(ctx, &verdifax.GetSignalsOptions{After: after, Limit: int(limit)})
	if getErr != nil {
		return nil, sdkError(getErr)
	}
	events, plainErr := plain(page.Events)
	if plainErr != nil {
		return nil, plainErr
	}
	if events == nil {
		events = []any{}
	}
	var head any
	if page.Head != nil {
		if head, plainErr = plain(page.Head); plainErr != nil {
			return nil, plainErr
		}
	}
	return map[string]any{"after": after, "events": events, "next_after": page.NextAfter, "head": head, "data_notice": contract.Implementation.DataNotice}, nil
}

func listPendingSignoffs(ctx context.Context, _ map[string]any, rt runtimeInfo) (map[string]any, error) {
	client, clientErr := feedClient(rt)
	if clientErr != nil {
		return nil, clientErr
	}
	limit, maxPages := contract.Implementation.FeedReading.PageLimit, contract.Implementation.FeedReading.MaxPages
	var events []verdifax.SignalEvent
	var head *verdifax.FeedHead
	var after int64
	pages := 0
	for {
		if pages == maxPages {
			return nil, toolErr(fmt.Sprintf("The feed holds more than %d events; this tool does not answer from part of a feed", maxPages*limit))
		}
		page, getErr := client.GetSignals(ctx, &verdifax.GetSignalsOptions{After: after, Limit: limit})
		if getErr != nil {
			return nil, sdkError(getErr)
		}
		pages++
		events = append(events, page.Events...)
		head = page.Head
		if len(page.Events) < limit || head != nil {
			break
		}
		if page.NextAfter <= after {
			return nil, toolErr("The Verdifax API's feed page names no next place")
		}
		after = page.NextAfter
	}
	runIDs, pendingErr := verdifax.PendingSignOffs(events)
	if pendingErr != nil {
		return nil, toolErr(pendingErr.Error())
	}
	if runIDs == nil {
		runIDs = []int64{}
	}
	var headValue any
	if head != nil {
		var plainErr error
		if headValue, plainErr = plain(head); plainErr != nil {
			return nil, plainErr
		}
	}
	return map[string]any{
		"run_ids":     runIDs,
		"events_read": len(events),
		"pages_read":  pages,
		"head":        headValue,
		"computed_by": outputConst("list_pending_signoffs", "computed_by"),
		"data_notice": contract.Implementation.DataNotice,
	}, nil
}

func getSignoffs(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error) {
	client, clientErr := memberClient(rt)
	if clientErr != nil {
		return nil, clientErr
	}
	runID := wholeNumber(args["run_id"])
	list, getErr := client.GetSignOffs(ctx, runID, nil)
	if getErr != nil {
		return nil, sdkError(getErr)
	}
	signoffs, plainErr := plain(list)
	if plainErr != nil {
		return nil, plainErr
	}
	return map[string]any{"run_id": runID, "signoffs": signoffs, "data_notice": contract.Implementation.DataNotice}, nil
}

func testPolicy(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error) {
	hash, hasHash := args["document_hash"].(string)
	path, hasPath := args["document_path"].(string)
	if hasHash == hasPath {
		return nil, toolErr("Give exactly one of document_hash and document_path")
	}
	client, clientErr := memberClient(rt)
	if clientErr != nil {
		return nil, clientErr
	}
	inputs, _ := args["inputs"].(map[string]any)
	req := &verdifax.PolicyTestRequest{Inputs: inputs, AIOutputDeclared: args["ai_output_declared"] == true}
	if hasPath {
		real, pathErr := resolveInWorkdir(rt.cfg.Workdir, path, "document_path")
		if pathErr != nil {
			return nil, pathErr
		}
		if info, statErr := os.Stat(real); statErr != nil || info.Size() > int64(contract.Implementation.Limits.MaxPolicyDocumentBytes) {
			return nil, toolErr("document_path is larger than 1 MB")
		}
		data, readErr := os.ReadFile(real)
		if readErr != nil {
			return nil, toolErr("document_path cannot be read")
		}
		req.Document = string(data)
	} else {
		req.DocumentHash = verdifax.Hex64(hash)
	}
	result, testErr := client.TestPolicy(ctx, req)
	if testErr != nil {
		return nil, sdkError(testErr)
	}
	return map[string]any{
		"sealed":        false,
		"outcome":       result.Outcome,
		"fired_rule_id": result.FiredRuleID,
		"reason_code":   result.ReasonCode,
		"data_notice":   contract.Implementation.DataNotice,
	}, nil
}

func sealDecision(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error) {
	if rt.cfg.APIKey == "" {
		return nil, toolErr("VERDIFAX_API_KEY is not set, so nothing can be sealed")
	}
	if err := refuseHiddenCharacters(args, "arguments"); err != nil {
		return nil, err
	}
	client := declaredClient(rt.clientName, rt.clientVersion)
	body := sealBody(args, client)
	text, encodeErr := canonicalJSON(body)
	if encodeErr != nil {
		return nil, toolErr("the request cannot be written as JSON")
	}
	sent := text
	var signedRequest any
	if len(rt.cfg.RequestKey) > 0 {
		signed, signErr := signBody(rt.cfg.RequestKey, text, body, "", "")
		if signErr != nil {
			return nil, toolErr("the request could not be signed")
		}
		if sent, encodeErr = canonicalJSON(signed); encodeErr != nil {
			return nil, toolErr("the request cannot be written as JSON")
		}
		signedRequest = text
	}
	timeout := time.Duration(contract.Implementation.Limits.RequestTimeoutSeconds) * time.Second
	answer, reqErr := request(ctx, rt.cfg.BaseURL, rt.cfg.APIKey, "POST", "/execute", []byte(sent), timeout)
	if reqErr != nil {
		return nil, reqErr
	}
	if answer.status != http.StatusOK && answer.status != http.StatusUnprocessableEntity {
		message := serverMessage(answer.body)
		out := fmt.Sprintf("The Verdifax API answered HTTP %d", answer.status)
		if message != "" {
			out += ": " + message
		}
		return nil, toolErr(out)
	}
	result, ok := answer.body.(map[string]any)
	if !ok {
		return nil, toolErr("The Verdifax API did not answer with a run result")
	}
	var recordHash any
	if h, ok := result["record_hash"].(string); ok && h != "" {
		recordHash = h
	}
	var runID any
	if n, ok := result["run_id"].(float64); ok {
		runID = int64(n)
	}
	outcome := "completed"
	if answer.status != http.StatusOK {
		outcome = "not_completed"
	}
	return map[string]any{
		"sealed":          recordHash != nil,
		"outcome":         outcome,
		"http_status":     answer.status,
		"run_id":          runID,
		"record_hash":     recordHash,
		"signed":          signedRequest != nil,
		"signed_request":  signedRequest,
		"declared_client": client,
		"answer":          result,
		"data_notice":     contract.Implementation.DataNotice,
	}, nil
}

var handlers = map[string]handler{
	"verify_record": func(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error) {
		return verify(ctx, "record", args, rt.cfg)
	},
	"verify_feed": func(ctx context.Context, args map[string]any, rt runtimeInfo) (map[string]any, error) {
		return verify(ctx, "feed", args, rt.cfg)
	},
	"get_record":            getRecord,
	"list_records":          listRecords,
	"read_feed":             readFeed,
	"list_pending_signoffs": listPendingSignoffs,
	"get_signoffs":          getSignoffs,
	"test_policy":           testPolicy,
	"seal_decision":         sealDecision,
	"prepare_signoff": func(_ context.Context, args map[string]any, _ runtimeInfo) (map[string]any, error) {
		return prepareSignoff(args)
	},
}

// HandlerNames lists the tools this implementation handles.
func HandlerNames() []string { return sortedKeys(handlers) }
