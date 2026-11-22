package verdifaxmcp

import (
	"fmt"
	"strings"
)

// prepare_signoff: the command a person runs with their own approver key.
// No request is made and nothing is signed here. Every value placed in the
// command has already passed the contract's patterns, so it holds only
// letters, digits and . _ : - characters.

func signoffTarget(args map[string]any) (map[string]any, error) {
	kind := fmt.Sprint(args["kind"])
	jobID, hasJob := args["job_id"].(string)
	if kind == "job" && !hasJob {
		return nil, toolErr("job_id is required for kind job")
	}
	if _, given := args["job_id"]; kind != "job" && given {
		return nil, toolErr("job_id is given only for kind job")
	}
	target := map[string]any{"kind": kind, "run_id": wholeNumber(args["run_id"]), "digest": args["digest"]}
	if kind == "job" {
		target["job_id"] = jobID
	}
	return target, nil
}

func signoffCommand(target map[string]any, decision string) string {
	literal := fmt.Sprintf(`{"kind": "%s", "run_id": %d, "digest": "%s"`, target["kind"], target["run_id"], target["digest"])
	if target["kind"] == "job" {
		literal += fmt.Sprintf(`, "job_id": "%s"`, target["job_id"])
	}
	literal += "}"
	command := strings.Replace(contract.Implementation.PrepareSignoff.CommandTemplate, "{target}", literal, 1)
	return strings.Replace(command, "{decision}", decision, 1)
}

func prepareSignoff(args map[string]any) (map[string]any, error) {
	target, targetErr := signoffTarget(args)
	if targetErr != nil {
		return nil, targetErr
	}
	decision := fmt.Sprint(args["decision"])
	return map[string]any{
		"command":            signoffCommand(target, decision),
		"shell":              outputConst("prepare_signoff", "shell"),
		"target":             target,
		"decision":           decision,
		"steps":              append([]string(nil), contract.Implementation.PrepareSignoff.Steps...),
		"what_this_tool_did": outputConst("prepare_signoff", "what_this_tool_did"),
	}, nil
}

// wholeNumber reads a JSON number that the input schema has already
// checked is a whole number.
func wholeNumber(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	}
	return 0
}
