package verdifaxmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runs the verdifax-verify program installed on this machine, never a shell
// and never the API. The child gets this server's environment without any
// VERDIFAX_ variable, so no key reaches it.

const verifierProgram = "verdifax-verify"

func executable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func findVerifier(configured string) (string, error) {
	if configured != "" {
		if !executable(configured) {
			return "", toolErr("VERDIFAX_VERIFY_PATH does not name a program this server can run")
		}
		return configured, nil
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		if candidate := filepath.Join(dir, verifierProgram); executable(candidate) {
			return candidate, nil
		}
	}
	return "", toolErr("verdifax-verify was not found on PATH. Install it from https://github.com/Verdifax/verdifax-verify/releases, or set VERDIFAX_VERIFY_PATH.")
}

func childEnvironment(env []string) []string {
	prefix := contract.Implementation.Verifier.EnvironmentRemovedPrefix
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(strings.ToUpper(name), prefix) {
			out = append(out, kv)
		}
	}
	return out
}

// cappedBuffer drops output past the shared limit and remembers that it
// did, so the run is refused once the program has finished.
type cappedBuffer struct {
	buf   bytes.Buffer
	total *int
	limit int
	mu    *sync.Mutex
	over  *bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.total += len(p)
	if *c.total > c.limit {
		*c.over = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func runProgram(ctx context.Context, path string, args []string) (int, string, string, error) {
	v := contract.Implementation.Verifier
	ctx, cancel := context.WithTimeout(ctx, time.Duration(v.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = childEnvironment(os.Environ())
	var total int
	var mu sync.Mutex
	var over bool
	stdout := &cappedBuffer{total: &total, limit: v.MaxOutputBytes, mu: &mu, over: &over}
	stderr := &cappedBuffer{total: &total, limit: v.MaxOutputBytes, mu: &mu, over: &over}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return 0, "", "", toolErr(fmt.Sprintf("verdifax-verify did not finish within %d seconds", v.TimeoutSeconds))
	}
	if over {
		return 0, "", "", toolErr("verdifax-verify printed more than this server accepts")
	}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		return 0, stdout.buf.String(), stderr.buf.String(), nil
	case errors.As(runErr, &exitErr):
		return exitErr.ExitCode(), stdout.buf.String(), stderr.buf.String(), nil
	}
	return 0, "", "", toolErr("verdifax-verify could not be started")
}

var (
	versionMu sync.Mutex
	versions  = map[string]string{}
)

func verifierVersion(ctx context.Context, path string) string {
	versionMu.Lock()
	defer versionMu.Unlock()
	if v, ok := versions[path]; ok {
		return v
	}
	code, out, _, err := runProgram(ctx, path, []string{"--version"})
	version := "unknown"
	if err == nil && code == 0 {
		version = strings.TrimSpace(out)
	}
	versions[path] = version
	return version
}

// verifierArguments are the arguments for the verifier, in the contract's
// order.
func verifierArguments(rules []argumentRule, args map[string]any, workdir string) ([]string, error) {
	var out []string
	for _, rule := range rules {
		field, flag, kind := rule[0], rule[1], rule[2]
		value, present := args[field]
		if !present || value == nil {
			continue
		}
		switch kind {
		case "flag":
			if value == true {
				out = append(out, flag)
			}
		case "value":
			out = append(out, flag, fmt.Sprint(value))
		case "path":
			real, pathErr := resolveInWorkdir(workdir, fmt.Sprint(value), field)
			if pathErr != nil {
				return nil, pathErr
			}
			out = append(out, flag, real)
		default:
			items, _ := value.([]any)
			paths := make([]string, 0, len(items))
			for i, item := range items {
				name := field + "[" + strconv.Itoa(i) + "]"
				real, pathErr := resolveInWorkdir(workdir, fmt.Sprint(item), name)
				if pathErr != nil {
					return nil, pathErr
				}
				if strings.Contains(real, ",") {
					return nil, toolErr(name + " holds a comma, which the verifier reads as a separator")
				}
				paths = append(paths, real)
			}
			out = append(out, flag, strings.Join(paths, ","))
		}
	}
	return out, nil
}

func outcomeOf(mode string, exitCode int) exitMeaning {
	v := contract.Implementation.Verifier
	table := v.RecordExitCodes
	if mode == "feed" {
		table = v.FeedExitCodes
	}
	if m, ok := table[strconv.Itoa(exitCode)]; ok {
		return m
	}
	return v.UnknownExitCode
}

func verify(ctx context.Context, mode string, args map[string]any, cfg *Config) (map[string]any, error) {
	v := contract.Implementation.Verifier
	target, targetErr := resolveInWorkdir(cfg.Workdir, fmt.Sprint(args["path"]), "path")
	if targetErr != nil {
		return nil, targetErr
	}
	var argv []string
	if mode == "record" {
		rest, argsErr := verifierArguments(v.RecordArguments, args, cfg.Workdir)
		if argsErr != nil {
			return nil, argsErr
		}
		argv = append(append([]string{"--json"}, rest...), target)
	} else {
		rest, argsErr := verifierArguments(v.FeedArguments, args, cfg.Workdir)
		if argsErr != nil {
			return nil, argsErr
		}
		argv = append([]string{"--json", "--signals", target}, rest...)
	}
	program, findErr := findVerifier(cfg.VerifierPath)
	if findErr != nil {
		return nil, findErr
	}
	version := verifierVersion(ctx, program)
	code, stdout, stderr, runErr := runProgram(ctx, program, argv)
	if runErr != nil {
		return nil, runErr
	}
	var report any
	var parsed any
	if json.Unmarshal([]byte(stdout), &parsed) == nil {
		if m, ok := parsed.(map[string]any); ok {
			report = m
		}
	}
	runes := []rune(stderr)
	if len(runes) > v.StderrMaxChars {
		runes = runes[:v.StderrMaxChars]
	}
	meaning := outcomeOf(mode, code)
	return map[string]any{
		"checked_by":      outputConst("verify_record", "checked_by"),
		"verifier":        map[string]any{"path": program, "version": version},
		"arguments":       argv,
		"exit_code":       code,
		"outcome":         meaning[0],
		"outcome_meaning": meaning[1],
		"report":          report,
		"stderr":          string(runes),
		"data_notice":     contract.Implementation.DataNotice,
	}, nil
}
