package verdifaxmcp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Configuration from the environment only. Secrets come from environment
// variables and key files; no tool takes a secret as input.

// DefaultBaseURL is the Verdifax API.
const DefaultBaseURL = "https://api.verdifax.com"

const requestKeyBytes = 32

var (
	hex64Text  = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	base64Text = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	localHosts = map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}
)

// Config is what the environment sets.
type Config struct {
	BaseURL      string
	APIKey       string
	FeedKey      string
	RequestKey   []byte
	Workdir      string
	VerifierPath string
	HTTPToken    string
}

func checkBaseURL(raw string) (string, error) {
	u, parseErr := url.Parse(raw)
	if parseErr != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", startupErr("VERDIFAX_BASE_URL is not a URL: " + raw)
	}
	if u.User != nil {
		return "", startupErr("VERDIFAX_BASE_URL must not carry a user name or password")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", startupErr("VERDIFAX_BASE_URL must not carry a query or fragment")
	}
	switch u.Scheme {
	case "http":
		if !localHosts[u.Hostname()] {
			return "", startupErr("VERDIFAX_BASE_URL must use https; plain http is accepted only for this machine")
		}
	case "https":
	default:
		return "", startupErr("VERDIFAX_BASE_URL must use https")
	}
	return strings.TrimRight(raw, "/"), nil
}

// LoadRequestKey reads the request key file: 32 raw bytes, 64 hex characters
// or base64. A file group or others can read or write is refused.
func LoadRequestKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE must be an absolute path")
	}
	if runtime.GOOS == "windows" {
		return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE is supported on Linux and macOS, where its permissions can be checked")
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE cannot be read")
	}
	if !info.Mode().IsRegular() {
		return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE can be read or written by group or others; run chmod 600 on it first")
	}
	if info.Size() > 1024 {
		return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE is too large to be a request key")
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE cannot be read")
	}
	if len(raw) == requestKeyBytes {
		return raw, nil
	}
	text := strings.TrimSpace(string(raw))
	if hex64Text.MatchString(text) {
		decoded, _ := hex.DecodeString(text)
		return decoded, nil
	}
	if base64Text.MatchString(text) {
		if decoded, decodeErr := base64.StdEncoding.DecodeString(text); decodeErr == nil && len(decoded) == requestKeyBytes {
			return decoded, nil
		}
	}
	return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE must hold the 32-byte private key as raw bytes, 64 hex characters or base64")
}

// LoadConfig reads the configuration from env, a lookup such as os.LookupEnv.
func LoadConfig(env func(string) string) (*Config, error) {
	get := func(name string) string { return strings.TrimSpace(env(name)) }
	for _, name := range sortedKeys(contract.Implementation.RefusedEnvironment) {
		if get(name) != "" {
			return nil, startupErr(fmt.Sprintf("%s is set. %s Remove it from this server's environment.", name, contract.Implementation.RefusedEnvironment[name]))
		}
	}
	base := get("VERDIFAX_BASE_URL")
	if base == "" {
		base = get("VERDIFAX_API_URL")
	}
	if base == "" {
		base = DefaultBaseURL
	}
	checked, baseErr := checkBaseURL(base)
	if baseErr != nil {
		return nil, baseErr
	}
	cfg := &Config{BaseURL: checked, APIKey: get("VERDIFAX_API_KEY"), FeedKey: get("VERDIFAX_FEED_KEY")}
	if cfg.APIKey != "" && cfg.APIKey == cfg.FeedKey {
		return nil, startupErr("VERDIFAX_API_KEY and VERDIFAX_FEED_KEY hold the same key")
	}
	if path := get("VERDIFAX_REQUEST_KEY_FILE"); path != "" {
		if cfg.APIKey == "" {
			return nil, startupErr("VERDIFAX_REQUEST_KEY_FILE is set but VERDIFAX_API_KEY is not")
		}
		key, keyErr := LoadRequestKey(path)
		if keyErr != nil {
			return nil, keyErr
		}
		cfg.RequestKey = key
	}
	if dir := get("VERDIFAX_MCP_WORKDIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			return nil, startupErr("VERDIFAX_MCP_WORKDIR must be an absolute path")
		}
		real, realErr := filepath.EvalSymlinks(dir)
		if realErr != nil {
			return nil, startupErr("VERDIFAX_MCP_WORKDIR does not exist")
		}
		if info, statErr := os.Stat(real); statErr != nil || !info.IsDir() {
			return nil, startupErr("VERDIFAX_MCP_WORKDIR is not a folder")
		}
		cfg.Workdir = real
	}
	if path := get("VERDIFAX_VERIFY_PATH"); path != "" {
		if !filepath.IsAbs(path) {
			return nil, startupErr("VERDIFAX_VERIFY_PATH must be an absolute path")
		}
		cfg.VerifierPath = path
	}
	if token := get("VERDIFAX_MCP_HTTP_TOKEN"); token != "" {
		if len([]rune(token)) < contract.Implementation.HTTPMode.TokenMinChars {
			return nil, startupErr(fmt.Sprintf("VERDIFAX_MCP_HTTP_TOKEN must be at least %d characters", contract.Implementation.HTTPMode.TokenMinChars))
		}
		cfg.HTTPToken = token
	}
	return cfg, nil
}

// Secrets lists every secret the redactor must hide, in each form it could
// appear.
func (c *Config) Secrets() []string {
	var out []string
	for _, s := range []string{c.APIKey, c.FeedKey, c.HTTPToken} {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(c.RequestKey) > 0 {
		h := hex.EncodeToString(c.RequestKey)
		out = append(out, h, strings.ToUpper(h), base64.StdEncoding.EncodeToString(c.RequestKey))
	}
	return out
}
