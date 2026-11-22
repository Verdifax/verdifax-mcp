package verdifaxmcp

import (
	"context"
	"fmt"
	"strconv"
)

// Startup: command-line arguments, configuration and the key checks that
// run before anything is served.

// Usage is the command's help text.
var Usage = fmt.Sprintf(`usage: verdifax-mcp [--http] [--host HOST] [--port PORT] [--version]

Serves the Verdifax tools over stdio, or with --http over Streamable HTTP at
http://HOST:PORT%s (default %s:%d).
Keys and paths come from the environment; see the README.`,
	contract.Implementation.HTTPMode.Path, contract.Implementation.HTTPMode.DefaultHost, contract.Implementation.HTTPMode.DefaultPort)

// Args are the command-line arguments.
type Args struct {
	HTTP    bool
	Host    string
	Port    int
	Version bool
	Help    bool
}

// ParseArgs reads the command-line arguments.
func ParseArgs(argv []string) (Args, error) {
	out := Args{Host: contract.Implementation.HTTPMode.DefaultHost, Port: contract.Implementation.HTTPMode.DefaultPort}
	hostOrPort := false
	for i := 0; i < len(argv); i++ {
		switch a := argv[i]; {
		case a == "--version":
			return Args{Version: true}, nil
		case a == "--help" || a == "-h":
			return Args{Help: true}, nil
		case a == "--http":
			out.HTTP = true
		case a == "--host" && i+1 < len(argv):
			i++
			out.Host, hostOrPort = argv[i], true
		case a == "--port" && i+1 < len(argv):
			i++
			port, portErr := strconv.Atoi(argv[i])
			if portErr != nil || port < 1 || port > 65535 {
				return Args{}, startupErr("--port must be 1 to 65535")
			}
			out.Port, hostOrPort = port, true
		default:
			return Args{}, startupErr("unknown argument " + a + "\n" + Usage)
		}
	}
	if !out.HTTP && hostOrPort {
		return Args{}, startupErr("--host and --port apply only with --http")
	}
	return out, nil
}

// Prepare loads the configuration and checks the keys: an owner key stops
// the server here, before it serves anything.
func Prepare(ctx context.Context, env func(string) string) (*Config, Grants, error) {
	cfg, configErr := LoadConfig(env)
	if configErr != nil {
		return nil, Grants{}, configErr
	}
	redactor := NewRedactor(cfg.Secrets())
	var grants Grants
	if cfg.APIKey != "" {
		reported, checkErr := CheckMemberKey(ctx, cfg.BaseURL, cfg.APIKey, redactor)
		if checkErr != nil {
			return nil, Grants{}, checkErr
		}
		grants.APIKey = reported
	}
	if cfg.FeedKey != "" {
		if checkErr := CheckFeedKey(ctx, cfg.BaseURL, cfg.FeedKey, redactor); checkErr != nil {
			return nil, Grants{}, checkErr
		}
	}
	return cfg, grants, nil
}

// VersionLine is what --version prints.
func VersionLine() string {
	return contract.Server.Name + " " + contract.Server.Version + " (go)"
}
