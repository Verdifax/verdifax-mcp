package verdifaxmcp

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The optional Streamable HTTP mode, for a customer to run on its own
// machines. It listens on 127.0.0.1 unless told otherwise, where the MCP SDK
// protects it against DNS rebinding, and it refuses to listen beyond this
// machine without a bearer token, which it then requires on every request.

var loopback = map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}

// HTTPHandler serves server at the contract's path, behind the token when
// one is set.
func HTTPHandler(server *mcp.Server, host, token string) (http.Handler, error) {
	if !loopback[host] && token == "" {
		return nil, startupErr("HTTP mode beyond this machine needs VERDIFAX_MCP_HTTP_TOKEN")
	}
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	path := contract.Implementation.HTTPMode.Path
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		if token != "" {
			given := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(given, want) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		streamable.ServeHTTP(w, r)
	}), nil
}
