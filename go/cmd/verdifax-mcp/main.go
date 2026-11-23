// Command verdifax-mcp is the Verdifax MCP server over stdio, or with --http
// over Streamable HTTP on this machine. It checks its keys before it
// serves. R users run this signed binary.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	verdifaxmcp "github.com/Verdifax/verdifax-mcp/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "verdifax-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	args, argsErr := verdifaxmcp.ParseArgs(os.Args[1:])
	if argsErr != nil {
		return argsErr
	}
	if args.Version {
		fmt.Println(verdifaxmcp.VersionLine())
		return nil
	}
	if args.Help {
		fmt.Println(verdifaxmcp.Usage)
		return nil
	}
	ctx := context.Background()
	cfg, grants, prepareErr := verdifaxmcp.Prepare(ctx, os.Getenv)
	if prepareErr != nil {
		return prepareErr
	}
	granted := "no tool list reported"
	if grants.GrantedTools != nil {
		granted = "granted tools: " + strings.Join(grants.GrantedTools, ", ")
		if len(grants.GrantedTools) == 0 {
			granted = "granted tools: none"
		}
	}
	fmt.Fprintf(os.Stderr, "verdifax-mcp: ready (%s; %s)\n", cfg.BaseURL, granted)
	server := verdifaxmcp.NewServer(cfg, grants)
	if !args.HTTP {
		return server.Run(ctx, &mcp.StdioTransport{})
	}
	handler, handlerErr := verdifaxmcp.HTTPHandler(server, args.Host, cfg.HTTPToken)
	if handlerErr != nil {
		return handlerErr
	}
	addr := net.JoinHostPort(args.Host, strconv.Itoa(args.Port))
	fmt.Fprintf(os.Stderr, "verdifax-mcp: listening on http://%s/mcp\n", addr)
	httpServer := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	return httpServer.ListenAndServe()
}
