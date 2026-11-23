"""verdifax-mcp: the Verdifax MCP server over stdio, or with --http over
Streamable HTTP on this machine. It checks its keys before it serves."""

import sys

import anyio

from .contract import CONTRACT, IMPL
from .errors import StartupError
from .server import create_server
from .startup import USAGE, parse_args, prepare


async def _run(argv: list[str]) -> None:
    parsed = parse_args(argv)
    if parsed == "version":
        print(f"{CONTRACT['server']['name']} {CONTRACT['server']['version']} (python)")
        return
    if parsed == "help":
        print(USAGE)
        return
    config, grants = await prepare()
    granted = "no tool list reported" if grants.granted_tools is None else "granted tools: " + (", ".join(grants.granted_tools) or "none")
    print(f"verdifax-mcp: ready ({config.base_url}; {granted})", file=sys.stderr)
    server = create_server(config, grants)
    if parsed.http:
        from .http_mode import serve_http

        print(f"verdifax-mcp: listening on http://{parsed.host}:{parsed.port}{IMPL['http_mode']['path']}", file=sys.stderr)
        await serve_http(server, parsed.host, parsed.port, config.http_token)
        return
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    try:
        anyio.run(_run, sys.argv[1:])
    except StartupError as err:
        print(f"verdifax-mcp: {err}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
