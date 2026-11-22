"""The optional Streamable HTTP mode, for a customer to run on its own machines.

It listens on 127.0.0.1 unless told otherwise, where the MCP SDK protects it
against DNS rebinding, and it refuses to listen beyond this machine without a
bearer token, which it then requires on every request.
"""

import hmac
from typing import Any, Optional

from mcp.server.lowlevel import Server

from .contract import IMPL
from .errors import StartupError

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class BearerGuard:
    """An ASGI wrapper that answers 401 to a request without the token."""

    def __init__(self, app: Any, token: Optional[str]) -> None:
        self.app = app
        self.token = token.encode("utf-8") if token else None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and self.token is not None:
            given = dict(scope.get("headers") or []).get(b"authorization", b"")
            supplied = given[7:] if given.startswith(b"Bearer ") else b""
            if not hmac.compare_digest(supplied, self.token):
                await send({"type": "http.response.start", "status": 401, "headers": [(b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b""})
                return
        await self.app(scope, receive, send)


def http_app(server: Server, host: str, token: Optional[str]) -> Any:
    if host not in LOOPBACK and not token:
        raise StartupError("HTTP mode beyond this machine needs VERDIFAX_MCP_HTTP_TOKEN")
    app = server.streamable_http_app(streamable_http_path=IMPL["http_mode"]["path"], host=host)
    return BearerGuard(app, token)


async def serve_http(server: Server, host: str, port: int, token: Optional[str]) -> None:
    import uvicorn

    app = http_app(server, host, token)
    await uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning")).serve()
