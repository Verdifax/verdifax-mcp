"""Startup: command-line arguments, configuration and the key checks that run
before anything is served."""

from dataclasses import dataclass
from typing import Mapping, Optional, Union

from .api import check_feed_key, check_member_key
from .clean import Redactor
from .config import Config, load_config, secrets_of
from .contract import IMPL
from .errors import StartupError
from .server import Grants

_HTTP = IMPL["http_mode"]
USAGE = f"""usage: verdifax-mcp [--http] [--host HOST] [--port PORT] [--version]

Serves the Verdifax tools over stdio, or with --http over Streamable HTTP at
http://HOST:PORT{_HTTP['path']} (default {_HTTP['default_host']}:{_HTTP['default_port']}).
Keys and paths come from the environment; see the README."""


@dataclass
class Args:
    http: bool = False
    host: str = _HTTP["default_host"]
    port: int = _HTTP["default_port"]


def parse_args(argv: list[str]) -> Union[Args, str]:
    out = Args()
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--version":
            return "version"
        if a in ("--help", "-h"):
            return "help"
        if a == "--http":
            out.http = True
        elif a == "--host" and i + 1 < len(argv):
            i += 1
            out.host = argv[i]
        elif a == "--port" and i + 1 < len(argv):
            i += 1
            try:
                port = int(argv[i])
            except ValueError:
                port = 0
            if not 1 <= port <= 65535:
                raise StartupError("--port must be 1 to 65535")
            out.port = port
        else:
            raise StartupError(f"unknown argument {a}\n{USAGE}")
        i += 1
    if not out.http and ("--host" in argv or "--port" in argv):
        raise StartupError("--host and --port apply only with --http")
    return out


async def prepare(env: Optional[Mapping[str, str]] = None) -> tuple[Config, Grants]:
    """Loads the configuration and checks the keys: an owner key stops the
    server here, before it serves anything."""
    config = load_config(env)
    redactor = Redactor(secrets_of(config))
    grants = Grants()
    if config.api_key:
        grants = Grants(granted_tools=await check_member_key(config.base_url, config.api_key, redactor))
    if config.feed_key:
        await check_feed_key(config.base_url, config.feed_key, redactor)
    return config, grants
