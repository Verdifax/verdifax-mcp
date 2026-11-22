"""Configuration from the environment only.

Secrets come from environment variables and key files; no tool takes a
secret as input.
"""

import base64
import os
import re
import stat
import sys
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlsplit

from .contract import IMPL
from .errors import StartupError

DEFAULT_BASE_URL = "https://api.verdifax.com"
_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}
_REQUEST_KEY_BYTES = 32


@dataclass
class Config:
    base_url: str
    api_key: Optional[str] = None
    feed_key: Optional[str] = None
    request_key: Optional[bytes] = None
    workdir: Optional[str] = None
    verifier_path: Optional[str] = None
    http_token: Optional[str] = None


def _present(value: Optional[str]) -> bool:
    return isinstance(value, str) and value.strip() != ""


def check_base_url(raw: str) -> str:
    try:
        parts = urlsplit(raw)
        host = parts.hostname
    except ValueError:
        raise StartupError(f"VERDIFAX_BASE_URL is not a URL: {raw}") from None
    if not parts.scheme or not host:
        raise StartupError(f"VERDIFAX_BASE_URL is not a URL: {raw}")
    if parts.username or parts.password:
        raise StartupError("VERDIFAX_BASE_URL must not carry a user name or password")
    if parts.query or parts.fragment:
        raise StartupError("VERDIFAX_BASE_URL must not carry a query or fragment")
    if parts.scheme == "http":
        if host not in _LOCAL_HOSTS:
            raise StartupError("VERDIFAX_BASE_URL must use https; plain http is accepted only for this machine")
    elif parts.scheme != "https":
        raise StartupError("VERDIFAX_BASE_URL must use https")
    return raw.rstrip("/")


def load_request_key(path: str) -> bytes:
    """The request key file: 32 raw bytes, 64 hex characters or base64. A file
    group or others can read or write is refused."""
    if not os.path.isabs(path):
        raise StartupError("VERDIFAX_REQUEST_KEY_FILE must be an absolute path")
    if sys.platform == "win32":
        raise StartupError("VERDIFAX_REQUEST_KEY_FILE is supported on Linux and macOS, where its permissions can be checked")
    try:
        info = os.stat(path)
    except OSError:
        raise StartupError("VERDIFAX_REQUEST_KEY_FILE cannot be read") from None
    if not stat.S_ISREG(info.st_mode):
        raise StartupError("VERDIFAX_REQUEST_KEY_FILE is not a regular file")
    if info.st_mode & 0o077:
        raise StartupError("VERDIFAX_REQUEST_KEY_FILE can be read or written by group or others; run chmod 600 on it first")
    if info.st_size > 1024:
        raise StartupError("VERDIFAX_REQUEST_KEY_FILE is too large to be a request key")
    with open(path, "rb") as handle:
        raw = handle.read()
    if len(raw) == _REQUEST_KEY_BYTES:
        return raw
    text = raw.decode("utf-8", errors="replace").strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    if re.fullmatch(r"[A-Za-z0-9+/]{43}=", text):
        decoded = base64.b64decode(text)
        if len(decoded) == _REQUEST_KEY_BYTES:
            return decoded
    raise StartupError("VERDIFAX_REQUEST_KEY_FILE must hold the 32-byte private key as raw bytes, 64 hex characters or base64")


def load_config(env: Optional[Mapping[str, str]] = None) -> Config:
    env = os.environ if env is None else env
    for name, reason in IMPL["refused_environment"].items():
        if _present(env.get(name)):
            raise StartupError(f"{name} is set. {reason} Remove it from this server's environment.")
    base = env.get("VERDIFAX_BASE_URL") if _present(env.get("VERDIFAX_BASE_URL")) else env.get("VERDIFAX_API_URL")
    config = Config(base_url=check_base_url(base if _present(base) else DEFAULT_BASE_URL))
    if _present(env.get("VERDIFAX_API_KEY")):
        config.api_key = env["VERDIFAX_API_KEY"].strip()
    if _present(env.get("VERDIFAX_FEED_KEY")):
        config.feed_key = env["VERDIFAX_FEED_KEY"].strip()
    if config.api_key and config.api_key == config.feed_key:
        raise StartupError("VERDIFAX_API_KEY and VERDIFAX_FEED_KEY hold the same key")
    if _present(env.get("VERDIFAX_REQUEST_KEY_FILE")):
        if not config.api_key:
            raise StartupError("VERDIFAX_REQUEST_KEY_FILE is set but VERDIFAX_API_KEY is not")
        config.request_key = load_request_key(env["VERDIFAX_REQUEST_KEY_FILE"].strip())
    if _present(env.get("VERDIFAX_MCP_WORKDIR")):
        folder = env["VERDIFAX_MCP_WORKDIR"].strip()
        if not os.path.isabs(folder):
            raise StartupError("VERDIFAX_MCP_WORKDIR must be an absolute path")
        if not os.path.exists(folder):
            raise StartupError("VERDIFAX_MCP_WORKDIR does not exist")
        real = os.path.realpath(folder)
        if not os.path.isdir(real):
            raise StartupError("VERDIFAX_MCP_WORKDIR is not a folder")
        config.workdir = real
    if _present(env.get("VERDIFAX_VERIFY_PATH")):
        path = env["VERDIFAX_VERIFY_PATH"].strip()
        if not os.path.isabs(path):
            raise StartupError("VERDIFAX_VERIFY_PATH must be an absolute path")
        config.verifier_path = path
    if _present(env.get("VERDIFAX_MCP_HTTP_TOKEN")):
        token = env["VERDIFAX_MCP_HTTP_TOKEN"].strip()
        minimum = IMPL["http_mode"]["token_min_chars"]
        if len(token) < minimum:
            raise StartupError(f"VERDIFAX_MCP_HTTP_TOKEN must be at least {minimum} characters")
        config.http_token = token
    return config


def secrets_of(config: Config) -> list[str]:
    """Every secret the redactor must hide, in each form it could appear."""
    out = [s for s in (config.api_key, config.feed_key, config.http_token) if s]
    if config.request_key:
        out += [config.request_key.hex(), config.request_key.hex().upper(), base64.b64encode(config.request_key).decode("ascii")]
    return out
