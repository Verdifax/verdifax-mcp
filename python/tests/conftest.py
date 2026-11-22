"""Test helpers: a local stand-in for the Verdifax API, a working folder, the
stand-in verifier, and an MCP client joined to the server in process. No test
reaches api.verdifax.com or any paid service."""

import json
import os
import shutil
import stat
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

import mcp_types as types
import pytest
from mcp import Client

from verdifax_mcp.config import Config
from verdifax_mcp.server import Grants, create_server

REPO = Path(__file__).resolve().parents[2]
TESTDATA = REPO / "testdata"

OWNER_ERROR = "an account owner key manages the account and cannot run or read runs itself; use a member key, or the /account routes"
FEED_ERROR = "a feed key reads the account's signal feed at GET /signals and nothing else"
MEMBER_KEY = "vfx_" + "1a" * 24
FEED_KEY = "vfx_" + "2b" * 24
OWNER_KEY = "vfx_" + "3c" * 24


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class FakeAPI:
    """A stand-in API. handler(entry) returns (status, body, headers) or None."""

    def __init__(self, handler: Callable[[dict], Optional[tuple]]) -> None:
        self.requests: list[dict] = []
        api = self

        class Handle(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8") if length else ""
                url = urlsplit(self.path)
                entry = {"method": self.command, "path": url.path, "query": parse_qs(url.query), "key": self.headers.get("X-Verdifax-Key"), "body": body}
                api.requests.append(entry)
                out = handler(entry) or (404, {"ok": False, "error": "not found"}, {})
                status, payload, headers = (out + ({},))[:3] if len(out) == 2 else out
                data = payload if isinstance(payload, str) else json.dumps(payload)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data.encode("utf-8"))))
                self.end_headers()
                self.wfile.write(data.encode("utf-8"))

            do_GET = _serve
            do_POST = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handle)
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake_api():
    made: list[FakeAPI] = []

    def start(handler: Callable[[dict], Optional[tuple]]) -> FakeAPI:
        api = FakeAPI(handler)
        made.append(api)
        return api

    yield start
    for api in made:
        api.close()


def key_check(entry: dict, headers: Optional[dict] = None) -> Optional[tuple]:
    if entry["method"] == "GET" and entry["path"] == "/stats":
        if entry["key"] == OWNER_KEY:
            return (403, {"ok": False, "error": OWNER_ERROR}, {})
        if entry["key"] == FEED_KEY:
            return (403, {"ok": False, "error": FEED_ERROR}, {})
        return (200, {"ok": True, "total_runs": 0}, headers or {})
    return None


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    folder = (tmp_path / "work").resolve()
    (folder / "records").mkdir(parents=True)
    (folder / "records" / "bundle.json").write_text("{}")
    (folder / "feed.json").write_text("{}")
    (folder / "policy.json").write_text('{"policy_id":"p"}')
    return Path(os.path.realpath(folder))


@pytest.fixture
def verifier(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    folder = tmp_path / "verifier"
    folder.mkdir()
    path = folder / "verdifax-verify"
    shutil.copyfile(TESTDATA / "fake-verdifax-verify", path)
    path.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    args_file = folder / "args.txt"
    monkeypatch.setenv("FAKE_VERIFY_ARGS_FILE", str(args_file))
    return {"path": str(path), "args_file": args_file}


def connect(config: Config, grants: Optional[Grants] = None, client_info: Optional[dict] = None) -> Client:
    info = client_info or {"name": "test-client", "version": "9.9.9"}
    server = create_server(config, grants or Grants())
    return Client(server, client_info=types.Implementation(**info), mode="legacy")


def result_json(result: Any) -> Any:
    return json.loads(result.content[0].text)


def temp_dir() -> Path:
    return Path(os.path.realpath(tempfile.mkdtemp(prefix="verdifax-mcp-test-")))
