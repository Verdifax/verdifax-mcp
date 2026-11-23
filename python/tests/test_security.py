"""Security tests: owner-key refusal, refused environment, key file
permissions, path traversal, hostile record strings and secret leaks."""

import base64
import json
import os
import re
from pathlib import Path

import pytest

from conftest import (
    FEED_KEY, MEMBER_KEY, OWNER_KEY, TESTDATA, connect, key_check, read_json, result_json, temp_dir,
)
from verdifax_mcp.config import Config, load_config
from verdifax_mcp.errors import StartupError
from verdifax_mcp.server import Grants
from verdifax_mcp.startup import prepare

HOSTILE = read_json(TESTDATA / "hostile-strings.json")["cases"]
SEAL_ARGS = {"program_id": "a" * 64, "route_id": "r", "registry_record_hash": "b" * 64, "payload_text": "x"}
# Characters a reader cannot see: control characters other than tab, line
# feed and carriage return, zero-width and direction marks, word joiners, the
# byte order mark and tag characters. The same set as hiddenChars in
# go/security_test.go, written as code point ranges (CodeQL
# py/overly-large-range reads a control-character range in a pattern as a
# likely mistake).
HIDDEN_RANGES = [
    (0x00, 0x08), (0x0B, 0x0C), (0x0E, 0x1F), (0x7F, 0x9F), (0x200B, 0x200F),
    (0x202A, 0x202E), (0x2060, 0x206F), (0xFEFF, 0xFEFF), (0xE0000, 0xE0FFF),
]


def hidden_chars(text: str) -> list[str]:
    return [c for c in text if any(lo <= ord(c) <= hi for lo, hi in HIDDEN_RANGES)]


@pytest.mark.anyio
async def test_an_owner_key_stops_the_server_at_startup_and_nothing_is_sealed(fake_api) -> None:
    api = fake_api(key_check)
    with pytest.raises(StartupError) as err:
        await prepare({"VERDIFAX_BASE_URL": api.base_url, "VERDIFAX_API_KEY": OWNER_KEY})
    assert re.search(r"VERDIFAX_API_KEY is an account owner key\. This server never holds owner powers", str(err.value))
    assert OWNER_KEY not in str(err.value)
    assert [f"{r['method']} {r['path']}" for r in api.requests] == ["GET /stats"]


@pytest.mark.anyio
async def test_owner_and_wrong_keys_in_either_slot_are_refused(fake_api) -> None:
    api = fake_api(key_check)
    with pytest.raises(StartupError, match="VERDIFAX_FEED_KEY is an account owner key"):
        await prepare({"VERDIFAX_BASE_URL": api.base_url, "VERDIFAX_API_KEY": MEMBER_KEY, "VERDIFAX_FEED_KEY": OWNER_KEY})
    with pytest.raises(StartupError, match="VERDIFAX_API_KEY is a feed key"):
        await prepare({"VERDIFAX_BASE_URL": api.base_url, "VERDIFAX_API_KEY": FEED_KEY})
    with pytest.raises(StartupError, match="not a feed key"):
        await prepare({"VERDIFAX_BASE_URL": api.base_url, "VERDIFAX_FEED_KEY": MEMBER_KEY})


@pytest.mark.anyio
async def test_reported_grants_limit_the_tools(fake_api) -> None:
    api = fake_api(lambda e: key_check(e, {"X-Verdifax-Allowed-Tools": "get_record, list_records, made_up_tool"}))
    config, grants = await prepare({"VERDIFAX_BASE_URL": api.base_url, "VERDIFAX_API_KEY": MEMBER_KEY, "VERDIFAX_FEED_KEY": FEED_KEY})
    assert grants.granted_tools == ["get_record", "list_records"]
    async with connect(config, grants) as client:
        assert "granted these tools: get_record, list_records." in client.instructions
        refused = await client.call_tool("seal_decision", SEAL_ARGS)
    assert refused.is_error
    assert "did not grant seal_decision" in result_json(refused)["error"]
    assert not any(r["path"] == "/execute" for r in api.requests)


def test_approver_and_owner_keys_in_the_environment_stop_the_server() -> None:
    for name in ("VERDIFAX_APPROVER_KEY", "VERDIFAX_APPROVER_KEY_FILE", "VERDIFAX_OWNER_KEY"):
        with pytest.raises(StartupError, match=name):
            load_config({name: "anything"})


def test_request_key_file_permissions_and_forms(tmp_path: Path) -> None:
    raw = bytes([7]) * 32
    for name, content in {"raw.key": raw, "hex.key": (raw.hex() + "\n").encode(), "b64.key": base64.b64encode(raw)}.items():
        path = tmp_path / name
        path.write_bytes(content)
        path.chmod(0o644)
        with pytest.raises(StartupError, match="group or others"):
            load_config({"VERDIFAX_API_KEY": MEMBER_KEY, "VERDIFAX_REQUEST_KEY_FILE": str(path)})
        path.chmod(0o600)
        assert load_config({"VERDIFAX_API_KEY": MEMBER_KEY, "VERDIFAX_REQUEST_KEY_FILE": str(path)}).request_key == raw
    bad = tmp_path / "bad.key"
    bad.write_text("not a key")
    bad.chmod(0o600)
    with pytest.raises(StartupError, match="32-byte private key"):
        load_config({"VERDIFAX_API_KEY": MEMBER_KEY, "VERDIFAX_REQUEST_KEY_FILE": str(bad)})


def test_plain_http_is_refused_for_any_host_but_this_machine() -> None:
    with pytest.raises(StartupError, match="https"):
        load_config({"VERDIFAX_BASE_URL": "http://api.verdifax.com"})
    with pytest.raises(StartupError, match="user name"):
        load_config({"VERDIFAX_BASE_URL": "https://user:pw@api.verdifax.com"})
    assert load_config({"VERDIFAX_BASE_URL": "http://127.0.0.1:8080/"}).base_url == "http://127.0.0.1:8080"


@pytest.mark.anyio
async def test_paths_that_leave_the_working_folder_are_refused_before_the_verifier_runs(workdir, verifier) -> None:
    outside = temp_dir()
    (outside / "secret.json").write_text("{}")
    os.symlink(outside / "secret.json", workdir / "link.json")
    attempts = [
        {"path": "../outside.json"},
        {"path": "records/../../etc/passwd"},
        {"path": "/etc/passwd"},
        {"path": "link.json"},
        {"path": "records"},
        {"path": "missing.json"},
        {"path": "records/bundle.json", "policy_path": "../policy.json"},
        {"path": "records/bundle.json\u0000.txt"},
    ]
    async with connect(Config(base_url="http://127.0.0.1:9", workdir=str(workdir), verifier_path=verifier["path"])) as client:
        for args in attempts:
            assert (await client.call_tool("verify_record", args)).is_error, args
        assert (await client.call_tool("verify_feed", {"path": "feed.json", "owner_request_key_paths": ["../k.txt"]})).is_error
        assert (await client.call_tool("test_policy", {"inputs": {}, "document_path": "../policy.json"})).is_error
    assert not verifier["args_file"].exists(), "the verifier never ran"


@pytest.mark.anyio
async def test_hostile_record_strings_come_back_only_as_cleaned_quoted_fields(fake_api, workdir, verifier, monkeypatch) -> None:
    record = {"notes": [c["raw"] for c in HOSTILE], HOSTILE[0]["raw"]: "key with hidden characters"}
    api = fake_api(lambda e: (200, record, {}) if e["path"] == "/runs/7/artifacts" else key_check(e))
    stdout = workdir / "stdout.json"
    stdout.write_text(json.dumps({"verdict_tier": "FAILED", "reason": HOSTILE[2]["raw"]}))
    monkeypatch.setenv("FAKE_VERIFY_STDOUT_FILE", str(stdout))
    monkeypatch.setenv("FAKE_VERIFY_STDERR", HOSTILE[0]["raw"])
    monkeypatch.setenv("FAKE_VERIFY_EXIT", "1")
    config = Config(base_url=api.base_url, api_key=MEMBER_KEY, workdir=str(workdir), verifier_path=verifier["path"])
    async with connect(config) as client:
        res = await client.call_tool("get_record", {"run_id": 7})
        verified = await client.call_tool("verify_record", {"path": "records/bundle.json"})
    assert not res.is_error
    assert res.structured_content["record"]["notes"] == [c["cleaned"] for c in HOSTILE]
    assert HOSTILE[0]["cleaned"] in res.structured_content["record"]
    assert result_json(res) == res.structured_content
    assert verified.structured_content["outcome"] == "failed"
    assert verified.structured_content["report"]["reason"] == HOSTILE[2]["cleaned"]
    assert verified.structured_content["stderr"].strip() == HOSTILE[0]["cleaned"]
    for content in (res.structured_content, verified.structured_content):
        assert not hidden_chars(json.dumps(content, ensure_ascii=False))


@pytest.mark.anyio
async def test_seal_decision_refuses_hidden_characters_and_sends_nothing(fake_api) -> None:
    api = fake_api(key_check)
    async with connect(Config(base_url=api.base_url, api_key=MEMBER_KEY)) as client:
        res = await client.call_tool("seal_decision", {**SEAL_ARGS, "payload_text": "approve\u200b"})
    assert res.is_error
    assert "control or zero-width" in result_json(res)["error"]
    assert api.requests == []


@pytest.mark.anyio
async def test_no_secret_leaves_the_server(fake_api, workdir, verifier, monkeypatch) -> None:
    request_key = bytes([9]) * 32
    echo = f"{MEMBER_KEY} {FEED_KEY} {request_key.hex()} {base64.b64encode(request_key).decode()} vfx_00112233445566778899"

    def handler(e: dict):
        if e["path"] == "/runs/1/artifacts":
            return (200, {"leaked": echo}, {})
        if e["path"] == "/runs":
            return (500, {"ok": False, "error": f"bad key {e['key']}"}, {})
        if e["path"] == "/execute":
            return (400, {"ok": False, "error": f"refused {echo}"}, {})
        if e["path"] == "/signals":
            return (200, {"events": [{"id": "1", "data": {"kind": "x", "entry": {"note": echo}}}], "next_after": 1, "newest": 1}, {})
        return key_check(e)

    api = fake_api(handler)
    monkeypatch.setenv("FAKE_VERIFY_STDERR", echo)
    monkeypatch.setenv("VERDIFAX_API_KEY", MEMBER_KEY)
    monkeypatch.setenv("VERDIFAX_FEED_KEY", FEED_KEY)
    config = Config(base_url=api.base_url, api_key=MEMBER_KEY, feed_key=FEED_KEY, request_key=request_key, workdir=str(workdir), verifier_path=verifier["path"])
    async with connect(config) as client:
        results = [
            await client.call_tool("get_record", {"run_id": 1}),
            await client.call_tool("list_records", {}),
            await client.call_tool("read_feed", {}),
            await client.call_tool("verify_record", {"path": "records/bundle.json"}),
            await client.call_tool("seal_decision", SEAL_ARGS),
        ]
    everything = json.dumps([r.model_dump(mode="json") for r in results])
    for secret in (MEMBER_KEY, FEED_KEY, request_key.hex(), base64.b64encode(request_key).decode(), "vfx_00112233445566778899"):
        assert secret not in everything, f"a secret leaked: {secret[:8]}"
    assert "[redacted]" in everything
    assert Path(str(verifier["args_file"]) + ".env").read_text().strip() == "", "no VERDIFAX_ variable reached the verifier"


def test_grants_default_is_no_list() -> None:
    assert Grants().granted_tools is None
