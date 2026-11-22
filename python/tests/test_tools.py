"""Each tool against the stand-in API and the stand-in verifier."""

import base64
import hashlib
import json
import socket
import threading
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from verdifax import request_signature_preimage_v2

from conftest import FEED_KEY, MEMBER_KEY, TESTDATA, connect, key_check, read_json, result_json
from verdifax_mcp.config import Config
from verdifax_mcp.contract import CONTRACT, IMPL
from verdifax_mcp.errors import StartupError
from verdifax_mcp.http_mode import http_app
from verdifax_mcp.server import Grants, create_server

SEAL_ARGS = {"program_id": "a" * 64, "route_id": "claims/review", "registry_record_hash": "b" * 64, "payload_text": "Approve claim 7."}
V = IMPL["verifier"]


def lines(path) -> list[str]:
    return path.read_text().strip().split("\n")


@pytest.fixture
def verify_config(workdir, verifier):
    for name in ("approver.txt", "owner-1.txt", "owner-2.txt"):
        (workdir / name).write_text("AAAA")
    return Config(base_url="http://127.0.0.1:9", workdir=str(workdir), verifier_path=verifier["path"])


@pytest.mark.anyio
async def test_verify_record_maps_every_exit_code_to_its_outcome(verify_config, monkeypatch) -> None:
    expected = {0: "verified", 1: "failed", 2: "unreadable_input", 3: "partial_coverage", 4: "signoff_not_shown", 9: "unknown_exit_code"}
    async with connect(verify_config) as client:
        for code, outcome in expected.items():
            monkeypatch.setenv("FAKE_VERIFY_EXIT", str(code))
            res = await client.call_tool("verify_record", {"path": "records/bundle.json"})
            assert not res.is_error, res
            out = res.structured_content
            assert out["exit_code"] == code
            assert out["outcome"] == outcome
            assert out["outcome_meaning"] == V["record_exit_codes"].get(str(code), V["unknown_exit_code"])[1]
            assert out["verifier"]["version"] == "verdifax-verify v0.38.0 (test stand-in)"


@pytest.mark.anyio
async def test_verify_record_passes_the_contract_flags_in_order(verify_config, verifier, workdir) -> None:
    async with connect(verify_config) as client:
        res = await client.call_tool(
            "verify_record",
            {
                "path": "records/bundle.json", "strict_signoff": True, "signoff_path": "feed.json", "policy_path": "policy.json",
                "approver_public_key_path": "approver.txt", "allow_partial": False, "signoff_head_max_age": "72h",
            },
        )
    assert not res.is_error, res
    want = [
        "--json", "--policy", str(workdir / "policy.json"), "--signoff", str(workdir / "feed.json"),
        "--approver-key", str(workdir / "approver.txt"), "--strict-signoff", "--signoff-head-max-age", "72h",
        str(workdir / "records" / "bundle.json"),
    ]
    assert lines(verifier["args_file"]) == want
    assert res.structured_content["arguments"] == want


@pytest.mark.anyio
async def test_verify_feed_runs_signals_with_its_flags(verify_config, verifier, workdir, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_VERIFY_EXIT", "3")
    after = "12:" + "c" * 64
    async with connect(verify_config) as client:
        res = await client.call_tool(
            "verify_feed",
            {"path": "feed.json", "signals_after": after, "owner_request_key_paths": ["owner-1.txt", "owner-2.txt"], "feed_head_max_age": "48h"},
        )
    assert not res.is_error, res
    assert res.structured_content["outcome"] == "partial_coverage"
    assert res.structured_content["outcome_meaning"] == V["feed_exit_codes"]["3"][1]
    assert lines(verifier["args_file"]) == [
        "--json", "--signals", str(workdir / "feed.json"), "--signals-after", after,
        "--owner-request-key", f"{workdir / 'owner-1.txt'},{workdir / 'owner-2.txt'}", "--feed-head-max-age", "48h",
    ]


@pytest.mark.anyio
async def test_arguments_outside_the_input_schema_are_refused(verify_config) -> None:
    async with connect(verify_config) as client:
        for args in ({}, {"path": "records/bundle.json", "url": "https://example.com"}, {"path": "records/bundle.json", "signoff_head_max_age": "1d"}):
            assert (await client.call_tool("verify_record", args)).is_error, args


@pytest.mark.anyio
async def test_the_verifier_missing_is_a_plain_refusal(workdir) -> None:
    async with connect(Config(base_url="http://127.0.0.1:9", workdir=str(workdir), verifier_path="/nonexistent/verdifax-verify")) as client:
        res = await client.call_tool("verify_record", {"path": "records/bundle.json"})
    assert res.is_error
    assert "VERDIFAX_VERIFY_PATH" in result_json(res)["error"]


@pytest.mark.anyio
async def test_the_read_tools_return_the_api_answers_through_the_sdk(fake_api, workdir) -> None:
    def sealed(i: int) -> dict:
        return {"specversion": "1.0", "id": str(i), "data": {"kind": "run.sealed", "sequence": i, "entry": {"run_id": i, "signoff_required": i in (11, 12)}}}

    first = [sealed(i + 1) for i in range(500)]
    later = [{"specversion": "1.0", "id": "501", "data": {"kind": "signoff.recorded", "sequence": 501, "entry": {"target": {"kind": "record", "run_id": 11}, "decision": "approve"}}}]

    def handler(e: dict):
        if e["path"] == "/runs/5/artifacts":
            return (200, {"bundle_anchor": {"anchored_digest": "d" * 64}}, {})
        if e["path"] == "/runs":
            return (200, {"ok": True, "runs": [{"id": 5, "status": "completed"}], "total": 1}, {})
        if e["path"] == "/runs/5/signoffs":
            return (200, [{"decision": "approve", "signoff_hash": "e" * 64}], {})
        if e["path"] == "/signals":
            assert e["key"] == FEED_KEY
            after = int(e["query"].get("after", ["0"])[0])
            limit = int(e["query"].get("limit", ["100"])[0])
            if limit == 500 and after == 0:
                return (200, {"events": first, "next_after": 500, "newest": 501}, {})
            if limit == 500 and after == 500:
                return (200, {"events": later, "next_after": 501, "newest": 501, "head": {"format": "verdifax.feed-head.v1", "account": "account-7", "sequence": 501, "head_hash": "a" * 64, "head_statement_hash": "b" * 64, "stated_at": "2026-11-17T12:00:00Z"}}, {})
            return (200, {"events": first[after:after + limit], "next_after": after + limit, "newest": 501}, {})
        if e["path"] == "/policies/test":
            body = json.loads(e["body"])
            assert sorted(body) == (["document", "inputs"] if "document" in body else ["document_hash", "inputs"])
            return (200, {"ok": True, "sealed": False, "outcome": "deny", "fired_rule_id": "r1", "reason_code": "TEST"}, {})
        return key_check(e)

    api = fake_api(handler)
    config = Config(base_url=api.base_url, api_key=MEMBER_KEY, feed_key=FEED_KEY, workdir=str(workdir))
    async with connect(config) as client:
        async def call(name: str, args: dict | None = None) -> dict:
            res = await client.call_tool(name, args or {})
            assert not res.is_error, (name, res)
            return res.structured_content

        assert (await call("get_record", {"run_id": 5}))["record"]["bundle_anchor"]["anchored_digest"] == "d" * 64
        listed = await call("list_records", {"limit": 5})
        assert (listed["total"], listed["limit"]) == (1, 5)
        assert next(r for r in api.requests if r["path"] == "/runs")["query"]["limit"] == ["5"]
        assert (await call("get_signoffs", {"run_id": 5}))["signoffs"][0]["decision"] == "approve"
        feed = await call("read_feed", {"limit": 1})
        assert (len(feed["events"]), feed["next_after"]) == (1, 1)
        pending = await call("list_pending_signoffs")
        assert pending["run_ids"] == [12]
        assert (pending["events_read"], pending["pages_read"], pending["head"]["sequence"]) == (501, 2, 501)
        tested = await call("test_policy", {"inputs": {"actor_type": "agent"}, "document_path": "policy.json"})
        assert (tested["sealed"], tested["outcome"], tested["fired_rule_id"]) == (False, "deny", "r1")
        await call("test_policy", {"inputs": {}, "document_hash": "f" * 64})
        both = await client.call_tool("test_policy", {"inputs": {}, "document_hash": "f" * 64, "document_path": "policy.json"})
        assert both.is_error
    assert not [r for r in api.requests if r["method"] == "POST" and r["path"] == "/execute"], "no read tool seals anything"


@pytest.mark.anyio
async def test_an_api_refusal_comes_back_as_a_plain_tool_error(fake_api) -> None:
    api = fake_api(lambda e: (404, {"ok": False, "error": "run not found"}, {}) if e["path"] == "/runs/8/artifacts" else key_check(e))
    async with connect(Config(base_url=api.base_url, api_key=MEMBER_KEY)) as client:
        res = await client.call_tool("get_record", {"run_id": 8})
        assert res.is_error
        assert "404" in result_json(res)["error"]
        no_feed = await client.call_tool("read_feed", {})
        assert "VERDIFAX_FEED_KEY is not set" in result_json(no_feed)["error"]


@pytest.mark.anyio
async def test_seal_decision_signs_and_seals_the_declared_client(fake_api) -> None:
    vector = read_json(TESTDATA / "seal-vector.json")
    key = bytes.fromhex(vector["request_key_hex"])
    api = fake_api(lambda e: (200, {"ok": True, "run_id": 42, "record_hash": "9" * 64}, {}) if e["path"] == "/execute" else key_check(e))
    args = {**SEAL_ARGS, "policy_context": {"data_use": {"purpose": "claims-review", "categories": ["health"]}}}
    async with connect(Config(base_url=api.base_url, api_key=MEMBER_KEY, request_key=key), client_info={"name": "Claude Code", "version": "2.9.0"}) as client:
        res = await client.call_tool("seal_decision", args)
    assert not res.is_error, res
    out = res.structured_content
    assert (out["sealed"], out["outcome"], out["run_id"], out["signed"]) == (True, "completed", 42, True)
    assert out["declared_client"] == {"name": "Claude Code", "version": "2.9.0", "label": "declared, not verified"}
    sent = json.loads(next(r for r in api.requests if r["path"] == "/execute")["body"])
    assert sorted(sent) == ["request_signature", "signed_request"]
    assert sent["signed_request"] == out["signed_request"]
    inner = json.loads(sent["signed_request"])
    ac = inner["attested_context"]
    assert (ac["client_name"], ac["client_version"], ac["attested"]) == ("Claude Code", "2.9.0", True)
    assert "reproducibility_context" not in inner
    assert inner["policy_context"]["data_use"] == {"purpose": "claims-review", "categories": ["health"]}
    sig = sent["request_signature"]
    preimage = request_signature_preimage_v2(
        hashlib.sha256(sent["signed_request"].encode()).hexdigest(), hashlib.sha256(SEAL_ARGS["payload_text"].encode()).hexdigest(),
        SEAL_ARGS["program_id"], SEAL_ARGS["route_id"], SEAL_ARGS["registry_record_hash"], "", None, sig["signed_at"], sig["nonce"],
    )
    Ed25519PrivateKey.from_private_bytes(key).public_key().verify(base64.b64decode(sig["signature"]), preimage)


@pytest.mark.anyio
async def test_seal_decision_unsigned_receipts_and_errors(fake_api) -> None:
    state = {"status": 422}

    def handler(e: dict):
        if e["path"] == "/execute":
            if state["status"] == 422:
                return (422, {"ok": False, "error": "policy refused", "run_id": 43, "record_hash": "8" * 64}, {})
            return (state["status"], {"ok": False, "error": "unknown field attested_context.client_name"}, {})
        return key_check(e)

    api = fake_api(handler)
    async with connect(Config(base_url=api.base_url, api_key=MEMBER_KEY)) as client:
        res = await client.call_tool("seal_decision", SEAL_ARGS)
        assert not res.is_error, res
        out = res.structured_content
        assert (out["outcome"], out["sealed"], out["signed"], out["signed_request"]) == ("not_completed", True, False, None)
        sent = json.loads(api.requests[-1]["body"])
        assert sent["payload_text"] == SEAL_ARGS["payload_text"]
        assert sent["attested_context"]["client_name"] == "test-client"
        assert "reproducibility_context" not in sent
        state["status"] = 400
        refused = await client.call_tool("seal_decision", SEAL_ARGS)
    assert refused.is_error
    assert "HTTP 400: unknown field" in result_json(refused)["error"]


@pytest.mark.anyio
async def test_prepare_signoff_makes_no_request_and_requires_job_id_only_for_a_job() -> None:
    async with connect(Config(base_url="http://127.0.0.1:9")) as client:
        ok = await client.call_tool("prepare_signoff", {"kind": "record", "run_id": 1, "digest": "1" * 64, "decision": "approve"})
        assert not ok.is_error
        assert len(ok.structured_content["steps"]) == 4
        assert (await client.call_tool("prepare_signoff", {"kind": "job", "run_id": 1, "digest": "1" * 64, "decision": "approve"})).is_error
        assert (await client.call_tool("prepare_signoff", {"kind": "record", "run_id": 1, "digest": "1" * 64, "job_id": "j", "decision": "approve"})).is_error
        bad = "1'; rm -rf ~; '".ljust(64, "a")
        assert (await client.call_tool("prepare_signoff", {"kind": "record", "run_id": 1, "digest": bad, "decision": "approve"})).is_error


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_http_mode_serves_the_same_tools_and_checks_the_bearer_token() -> None:
    import uvicorn

    token = "t" * 40
    port = _free_port()
    app = http_app(create_server(Config(base_url="http://127.0.0.1:9"), Grants()), "127.0.0.1", token)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        url = f"http://127.0.0.1:{port}/mcp"
        assert httpx.post(url, json={}).status_code == 401
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "http-test", "version": "1"}}}
        with httpx.Client(headers=headers, timeout=10) as http:
            first = http.post(url, json=init)
            assert first.status_code == 200, first.text
            session = first.headers.get("mcp-session-id")
            more = {"mcp-session-id": session} if session else {}
            more["mcp-protocol-version"] = "2025-06-18"
            http.post(url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=more)
            listed = http.post(url, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=more)
            text = listed.text
            payload = json.loads(text[text.index("{"):text.rindex("}") + 1]) if text.lstrip().startswith(("event", "data", ":")) else listed.json()
            assert [t["name"] for t in payload["result"]["tools"]] == [t["name"] for t in CONTRACT["tools"]]
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    with pytest.raises(StartupError):
        http_app(create_server(Config(base_url="http://127.0.0.1:9"), Grants()), "0.0.0.0", None)
