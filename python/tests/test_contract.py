"""Contract conformance: this implementation serves exactly the tools in
mcp-tools.json, its copy of the contract is byte-identical to the root one,
and the shared vectors come out the same as in every other language."""

import json
import re

import pytest

from conftest import REPO, TESTDATA, connect, read_json
from verdifax_mcp.config import Config
from verdifax_mcp.contract import CONTRACT, CONTRACT_PATH, IMPL
from verdifax_mcp.seal import declared_client, seal_body, sign_body
from verdifax_mcp.signoff import prepare_signoff
from verdifax_mcp.tools import HANDLERS

NAMES = ["verify_record", "verify_feed", "get_record", "list_records", "read_feed", "list_pending_signoffs", "get_signoffs", "test_policy", "seal_decision", "prepare_signoff"]


def test_shipped_contract_is_byte_identical_to_the_root_copy() -> None:
    assert CONTRACT_PATH.read_bytes() == (REPO / "mcp-tools.json").read_bytes()


@pytest.mark.anyio
async def test_tools_list_serves_exactly_the_contract_tools_in_order() -> None:
    root = read_json(REPO / "mcp-tools.json")
    async with connect(Config(base_url="http://127.0.0.1:9")) as client:
        listed = await client.list_tools()
        served = [t.model_dump(by_alias=True, exclude_none=True, mode="json") for t in listed.tools]
    assert served == root["tools"]
    assert [t["name"] for t in served] == NAMES


def test_every_contract_tool_has_a_handler_and_no_handler_is_outside_it() -> None:
    assert sorted(HANDLERS) == sorted(NAMES)
    assert sorted(IMPL["uses"]) == sorted(NAMES)


def test_no_tool_takes_a_secret_as_input() -> None:
    forbidden = re.compile(r"key|secret|token|password|credential", re.I)
    allowed = {"approver_public_key_path", "signer_public_key_path", "owner_request_key_paths"}

    def walk(schema: dict, path: str) -> None:
        for name, sub in schema.get("properties", {}).items():
            assert name in allowed or not forbidden.search(name), f"{path}.{name} looks like a secret field"
            if sub.get("type") == "object":
                walk(sub, f"{path}.{name}")

    for tool in CONTRACT["tools"]:
        walk(tool["inputSchema"], tool["name"])


@pytest.mark.anyio
async def test_initialize_names_the_contract_server_and_instructions() -> None:
    async with connect(Config(base_url="http://127.0.0.1:9")) as client:
        assert client.server_info.name == CONTRACT["server"]["name"]
        assert client.server_info.version == CONTRACT["server"]["version"]
        assert client.instructions.startswith(CONTRACT["server"]["instructions"])
        assert client.instructions.endswith(CONTRACT["server"]["grants_line_none"])


def test_seal_decision_builds_and_signs_the_shared_vector_exactly() -> None:
    vector = read_json(TESTDATA / "seal-vector.json")
    for case in vector["cases"]:
        body = seal_body(case["arguments"], declared_client(case["client_info"]))
        assert json.dumps(body, ensure_ascii=False, separators=(",", ":")) == case["signed_request"]
        signed = sign_body(bytes.fromhex(vector["request_key_hex"]), body, vector["signed_at"], vector["nonce"])
        assert signed["signed_request"] == case["signed_request"]
        assert signed["request_signature"] == case["request_signature"]


def test_prepare_signoff_prints_the_shared_vector_commands_exactly() -> None:
    for case in read_json(TESTDATA / "prepare-signoff-vector.json")["cases"]:
        assert prepare_signoff(case["arguments"])["command"] == case["command"]


def test_the_em_dash_appears_nowhere_in_the_contract() -> None:
    assert "\u2014" not in CONTRACT_PATH.read_text(encoding="utf-8")
