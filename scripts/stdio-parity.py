"""Runs the TypeScript, Python and Go servers over stdio, as an assistant
would, and fails unless all three list the same tools as mcp-tools.json and
give the same answers to the same calls.

It uses the stand-in verifier in testdata and no API key, so it reaches no
Verdifax server. Run it from the repository root after building the three
servers:

    python scripts/stdio-parity.py "node typescript/dist/main.js" "python -m verdifax_mcp" "go/verdifax-mcp"
"""

import json
import os
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

import anyio
import mcp_types as types
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "mcp-tools.json").read_text(encoding="utf-8"))

CALLS = [
    ("prepare_signoff", {"kind": "job", "run_id": 900, "digest": "3" * 64, "job_id": "claims-7", "decision": "approve"}),
    ("verify_record", {"path": "bundle.json", "strict_signoff": True}),
    ("verify_feed", {"path": "feed.json", "allow_partial": True}),
    ("verify_record", {"path": "../escape.json"}),
    ("get_record", {"run_id": 1}),
    ("seal_decision", {"program_id": "a" * 64, "route_id": "r", "registry_record_hash": "b" * 64, "payload_text": "x"}),
    ("test_policy", {"inputs": {}}),
]


def comparable(tool: dict) -> dict:
    """A tool with the spec's default filled in for any annotation hint left out."""
    tool = json.loads(json.dumps(tool))
    defaults = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
    for key, value in defaults.items():
        tool.setdefault("annotations", {}).setdefault(key, value)
    return tool


async def run(command: str, env: dict) -> tuple[list, list]:
    argv = shlex.split(command)
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=env, cwd=str(ROOT))
    async with Client(params, client_info=types.Implementation(name="parity-check", version="1"), mode="legacy") as client:
        listed = (await client.list_tools()).tools
        tools = sorted((comparable(t.model_dump(by_alias=True, exclude_none=True, mode="json")) for t in listed), key=lambda t: t["name"])
        answers = []
        for name, args in CALLS:
            result = await client.call_tool(name, args)
            answers.append({"tool": name, "is_error": bool(result.is_error), "text": json.loads(result.content[0].text)})
    return tools, answers


async def main(commands: list[str]) -> int:
    work = Path(tempfile.mkdtemp(prefix="verdifax-mcp-parity-"))
    (work / "bundle.json").write_text("{}")
    (work / "feed.json").write_text("{}")
    verifier = work / "bin" / "verdifax-verify"
    verifier.parent.mkdir()
    shutil.copyfile(ROOT / "testdata" / "fake-verdifax-verify", verifier)
    verifier.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("VERDIFAX_")}
    env.update({"VERDIFAX_MCP_WORKDIR": str(work.resolve()), "VERDIFAX_VERIFY_PATH": str(verifier.resolve()), "FAKE_VERIFY_EXIT": "4"})
    want = sorted((comparable(t) for t in CONTRACT["tools"]), key=lambda t: t["name"])
    results = {}
    for command in commands:
        tools, answers = await run(command, env)
        if tools != want:
            print(f"FAIL: {command} lists tools that differ from mcp-tools.json")
            return 1
        results[command] = answers
    first, *rest = commands
    for command in rest:
        for a, b in zip(results[first], results[command]):
            if a != b:
                print(f"FAIL: {command} answers {a['tool']} differently from {first}:\n  {json.dumps(b)[:400]}\n  {json.dumps(a)[:400]}")
                return 1
    print(f"OK: {len(commands)} servers list the contract's {len(want)} tools and give the same {len(CALLS)} answers")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(anyio.run(main, sys.argv[1:]))
