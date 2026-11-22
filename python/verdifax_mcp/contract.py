"""The tool contract, mcp-tools.json, shipped inside this package.

The contract test fails when this copy differs from the one at the
repository's root.
"""

import json
from pathlib import Path
from typing import Any

CONTRACT_PATH = Path(__file__).with_name("mcp-tools.json")
CONTRACT: dict[str, Any] = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
IMPL: dict[str, Any] = CONTRACT["implementation"]
TOOLS: list[dict[str, Any]] = CONTRACT["tools"]
TOOL_NAMES: list[str] = [t["name"] for t in TOOLS]
NOTICE: str = IMPL["data_notice"]


def tool_definition(name: str) -> dict[str, Any] | None:
    for tool in TOOLS:
        if tool["name"] == name:
            return tool
    return None


def output_const(tool: str, field: str) -> str:
    """The fixed text the contract's output schema gives a field."""
    definition = tool_definition(tool)
    value = (definition or {}).get("outputSchema", {}).get("properties", {}).get(field, {}).get("const")
    if not isinstance(value, str):
        raise RuntimeError(f"mcp-tools.json gives {tool}.{field} no fixed text")
    return value
