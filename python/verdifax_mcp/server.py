"""The MCP server.

tools/list serves the contract's tools exactly; tools/call checks the
arguments against the contract's input schema, applies the key's reported
grants, runs the handler, cleans and redacts the answer, and checks it
against the contract's output schema before it is sent.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Optional

import jsonschema
import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError

from .clean import Redactor
from .config import Config, secrets_of
from .contract import CONTRACT, IMPL, TOOLS, tool_definition
from .errors import ToolError
from .tools import HANDLERS, Runtime

_INPUT = {t["name"]: jsonschema.Draft202012Validator(t["inputSchema"]) for t in TOOLS}
_OUTPUT = {t["name"]: jsonschema.Draft202012Validator(t["outputSchema"]) for t in TOOLS}
_LISTED = [types.Tool.model_validate(t) for t in TOOLS]


@dataclass
class Grants:
    """The tools the server reported this member key may use, or None."""

    api_key: Optional[list[str]] = field(default=None)


def instructions_for(grants: Grants) -> str:
    server = CONTRACT["server"]
    if grants.api_key is None:
        line = server["grants_line_none"]
    else:
        line = server["grants_line_reported"].replace("{tools}", ", ".join(grants.api_key) if grants.api_key else "none")
    return f"{server['instructions']} {line}"


def _describe(error: Optional[jsonschema.ValidationError]) -> str:
    if error is None:
        return "the arguments do not match the tool's input schema"
    where = "/" + "/".join(str(p) for p in error.absolute_path) if error.absolute_path else "the arguments"
    return f"{where} {error.message}"


def create_server(config: Config, grants: Grants) -> Server:
    redactor = Redactor(secrets_of(config))

    def failure(message: str) -> types.CallToolResult:
        text = json.dumps({"error": redactor.text(message)}, ensure_ascii=False)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)

    async def list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=list(_LISTED))

    async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        name = params.name
        if tool_definition(name) is None or name not in HANDLERS:
            raise MCPError(code=types.INVALID_PARAMS, message=f"Unknown tool: {redactor.text(str(name))}")
        args = dict(params.arguments or {})
        error = next(iter(_INPUT[name].iter_errors(args)), None)
        if error is not None:
            return failure(f"Refused: {_describe(error)}")
        if IMPL["uses"][name] == "api_key" and grants.api_key is not None and name not in grants.api_key:
            return failure(f"Refused: the Verdifax server reports that this key's owner did not grant {name}")

        def client_info() -> Optional[dict[str, Any]]:
            client_params = ctx.session.client_params
            if client_params is None or client_params.client_info is None:
                return None
            return {"name": client_params.client_info.name, "version": client_params.client_info.version}

        try:
            answer = redactor.value(await HANDLERS[name](args, Runtime(config=config, client_info=client_info)))
        except ToolError as err:
            return failure(str(err))
        except Exception as err:  # noqa: BLE001 - every failure becomes a plain, redacted tool error
            return failure(f"The tool failed: {err}")
        out_error = next(iter(_OUTPUT[name].iter_errors(answer)), None)
        if out_error is not None:
            return failure(f"This server built an answer its contract does not allow: {_describe(out_error)}")
        text = json.dumps(answer, ensure_ascii=False)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], structured_content=answer)

    return Server(
        CONTRACT["server"]["name"],
        version=CONTRACT["server"]["version"],
        title=CONTRACT["server"]["title"],
        instructions=instructions_for(grants),
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
