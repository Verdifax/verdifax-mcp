"""The two requests this server makes without the SDK: the startup key
check, which must read a response header, and seal_decision's POST of the
exact body text it signed. Every other request goes through the Verdifax SDK.
"""

import json
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .clean import Redactor
from .contract import CONTRACT, IMPL, TOOL_NAMES
from .errors import StartupError, ToolError

USER_AGENT = f"verdifax-mcp/{CONTRACT['server']['version']} (python)"


@dataclass
class RawAnswer:
    status: int
    headers: httpx.Headers
    body: Any


async def request(
    base_url: str,
    key: str,
    method: str,
    path: str,
    body: Optional[str] = None,
    timeout: float = IMPL["limits"]["request_timeout_seconds"],
) -> RawAnswer:
    headers = {"X-Verdifax-Key": key, "Accept": "application/json", "User-Agent": USER_AGENT}
    if body is not None:
        headers["Content-Type"] = "application/json"
    limit = IMPL["limits"]["max_answer_bytes"]
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            async with client.stream(method, base_url + path, headers=headers, content=body) as res:
                chunks = []
                total = 0
                async for chunk in res.aiter_bytes():
                    total += len(chunk)
                    if total > limit:
                        raise ToolError("The Verdifax API's answer is larger than this server accepts")
                    chunks.append(chunk)
                status, response_headers = res.status_code, res.headers
    except httpx.HTTPError:
        raise ToolError(f"The Verdifax API at {base_url} could not be reached") from None
    text = b"".join(chunks).decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    return RawAnswer(status, response_headers, parsed)


def server_message(body: Any) -> str:
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        return body["error"]
    return ""


def grants_from(headers: httpx.Headers) -> Optional[list[str]]:
    """The tools the server reports this key's owner granted, or None when the
    server reports no list. Names outside the contract are dropped."""
    value = headers.get(IMPL["key_check"]["allowed_tools_header"])
    if value is None:
        return None
    return [s.strip() for s in value.split(",") if s.strip() in TOOL_NAMES]


async def check_member_key(base_url: str, key: str, redactor: Redactor) -> Optional[list[str]]:
    """Checks the member key on GET /stats, which seals nothing: an owner key
    is refused with the server's documented owner-key error, and this server
    then refuses to start."""
    check = IMPL["key_check"]
    try:
        answer = await request(base_url, key, "GET", check["path"], timeout=15)
    except ToolError as err:
        raise StartupError(f"VERDIFAX_API_KEY could not be checked: {redactor.text(str(err))}") from None
    message = server_message(answer.body)
    if answer.status == 200:
        return grants_from(answer.headers)
    if answer.status == 403 and message == check["owner_key_error"]:
        raise StartupError("VERDIFAX_API_KEY is an account owner key. This server never holds owner powers; give it a member key.")
    if answer.status == 403 and message == check["feed_key_error"]:
        raise StartupError("VERDIFAX_API_KEY is a feed key. Set a feed key as VERDIFAX_FEED_KEY and a member key as VERDIFAX_API_KEY.")
    suffix = f": {redactor.text(message)}" if message else ""
    raise StartupError(f"The Verdifax API refused VERDIFAX_API_KEY (HTTP {answer.status}){suffix}")


async def check_feed_key(base_url: str, key: str, redactor: Redactor) -> None:
    """Checks the feed key on the same route: a feed key is answered with the
    server's feed-key error, an owner key with the owner-key error."""
    check = IMPL["key_check"]
    try:
        answer = await request(base_url, key, "GET", check["path"], timeout=15)
    except ToolError as err:
        raise StartupError(f"VERDIFAX_FEED_KEY could not be checked: {redactor.text(str(err))}") from None
    message = server_message(answer.body)
    if answer.status == 403 and message == check["feed_key_error"]:
        return
    if answer.status == 403 and message == check["owner_key_error"]:
        raise StartupError("VERDIFAX_FEED_KEY is an account owner key. This server never holds owner powers; give it a feed key.")
    if answer.status == 200:
        raise StartupError("VERDIFAX_FEED_KEY is not a feed key: the server let it read runs")
    suffix = f": {redactor.text(message)}" if message else ""
    raise StartupError(f"The Verdifax API refused VERDIFAX_FEED_KEY (HTTP {answer.status}){suffix}")
