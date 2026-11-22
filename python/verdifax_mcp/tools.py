"""The ten tool handlers.

Reads go through the Verdifax SDK with the member key or the feed key; the
verify tools run the local verifier; prepare_signoff makes no request. Each
handler returns the structured answer the contract's output schema
describes; server.py cleans, redacts and checks it.
"""

import json
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Optional

from verdifax import APIError, AsyncVerdifaxClient, VerdifaxError, pending_signoffs

from .api import USER_AGENT, request, server_message
from .config import Config
from .contract import IMPL, NOTICE, output_const
from .errors import ToolError
from .paths import resolve_in_workdir
from .seal import declared_client, refuse_hidden_characters, seal_body, sign_body
from .signoff import prepare_signoff
from .verifier import verify


@dataclass
class Runtime:
    config: Config
    client_info: Callable[[], Optional[Mapping[str, Any]]]


Handler = Callable[[dict[str, Any], Runtime], Awaitable[dict[str, Any]]]


def _member(rt: Runtime) -> AsyncVerdifaxClient:
    if not rt.config.api_key:
        raise ToolError("VERDIFAX_API_KEY is not set, so this tool cannot read Verdifax")
    return AsyncVerdifaxClient(base_url=rt.config.base_url, api_key=rt.config.api_key, user_agent=USER_AGENT)


def _feed(rt: Runtime) -> AsyncVerdifaxClient:
    if not rt.config.feed_key:
        raise ToolError("VERDIFAX_FEED_KEY is not set, so this tool cannot read the signal feed")
    return AsyncVerdifaxClient(base_url=rt.config.base_url, api_key=rt.config.feed_key, user_agent=USER_AGENT)


async def _sdk(call: Callable[[], Awaitable[Any]]) -> Any:
    """Runs an SDK call and turns its errors into plain tool errors."""
    try:
        return await call()
    except APIError as err:
        raise ToolError(f"The Verdifax API answered HTTP {err.status_code}: {err.message}") from None
    except VerdifaxError as err:
        raise ToolError(str(err)) from None


def _plain(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.loads(json.dumps(value))


def _object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolError(f"The Verdifax API did not answer with {what}")
    return value


def _array(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise ToolError(f"The Verdifax API did not answer with {what}")
    return value


async def get_record(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    run_id = int(args["run_id"])
    async with _member(rt) as client:
        text = await _sdk(lambda: client.get_run_artifacts(run_id))
    try:
        record = json.loads(text)
    except ValueError:
        raise ToolError("The Verdifax API's bundle is not JSON") from None
    return {"run_id": run_id, "record": _object(record, "a bundle"), "data_notice": NOTICE}


async def list_records(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    limit = args.get("limit", 20)
    offset = args.get("offset", 0)
    async with _member(rt) as client:
        page = await _sdk(lambda: client.list_runs(limit=limit, offset=offset))
    return {
        "runs": [_plain(r) for r in page.runs],
        "total": page.total if isinstance(page.total, int) else None,
        "limit": limit,
        "offset": offset,
        "data_notice": NOTICE,
    }


async def read_feed(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    after = args.get("after", 0)
    limit = args.get("limit", 100)
    async with _feed(rt) as client:
        page = _plain(await _sdk(lambda: client.get_signals(after=after, limit=limit)))
    head = page.get("head")
    return {
        "after": after,
        "events": _array(page.get("events") or [], "a list of events"),
        "next_after": page.get("next_after") if isinstance(page.get("next_after"), int) else None,
        "head": head if isinstance(head, dict) else None,
        "data_notice": NOTICE,
    }


async def list_pending_signoffs(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    limit = IMPL["feed_reading"]["page_limit"]
    max_pages = IMPL["feed_reading"]["max_pages"]
    events: list[Any] = []
    after = 0
    head = None
    pages = 0
    async with _feed(rt) as client:
        while True:
            if pages == max_pages:
                raise ToolError(f"The feed holds more than {max_pages * limit} events; this tool does not answer from part of a feed")
            page = await _sdk(lambda: client.get_signals(after=after, limit=limit))
            pages += 1
            batch = page.get("events") or []
            events.extend(batch)
            head = page.get("head")
            if len(batch) < limit or head:
                break
            following = page.get("next_after")
            if not isinstance(following, int) or following <= after:
                raise ToolError("The Verdifax API's feed page names no next place")
            after = following
    try:
        run_ids = pending_signoffs(events)
    except VerdifaxError as err:
        raise ToolError(str(err)) from None
    return {
        "run_ids": list(run_ids),
        "events_read": len(events),
        "pages_read": pages,
        "head": _plain(head) if isinstance(head, dict) else None,
        "computed_by": output_const("list_pending_signoffs", "computed_by"),
        "data_notice": NOTICE,
    }


async def get_signoffs(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    run_id = int(args["run_id"])
    async with _member(rt) as client:
        listing = await _sdk(lambda: client.get_signoffs(run_id))
    return {"run_id": run_id, "signoffs": _array(_plain(listing), "a list of sign-offs"), "data_notice": NOTICE}


async def test_policy(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    has_hash = isinstance(args.get("document_hash"), str)
    has_path = isinstance(args.get("document_path"), str)
    if has_hash == has_path:
        raise ToolError("Give exactly one of document_hash and document_path")
    client = _member(rt)
    document = None
    if has_path:
        path = resolve_in_workdir(rt.config.workdir, args["document_path"], "document_path")
        if os.path.getsize(path) > IMPL["limits"]["max_policy_document_bytes"]:
            raise ToolError("document_path is larger than 1 MB")
        with open(path, encoding="utf-8") as handle:
            document = handle.read()
    async with client:
        result = await _sdk(
            lambda: client.test_policy(
                args["inputs"],
                document=document,
                document_hash=None if has_path else args["document_hash"],
                ai_output_declared=args.get("ai_output_declared") is True,
            )
        )
    return {
        "sealed": False,
        "outcome": str(result.get("outcome", "")),
        "fired_rule_id": str(result.get("fired_rule_id", "")),
        "reason_code": str(result.get("reason_code", "")),
        "data_notice": NOTICE,
    }


async def seal_decision(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    if not rt.config.api_key:
        raise ToolError("VERDIFAX_API_KEY is not set, so nothing can be sealed")
    refuse_hidden_characters(args, "arguments")
    client = declared_client(rt.client_info())
    body = seal_body(args, client)
    signed_request = None
    if rt.config.request_key:
        signed = sign_body(rt.config.request_key, body)
        sent = json.dumps(signed, ensure_ascii=False, separators=(",", ":"))
        signed_request = signed["signed_request"]
    else:
        sent = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    answer = await request(rt.config.base_url, rt.config.api_key, "POST", "/execute", sent)
    if answer.status not in (200, 422):
        message = server_message(answer.body)
        raise ToolError(f"The Verdifax API answered HTTP {answer.status}" + (f": {message}" if message else ""))
    result = _object(answer.body, "a run result")
    record_hash = result.get("record_hash") if isinstance(result.get("record_hash"), str) and result.get("record_hash") else None
    run_id = result.get("run_id")
    return {
        "sealed": record_hash is not None,
        "outcome": "completed" if answer.status == 200 else "not_completed",
        "http_status": answer.status,
        "run_id": run_id if isinstance(run_id, int) and not isinstance(run_id, bool) else None,
        "record_hash": record_hash,
        "signed": signed_request is not None,
        "signed_request": signed_request,
        "declared_client": client,
        "answer": result,
        "data_notice": NOTICE,
    }


async def _verify_record(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    return await verify("record", args, rt.config.workdir, rt.config.verifier_path)


async def _verify_feed(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    return await verify("feed", args, rt.config.workdir, rt.config.verifier_path)


async def _prepare_signoff(args: dict[str, Any], rt: Runtime) -> dict[str, Any]:
    return prepare_signoff(args)


HANDLERS: dict[str, Handler] = {
    "verify_record": _verify_record,
    "verify_feed": _verify_feed,
    "get_record": get_record,
    "list_records": list_records,
    "read_feed": read_feed,
    "list_pending_signoffs": list_pending_signoffs,
    "get_signoffs": get_signoffs,
    "test_policy": test_policy,
    "seal_decision": seal_decision,
    "prepare_signoff": _prepare_signoff,
}
