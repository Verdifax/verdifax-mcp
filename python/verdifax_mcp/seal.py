"""seal_decision: builds the request body the contract defines, signs it on
this machine with signature version 2 when a request key is configured, and
sends that exact text. The signature is made by the Verdifax SDK's
sign_request_v2; the private key never leaves this process.
"""

from typing import Any, Mapping, Optional

from verdifax import sign_request_v2

from .clean import clean_string, has_refused_character
from .contract import IMPL
from .errors import ToolError

_SEAL = IMPL["seal"]


def declared_client(info: Optional[Mapping[str, Any]]) -> dict[str, str]:
    """The client's declared name and version, cleaned to printable ASCII,
    clipped to the byte limit and stripped of leading and trailing spaces, as
    the server accepts them. The label says that nothing checked them."""
    limit = _SEAL["declared_client_max_bytes"]

    def short(value: Any) -> str:
        text = clean_string(value if isinstance(value, str) else "")
        return "".join(c for c in text if " " <= c <= "~")[:limit].strip(" ")

    info = info or {}
    return {"name": short(info.get("name")), "version": short(info.get("version")), "label": _SEAL["declared_client_label"]}


def refuse_hidden_characters(value: Any, field: str) -> None:
    """Refuses a hidden character anywhere in the arguments, naming the field."""
    if isinstance(value, str):
        if has_refused_character(value):
            raise ToolError(f"{field} holds a control or zero-width character; seal plain text only")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            refuse_hidden_characters(item, f"{field}[{i}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            refuse_hidden_characters(key, field)
            refuse_hidden_characters(item, f"{field}.{key}")


def sorted_deep(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: sorted_deep(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [sorted_deep(v) for v in value]
    return value


def seal_body(args: Mapping[str, Any], client: Mapping[str, str]) -> dict[str, Any]:
    """The body the contract defines, with keys sorted."""
    body: dict[str, Any] = {k: args[k] for k in ("payload_text", "program_id", "route_id", "registry_record_hash")}
    for key in ("ai_output_text", "policy_context", "expected_policy_hash"):
        if key in args:
            body[key] = args[key]
    declared = {k: v for k, v in (("client_name", client["name"]), ("client_version", client["version"])) if v}
    if "attested_context" in args or declared:
        body["attested_context"] = {**args.get("attested_context", {}), **declared, "attested": True}
    return sorted_deep(body)


def sign_body(key: bytes, body: Mapping[str, Any], signed_at: Optional[str] = None, nonce: Optional[str] = None) -> dict[str, Any]:
    """The version 2 envelope: the exact text and its signature, from the SDK."""
    return sign_request_v2(key, body, signed_at=signed_at, nonce=nonce)
