"""prepare_signoff: the command a person runs with their own approver key.

No request is made and nothing is signed here. Every value placed in the
command has already passed the contract's patterns, so it holds only
letters, digits and . _ : - characters.
"""

from typing import Any, Mapping

from .contract import IMPL, output_const
from .errors import ToolError

_P = IMPL["prepare_signoff"]


def signoff_target(args: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(args["kind"])
    if kind == "job" and not isinstance(args.get("job_id"), str):
        raise ToolError("job_id is required for kind job")
    if kind != "job" and "job_id" in args:
        raise ToolError("job_id is given only for kind job")
    target: dict[str, Any] = {"kind": kind, "run_id": args["run_id"], "digest": args["digest"]}
    if kind == "job":
        target["job_id"] = args["job_id"]
    return target


def signoff_command(target: Mapping[str, Any], decision: str) -> str:
    literal = '{"kind": "%s", "run_id": %d, "digest": "%s"' % (target["kind"], target["run_id"], target["digest"])
    if target["kind"] == "job":
        literal += ', "job_id": "%s"' % target["job_id"]
    literal += "}"
    return _P["command_template"].replace("{target}", literal, 1).replace("{decision}", decision, 1)


def prepare_signoff(args: Mapping[str, Any]) -> dict[str, Any]:
    target = signoff_target(args)
    decision = str(args["decision"])
    return {
        "command": signoff_command(target, decision),
        "shell": output_const("prepare_signoff", "shell"),
        "target": target,
        "decision": decision,
        "steps": list(_P["steps"]),
        "what_this_tool_did": output_const("prepare_signoff", "what_this_tool_did"),
    }
