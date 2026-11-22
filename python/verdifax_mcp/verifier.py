"""Runs the verdifax-verify program installed on this machine, never a shell
and never the API. The child gets this server's environment without any
VERDIFAX_ variable, so no key reaches it.
"""

import asyncio
import json
import os
from typing import Any, Mapping, Optional

from .contract import IMPL, NOTICE, output_const
from .errors import ToolError
from .paths import resolve_in_workdir

_V = IMPL["verifier"]
_PROGRAM = "verdifax-verify"


def _executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def find_verifier(configured: Optional[str]) -> str:
    if configured:
        if not _executable(configured):
            raise ToolError("VERDIFAX_VERIFY_PATH does not name a program this server can run")
        return configured
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if folder and os.path.isabs(folder):
            candidate = os.path.join(folder, _PROGRAM)
            if _executable(candidate):
                return candidate
    raise ToolError(
        "verdifax-verify was not found on PATH. Install it from "
        "https://github.com/Verdifax/verdifax-verify/releases, or set VERDIFAX_VERIFY_PATH."
    )


def child_environment(env: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    env = os.environ if env is None else env
    prefix = _V["environment_removed_prefix"]
    return {k: v for k, v in env.items() if not k.upper().startswith(prefix)}


async def run_program(path: str, args: list[str]) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            path,
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_environment(),
        )
    except OSError:
        raise ToolError("verdifax-verify could not be started") from None
    limit = _V["max_output_bytes"]
    size = 0
    too_big = False

    async def collect(stream: asyncio.StreamReader, into: list[bytes]) -> None:
        nonlocal size, too_big
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return
            size += len(chunk)
            if size > limit:
                too_big = True
                proc.kill()
                return
            into.append(chunk)

    out: list[bytes] = []
    err: list[bytes] = []
    try:
        await asyncio.wait_for(
            asyncio.gather(collect(proc.stdout, out), collect(proc.stderr, err), proc.wait()),
            timeout=_V["timeout_seconds"],
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise ToolError(f"verdifax-verify did not finish within {_V['timeout_seconds']} seconds") from None
    if too_big:
        raise ToolError("verdifax-verify printed more than this server accepts")
    return proc.returncode, b"".join(out).decode("utf-8", errors="replace"), b"".join(err).decode("utf-8", errors="replace")


_versions: dict[str, str] = {}


async def verifier_version(path: str) -> str:
    if path not in _versions:
        code, out, _ = await run_program(path, ["--version"])
        _versions[path] = out.strip() if code == 0 else "unknown"
    return _versions[path]


def verifier_arguments(rules: list, args: Mapping[str, Any], workdir: Optional[str]) -> list[str]:
    """The arguments for the verifier, in the contract's order."""
    out: list[str] = []
    for field, flag, kind in rules:
        value = args.get(field)
        if value is None:
            continue
        if kind == "flag":
            if value is True:
                out.append(flag)
        elif kind == "value":
            out += [flag, str(value)]
        elif kind == "path":
            out += [flag, resolve_in_workdir(workdir, str(value), field)]
        else:
            paths = []
            for i, item in enumerate(value):
                real = resolve_in_workdir(workdir, str(item), f"{field}[{i}]")
                if "," in real:
                    raise ToolError(f"{field}[{i}] holds a comma, which the verifier reads as a separator")
                paths.append(real)
            out += [flag, ",".join(paths)]
    return out


def outcome_of(mode: str, exit_code: int) -> list[str]:
    table = _V["record_exit_codes"] if mode == "record" else _V["feed_exit_codes"]
    return table.get(str(exit_code), _V["unknown_exit_code"])


async def verify(mode: str, args: Mapping[str, Any], workdir: Optional[str], verifier_path: Optional[str]) -> dict[str, Any]:
    target = resolve_in_workdir(workdir, str(args["path"]), "path")
    if mode == "record":
        argv = ["--json", *verifier_arguments(_V["record_arguments"], args, workdir), target]
    else:
        argv = ["--json", "--signals", target, *verifier_arguments(_V["feed_arguments"], args, workdir)]
    program = find_verifier(verifier_path)
    version = await verifier_version(program)
    code, stdout, stderr = await run_program(program, argv)
    report = None
    try:
        parsed = json.loads(stdout)
        if isinstance(parsed, dict):
            report = parsed
    except ValueError:
        report = None
    outcome, meaning = outcome_of(mode, code)
    return {
        "checked_by": output_const("verify_record", "checked_by"),
        "verifier": {"path": program, "version": version},
        "arguments": argv,
        "exit_code": code,
        "outcome": outcome,
        "outcome_meaning": meaning,
        "report": report,
        "stderr": stderr[: _V["stderr_max_chars"]],
        "data_notice": NOTICE,
    }

