"""Every file a tool reads must stay inside the working folder.

A path is relative, never holds a .. segment, and after symbolic links are
followed it must still be a regular file inside the folder.
"""

import os
import re
from typing import Optional

from .errors import ToolError


def resolve_in_workdir(workdir: Optional[str], relative: str, field: str) -> str:
    if not workdir:
        raise ToolError("VERDIFAX_MCP_WORKDIR is not set, so this server reads no files")
    if "\x00" in relative:
        raise ToolError(f"{field} holds a zero byte")
    if os.path.isabs(relative) or re.match(r"^[A-Za-z]:", relative) or relative.startswith("\\"):
        raise ToolError(f"{field} must be a path relative to the working folder")
    if any(segment == ".." for segment in re.split(r"[\\/]", relative)):
        raise ToolError(f"{field} must not hold a .. segment")
    joined = os.path.join(workdir, relative)
    if not os.path.exists(joined):
        raise ToolError(f"{field} names no file in the working folder")
    real = os.path.realpath(joined)
    prefix = workdir if workdir.endswith(os.sep) else workdir + os.sep
    if real != workdir and not real.startswith(prefix):
        raise ToolError(f"{field} leads outside the working folder")
    if not os.path.isfile(real):
        raise ToolError(f"{field} is not a regular file")
    return real
