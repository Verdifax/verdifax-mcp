// Every file a tool reads must stay inside the working folder. A path is
// relative, never holds a .. segment, and after symbolic links are followed
// it must still be a regular file inside the folder.

import { realpathSync, statSync } from "node:fs";
import { isAbsolute, join, sep } from "node:path";

import { ToolError } from "./errors.js";

export function resolveInWorkdir(workdir: string | undefined, relative: string, field: string): string {
  if (!workdir) throw new ToolError("VERDIFAX_MCP_WORKDIR is not set, so this server reads no files");
  if (relative.includes("\0")) throw new ToolError(`${field} holds a zero byte`);
  if (isAbsolute(relative) || /^[A-Za-z]:/.test(relative) || relative.startsWith("\\")) {
    throw new ToolError(`${field} must be a path relative to the working folder`);
  }
  if (relative.split(/[\\/]/).some((segment) => segment === "..")) {
    throw new ToolError(`${field} must not hold a .. segment`);
  }
  let real: string;
  try {
    real = realpathSync(join(workdir, relative));
  } catch {
    throw new ToolError(`${field} names no file in the working folder`);
  }
  if (real !== workdir && !real.startsWith(workdir.endsWith(sep) ? workdir : workdir + sep)) {
    throw new ToolError(`${field} leads outside the working folder`);
  }
  if (!statSync(real).isFile()) throw new ToolError(`${field} is not a regular file`);
  return real;
}
