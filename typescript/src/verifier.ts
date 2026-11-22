// Runs the verdifax-verify program installed on this machine, never a shell
// and never the API. The child gets this server's environment without any
// VERDIFAX_ variable, so no key reaches it.

import { spawn } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";

import { contract, outputConst, type ArgumentRule } from "./contract.js";
import { ToolError } from "./errors.js";
import { resolveInWorkdir } from "./paths.js";

const V = contract.implementation.verifier;
const PROGRAM = "verdifax-verify";

export interface VerifierRun {
  exitCode: number;
  stdout: string;
  stderr: string;
}

function executable(path: string): boolean {
  try {
    if (!statSync(path).isFile()) return false;
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function findVerifier(configured: string | undefined, env: NodeJS.ProcessEnv = process.env): string {
  if (configured) {
    if (!executable(configured)) throw new ToolError("VERDIFAX_VERIFY_PATH does not name a program this server can run");
    return configured;
  }
  for (const dir of (env.PATH ?? "").split(delimiter)) {
    if (!dir || !isAbsolute(dir)) continue;
    const candidate = join(dir, PROGRAM);
    if (executable(candidate)) return candidate;
  }
  throw new ToolError(
    "verdifax-verify was not found on PATH. Install it from https://github.com/Verdifax/verdifax-verify/releases, or set VERDIFAX_VERIFY_PATH.",
  );
}

export function childEnvironment(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) {
    if (!k.toUpperCase().startsWith(V.environment_removed_prefix)) out[k] = v;
  }
  return out;
}

export function runProgram(path: string, args: string[]): Promise<VerifierRun> {
  return new Promise((resolve, reject) => {
    const child = spawn(path, args, { shell: false, env: childEnvironment(), stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let size = 0;
    let failure: ToolError | undefined;
    const timer = setTimeout(() => {
      failure = new ToolError(`verdifax-verify did not finish within ${V.timeout_seconds} seconds`);
      child.kill("SIGKILL");
    }, V.timeout_seconds * 1000);
    const collect = (into: Buffer[]) => (chunk: Buffer) => {
      size += chunk.length;
      if (size > V.max_output_bytes) {
        failure = new ToolError("verdifax-verify printed more than this server accepts");
        child.kill("SIGKILL");
        return;
      }
      into.push(chunk);
    };
    child.stdout.on("data", collect(out));
    child.stderr.on("data", collect(err));
    child.on("error", () => {
      clearTimeout(timer);
      reject(new ToolError("verdifax-verify could not be started"));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (failure) return reject(failure);
      resolve({
        exitCode: code ?? -1,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
  });
}

const versions = new Map<string, string>();

export async function verifierVersion(path: string): Promise<string> {
  const known = versions.get(path);
  if (known !== undefined) return known;
  const run = await runProgram(path, ["--version"]);
  const version = run.exitCode === 0 ? run.stdout.trim() : "unknown";
  versions.set(path, version);
  return version;
}

/** The arguments for the verifier, in the contract's order. */
export function verifierArguments(
  rules: ArgumentRule[],
  args: Record<string, unknown>,
  workdir: string | undefined,
): string[] {
  const out: string[] = [];
  for (const [field, flag, kind] of rules) {
    const value = args[field];
    if (value === undefined || value === null) continue;
    if (kind === "flag") {
      if (value === true) out.push(flag);
    } else if (kind === "value") {
      out.push(flag, String(value));
    } else if (kind === "path") {
      out.push(flag, resolveInWorkdir(workdir, String(value), field));
    } else {
      const paths = (value as string[]).map((p, i) => {
        const real = resolveInWorkdir(workdir, p, `${field}[${i}]`);
        if (real.includes(",")) throw new ToolError(`${field}[${i}] holds a comma, which the verifier reads as a separator`);
        return real;
      });
      out.push(flag, paths.join(","));
    }
  }
  return out;
}

export function outcomeOf(mode: "record" | "feed", exitCode: number): [string, string] {
  const table = mode === "record" ? V.record_exit_codes : V.feed_exit_codes;
  return table[String(exitCode)] ?? V.unknown_exit_code;
}

export async function verify(
  mode: "record" | "feed",
  args: Record<string, unknown>,
  workdir: string | undefined,
  verifierPath: string | undefined,
): Promise<Record<string, unknown>> {
  const target = resolveInWorkdir(workdir, String(args.path), "path");
  const argv =
    mode === "record"
      ? ["--json", ...verifierArguments(V.record_arguments, args, workdir), target]
      : ["--json", "--signals", target, ...verifierArguments(V.feed_arguments, args, workdir)];
  const program = findVerifier(verifierPath);
  const version = await verifierVersion(program);
  const run = await runProgram(program, argv);
  let report: unknown = null;
  try {
    const parsed: unknown = JSON.parse(run.stdout);
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) report = parsed;
  } catch {
    report = null;
  }
  const [outcome, meaning] = outcomeOf(mode, run.exitCode);
  return {
    checked_by: outputConst("verify_record", "checked_by"),
    verifier: { path: program, version },
    arguments: argv,
    exit_code: run.exitCode,
    outcome,
    outcome_meaning: meaning,
    report,
    stderr: [...run.stderr].slice(0, V.stderr_max_chars).join(""),
    data_notice: contract.implementation.data_notice,
  };
}
