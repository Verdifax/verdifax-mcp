// prepare_signoff: the command a person runs with their own approver key.
// No request is made and nothing is signed here. Every value placed in the
// command has already passed the contract's patterns, so it holds only
// letters, digits and . _ : - characters.

import { contract, outputConst } from "./contract.js";
import { ToolError } from "./errors.js";

const P = contract.implementation.prepare_signoff;

export function signoffTarget(args: Record<string, unknown>): Record<string, unknown> {
  const kind = String(args.kind);
  if (kind === "job" && typeof args.job_id !== "string") throw new ToolError("job_id is required for kind job");
  if (kind !== "job" && args.job_id !== undefined) throw new ToolError("job_id is given only for kind job");
  const target: Record<string, unknown> = { kind, run_id: args.run_id, digest: args.digest };
  if (kind === "job") target.job_id = args.job_id;
  return target;
}

export function signoffCommand(target: Record<string, unknown>, decision: string): string {
  let literal = `{"kind": "${target.kind}", "run_id": ${target.run_id}, "digest": "${target.digest}"`;
  if (target.kind === "job") literal += `, "job_id": "${target.job_id}"`;
  literal += "}";
  return P.command_template.replace("{target}", literal).replace("{decision}", decision);
}

export function prepareSignoff(args: Record<string, unknown>): Record<string, unknown> {
  const target = signoffTarget(args);
  const decision = String(args.decision);
  return {
    command: signoffCommand(target, decision),
    shell: outputConst("prepare_signoff", "shell"),
    target,
    decision,
    steps: [...P.steps],
    what_this_tool_did: outputConst("prepare_signoff", "what_this_tool_did"),
  };
}
