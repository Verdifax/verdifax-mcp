// The ten tool handlers. Reads go through the Verdifax SDK with the member
// key or the feed key; the verify tools run the local verifier; prepare_signoff
// makes no request. Each handler returns the structured answer the contract's
// output schema describes; server.ts cleans, redacts and checks it.

import { readFileSync, statSync } from "node:fs";

import { APIError, AuthError, NotFoundError, VerdifaxClient, VerdifaxError, pendingSignOffs } from "verdifax";

import { request, serverMessage, USER_AGENT, type FetchLike } from "./api.js";
import type { Config } from "./config.js";
import { contract } from "./contract.js";
import { ToolError } from "./errors.js";
import { resolveInWorkdir } from "./paths.js";
import { declaredClient, refuseHiddenCharacters, sealBody, signBody, signingKey } from "./seal.js";
import { prepareSignoff } from "./signoff.js";
import { verify } from "./verifier.js";
import { outputConst } from "./contract.js";

const NOTICE = contract.implementation.data_notice;

export interface ClientInfo {
  name?: unknown;
  version?: unknown;
}

export interface Runtime {
  config: Config;
  fetch: FetchLike;
  clientInfo: () => ClientInfo | undefined;
}

export type Handler = (args: Record<string, unknown>, rt: Runtime) => Promise<Record<string, unknown>>;

function memberClient(rt: Runtime): VerdifaxClient {
  if (!rt.config.apiKey) throw new ToolError("VERDIFAX_API_KEY is not set, so this tool cannot read Verdifax");
  return new VerdifaxClient({ baseURL: rt.config.baseURL, apiKey: rt.config.apiKey, userAgent: USER_AGENT });
}

function feedClient(rt: Runtime): VerdifaxClient {
  if (!rt.config.feedKey) throw new ToolError("VERDIFAX_FEED_KEY is not set, so this tool cannot read the signal feed");
  return new VerdifaxClient({ baseURL: rt.config.baseURL, apiKey: rt.config.feedKey, userAgent: USER_AGENT });
}

/** Runs an SDK call and turns its errors into plain tool errors. */
async function sdk<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (err) {
    if (err instanceof APIError || err instanceof AuthError) {
      throw new ToolError(`The Verdifax API answered HTTP ${err.status}: ${err.message}`);
    }
    if (err instanceof NotFoundError) throw new ToolError(`The Verdifax API answered HTTP 404: ${err.message}`);
    if (err instanceof VerdifaxError) throw new ToolError(err.message);
    throw err;
  }
}

function plain(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value ?? null));
}

function asObject(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ToolError(`The Verdifax API did not answer with ${what}`);
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new ToolError(`The Verdifax API did not answer with ${what}`);
  return value;
}

async function getRecord(args: Record<string, unknown>, rt: Runtime) {
  const runId = Number(args.run_id);
  const text = await sdk(() => memberClient(rt).getRunArtifacts(runId));
  let record: unknown;
  try {
    record = JSON.parse(text);
  } catch {
    throw new ToolError("The Verdifax API's bundle is not JSON");
  }
  return { run_id: runId, record: asObject(record, "a bundle"), data_notice: NOTICE };
}

async function listRecords(args: Record<string, unknown>, rt: Runtime) {
  const limit = typeof args.limit === "number" ? args.limit : 20;
  const offset = typeof args.offset === "number" ? args.offset : 0;
  const page = await sdk(() => memberClient(rt).listRuns({ limit, offset }));
  const total = (page as { total?: unknown }).total;
  return {
    runs: asArray(plain(page.runs), "a list of runs"),
    total: typeof total === "number" ? total : null,
    limit,
    offset,
    data_notice: NOTICE,
  };
}

async function readFeed(args: Record<string, unknown>, rt: Runtime) {
  const after = typeof args.after === "number" ? args.after : 0;
  const limit = typeof args.limit === "number" ? args.limit : 100;
  const page = plain(await sdk(() => feedClient(rt).getSignals({ after, limit }))) as Record<string, unknown>;
  return {
    after,
    events: asArray(page.events ?? [], "a list of events"),
    next_after: typeof page.next_after === "number" ? page.next_after : null,
    head: page.head && typeof page.head === "object" ? page.head : null,
    data_notice: NOTICE,
  };
}

async function listPendingSignoffs(_args: Record<string, unknown>, rt: Runtime) {
  const client = feedClient(rt);
  const { page_limit: limit, max_pages: maxPages } = contract.implementation.feed_reading;
  const events: unknown[] = [];
  let after = 0;
  let head: unknown = null;
  let pages = 0;
  for (;;) {
    if (pages === maxPages) {
      throw new ToolError(
        `The feed holds more than ${maxPages * limit} events; this tool does not answer from part of a feed`,
      );
    }
    const page = await sdk(() => client.getSignals({ after, limit }));
    pages += 1;
    const batch = (page.events ?? []) as unknown[];
    events.push(...batch);
    head = page.head ?? null;
    if (batch.length < limit || head) break;
    const next = (page as { next_after?: unknown }).next_after;
    if (typeof next !== "number" || next <= after) throw new ToolError("The Verdifax API's feed page names no next place");
    after = next;
  }
  const runIds = await sdk(async () => pendingSignOffs(events as Parameters<typeof pendingSignOffs>[0]));
  return {
    run_ids: runIds,
    events_read: events.length,
    pages_read: pages,
    head: head ? plain(head) : null,
    computed_by: outputConst("list_pending_signoffs", "computed_by"),
    data_notice: NOTICE,
  };
}

async function getSignoffs(args: Record<string, unknown>, rt: Runtime) {
  const runId = Number(args.run_id);
  const list = await sdk(() => memberClient(rt).getSignOffs(runId));
  return { run_id: runId, signoffs: asArray(plain(list), "a list of sign-offs"), data_notice: NOTICE };
}

async function testPolicy(args: Record<string, unknown>, rt: Runtime) {
  const hasHash = typeof args.document_hash === "string";
  const hasPath = typeof args.document_path === "string";
  if (hasHash === hasPath) throw new ToolError("Give exactly one of document_hash and document_path");
  const client = memberClient(rt);
  let document: string | undefined;
  if (hasPath) {
    const path = resolveInWorkdir(rt.config.workdir, String(args.document_path), "document_path");
    if (statSync(path).size > contract.implementation.limits.max_policy_document_bytes) {
      throw new ToolError("document_path is larger than 1 MB");
    }
    document = readFileSync(path, "utf8");
  }
  const result = await sdk(() =>
    client.testPolicy({
      inputs: args.inputs as Record<string, unknown>,
      ...(document !== undefined ? { document } : { documentHash: String(args.document_hash) }),
      ...(args.ai_output_declared === true ? { aiOutputDeclared: true } : {}),
    }),
  );
  return {
    sealed: false,
    outcome: String(result.outcome ?? ""),
    fired_rule_id: String(result.fired_rule_id ?? ""),
    reason_code: String(result.reason_code ?? ""),
    data_notice: NOTICE,
  };
}

async function sealDecision(args: Record<string, unknown>, rt: Runtime) {
  if (!rt.config.apiKey) throw new ToolError("VERDIFAX_API_KEY is not set, so nothing can be sealed");
  refuseHiddenCharacters(args, "arguments");
  const client = declaredClient(rt.clientInfo());
  const body = sealBody(args, client);
  const text = JSON.stringify(body);
  let sent = text;
  let signedRequest: string | null = null;
  if (rt.config.requestKey) {
    const signed = signBody(signingKey(rt.config.requestKey), text, body);
    sent = JSON.stringify(signed);
    signedRequest = signed.signed_request;
  }
  const answer = await request(rt.fetch, rt.config.baseURL, rt.config.apiKey, "POST", "/execute", sent);
  if (answer.status !== 200 && answer.status !== 422) {
    const message = serverMessage(answer.body);
    throw new ToolError(`The Verdifax API answered HTTP ${answer.status}${message ? ": " + message : ""}`);
  }
  const body2 = asObject(answer.body, "a run result");
  const recordHash = typeof body2.record_hash === "string" && body2.record_hash !== "" ? body2.record_hash : null;
  return {
    sealed: recordHash !== null,
    outcome: answer.status === 200 ? "completed" : "not_completed",
    http_status: answer.status,
    run_id: typeof body2.run_id === "number" ? body2.run_id : null,
    record_hash: recordHash,
    signed: signedRequest !== null,
    signed_request: signedRequest,
    declared_client: client,
    answer: body2,
    data_notice: NOTICE,
  };
}

export const handlers: Record<string, Handler> = {
  verify_record: (args, rt) => verify("record", args, rt.config.workdir, rt.config.verifierPath),
  verify_feed: (args, rt) => verify("feed", args, rt.config.workdir, rt.config.verifierPath),
  get_record: getRecord,
  list_records: listRecords,
  read_feed: readFeed,
  list_pending_signoffs: listPendingSignoffs,
  get_signoffs: getSignoffs,
  test_policy: testPolicy,
  seal_decision: sealDecision,
  prepare_signoff: async (args) => prepareSignoff(args),
};
