// The two requests this server makes without the SDK: the startup key check,
// which must read a response header, and seal_decision's POST of the exact
// body text it signed. Every other request goes through the Verdifax SDK.

import { contract } from "./contract.js";
import { StartupError, ToolError } from "./errors.js";
import type { Redactor } from "./clean.js";

export const USER_AGENT = `verdifax-mcp/${contract.server.version} (typescript)`;

export interface RawAnswer {
  status: number;
  headers: Headers;
  body: unknown;
}

export type FetchLike = typeof fetch;

async function readCapped(res: Response, max: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      throw new ToolError("The Verdifax API's answer is larger than this server accepts");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function request(
  fetchImpl: FetchLike,
  baseURL: string,
  key: string,
  method: "GET" | "POST",
  path: string,
  body?: string,
  timeoutSeconds = contract.implementation.limits.request_timeout_seconds,
): Promise<RawAnswer> {
  const headers: Record<string, string> = {
    "X-Verdifax-Key": key,
    Accept: "application/json",
    "User-Agent": USER_AGENT,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetchImpl(baseURL + path, {
      method,
      headers,
      body,
      redirect: "error",
      signal: AbortSignal.timeout(timeoutSeconds * 1000),
    });
  } catch {
    throw new ToolError(`The Verdifax API at ${baseURL} could not be reached`);
  }
  const text = await readCapped(res, contract.implementation.limits.max_answer_bytes);
  let parsed: unknown = null;
  if (text !== "") {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }
  return { status: res.status, headers: res.headers, body: parsed };
}

function serverMessage(body: unknown): string {
  if (body && typeof body === "object" && typeof (body as { error?: unknown }).error === "string") {
    return (body as { error: string }).error;
  }
  return "";
}

/** The tools the server reports this key's owner granted, or null when the
 *  server reports no list. Names outside the contract are dropped. */
export function grantsFrom(headers: Headers): string[] | null {
  const value = headers.get(contract.implementation.key_check.allowed_tools_header);
  if (value === null) return null;
  const known = new Set(contract.tools.map((t) => t.name));
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => known.has(s));
}

export interface KeyCheck {
  grants: string[] | null;
}

/** Checks the member key on GET /stats, which seals nothing: an owner key is
 *  refused with the server's documented owner-key error, and this server then
 *  refuses to start. */
export async function checkMemberKey(
  fetchImpl: FetchLike,
  baseURL: string,
  key: string,
  redactor: Redactor,
): Promise<KeyCheck> {
  const check = contract.implementation.key_check;
  let answer: RawAnswer;
  try {
    answer = await request(fetchImpl, baseURL, key, "GET", check.path, undefined, 15);
  } catch (err) {
    throw new StartupError(`VERDIFAX_API_KEY could not be checked: ${redactor.text((err as Error).message)}`);
  }
  const message = serverMessage(answer.body);
  if (answer.status === 200) return { grants: grantsFrom(answer.headers) };
  if (answer.status === 403 && message === check.owner_key_error) {
    throw new StartupError(
      "VERDIFAX_API_KEY is an account owner key. This server never holds owner powers; give it a member key.",
    );
  }
  if (answer.status === 403 && message === check.feed_key_error) {
    throw new StartupError("VERDIFAX_API_KEY is a feed key. Set a feed key as VERDIFAX_FEED_KEY and a member key as VERDIFAX_API_KEY.");
  }
  throw new StartupError(
    `The Verdifax API refused VERDIFAX_API_KEY (HTTP ${answer.status})${message ? ": " + redactor.text(message) : ""}`,
  );
}

/** Checks the feed key on the same route: a feed key is answered with the
 *  server's feed-key error, an owner key with the owner-key error. */
export async function checkFeedKey(
  fetchImpl: FetchLike,
  baseURL: string,
  key: string,
  redactor: Redactor,
): Promise<void> {
  const check = contract.implementation.key_check;
  let answer: RawAnswer;
  try {
    answer = await request(fetchImpl, baseURL, key, "GET", check.path, undefined, 15);
  } catch (err) {
    throw new StartupError(`VERDIFAX_FEED_KEY could not be checked: ${redactor.text((err as Error).message)}`);
  }
  const message = serverMessage(answer.body);
  if (answer.status === 403 && message === check.feed_key_error) return;
  if (answer.status === 403 && message === check.owner_key_error) {
    throw new StartupError(
      "VERDIFAX_FEED_KEY is an account owner key. This server never holds owner powers; give it a feed key.",
    );
  }
  if (answer.status === 200) throw new StartupError("VERDIFAX_FEED_KEY is not a feed key: the server let it read runs");
  throw new StartupError(
    `The Verdifax API refused VERDIFAX_FEED_KEY (HTTP ${answer.status})${message ? ": " + redactor.text(message) : ""}`,
  );
}

export { serverMessage };
