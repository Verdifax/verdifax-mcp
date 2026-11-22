// Test helpers: a local stand-in for the Verdifax API, a working folder, the
// stand-in verifier, and an MCP client joined to the server in memory. No
// test reaches api.verdifax.com or any paid service.

import { copyFileSync, chmodSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, realpathSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createServer as createMcpServer } from "../dist/server.js";

const here = dirname(fileURLToPath(import.meta.url));
export const REPO = join(here, "..", "..");
export const TESTDATA = join(REPO, "testdata");

export const OWNER_ERROR =
  "an account owner key manages the account and cannot run or read runs itself; use a member key, or the /account routes";
export const FEED_ERROR = "a feed key reads the account's signal feed at GET /signals and nothing else";

export const MEMBER_KEY = "vfx_" + "1a".repeat(24);
export const FEED_KEY = "vfx_" + "2b".repeat(24);
export const OWNER_KEY = "vfx_" + "3c".repeat(24);

export function readJSON(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/** A stand-in API. handler(req) returns { status, body, headers }. Every
 *  request is recorded with its method, path, key and body text. */
export async function fakeAPI(handler) {
  const requests = [];
  const server = createServer((req, res) => {
    let text = "";
    req.on("data", (c) => (text += c));
    req.on("end", async () => {
      const url = new URL(req.url, "http://x");
      const entry = { method: req.method, path: url.pathname, query: url.searchParams, key: req.headers["x-verdifax-key"], body: text };
      requests.push(entry);
      const out = (await handler(entry)) ?? { status: 404, body: { ok: false, error: "not found" } };
      res.writeHead(out.status, { "Content-Type": "application/json", ...(out.headers ?? {}) });
      res.end(typeof out.body === "string" ? out.body : JSON.stringify(out.body));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { baseURL: `http://127.0.0.1:${port}`, requests, close: () => new Promise((r) => server.close(r)) };
}

/** The usual key check answers: a member key reads /stats, a feed key gets
 *  the feed-key error and an owner key the owner-key error. */
export function keyCheck(entry, headers = {}) {
  if (entry.method === "GET" && entry.path === "/stats") {
    if (entry.key === OWNER_KEY) return { status: 403, body: { ok: false, error: OWNER_ERROR } };
    if (entry.key === FEED_KEY) return { status: 403, body: { ok: false, error: FEED_ERROR } };
    return { status: 200, body: { ok: true, total_runs: 0 }, headers };
  }
  return undefined;
}

export function workdir() {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "verdifax-mcp-test-")));
  mkdirSync(join(dir, "records"));
  writeFileSync(join(dir, "records", "bundle.json"), "{}");
  writeFileSync(join(dir, "feed.json"), "{}");
  writeFileSync(join(dir, "policy.json"), '{"policy_id":"p"}');
  return dir;
}

export function fakeVerifier() {
  const dir = mkdtempSync(join(tmpdir(), "verdifax-mcp-verifier-"));
  const path = join(dir, "verdifax-verify");
  copyFileSync(join(TESTDATA, "fake-verdifax-verify"), path);
  chmodSync(path, 0o755);
  return { path, argsFile: join(dir, "args.txt") };
}

export async function connect(options, clientInfo = { name: "test-client", version: "9.9.9" }) {
  const server = createMcpServer(options);
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client(clientInfo);
  await client.connect(clientSide);
  return { client, server };
}

export function config(overrides = {}) {
  return { baseURL: "http://127.0.0.1:9", ...overrides };
}

export function parseResult(result) {
  return JSON.parse(result.content[0].text);
}
