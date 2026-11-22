// Each tool against the stand-in API and the stand-in verifier.

import assert from "node:assert/strict";
import { createPublicKey, createPrivateKey, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { requestSignaturePreimageV2 } from "verdifax";

import { contract } from "../dist/contract.js";
import { StartupError } from "../dist/errors.js";
import { startHttp } from "../dist/http.js";
import { createServer } from "../dist/server.js";
import { sha256Hex } from "../dist/seal.js";
import {
  connect, config, fakeAPI, fakeVerifier, keyCheck, parseResult, readJSON, workdir,
  FEED_KEY, MEMBER_KEY, TESTDATA,
} from "./helpers.mjs";

const SEAL_ARGS = { program_id: "a".repeat(64), route_id: "claims/review", registry_record_hash: "b".repeat(64), payload_text: "Approve claim 7." };

async function withVerifier(fn) {
  const dir = workdir();
  writeFileSync(join(dir, "approver.txt"), "AAAA");
  writeFileSync(join(dir, "owner-1.txt"), "AAAA");
  writeFileSync(join(dir, "owner-2.txt"), "AAAA");
  const verifier = fakeVerifier();
  process.env.FAKE_VERIFY_ARGS_FILE = verifier.argsFile;
  try {
    const { client } = await connect({ config: config({ workdir: dir, verifierPath: verifier.path }), grants: { apiKey: null } });
    await fn(client, dir, () => readFileSync(verifier.argsFile, "utf8").trim().split("\n"), verifier);
  } finally {
    delete process.env.FAKE_VERIFY_ARGS_FILE;
    delete process.env.FAKE_VERIFY_EXIT;
  }
}

test("verify_record maps every exit code to its outcome and never calls an exit code other than 0 verified", async () => {
  await withVerifier(async (client) => {
    const expected = { 0: "verified", 1: "failed", 2: "unreadable_input", 3: "partial_coverage", 4: "signoff_not_shown", 9: "unknown_exit_code" };
    for (const [code, outcome] of Object.entries(expected)) {
      process.env.FAKE_VERIFY_EXIT = code;
      const res = await client.callTool({ name: "verify_record", arguments: { path: "records/bundle.json" } });
      assert.ok(!res.isError, JSON.stringify(res));
      assert.equal(res.structuredContent.exit_code, Number(code));
      assert.equal(res.structuredContent.outcome, outcome);
      assert.equal(res.structuredContent.outcome_meaning, (contract.implementation.verifier.record_exit_codes[code] ?? contract.implementation.verifier.unknown_exit_code)[1]);
      assert.equal(res.structuredContent.verifier.version, "verdifax-verify v0.38.0 (test stand-in)");
    }
  });
});

test("verify_record passes the contract's flags in the contract's order, with absolute paths", async () => {
  await withVerifier(async (client, dir, args) => {
    const res = await client.callTool({
      name: "verify_record",
      arguments: {
        path: "records/bundle.json", strict_signoff: true, signoff_path: "feed.json", policy_path: "policy.json",
        approver_public_key_path: "approver.txt", allow_partial: false, signoff_head_max_age: "72h",
      },
    });
    assert.ok(!res.isError, JSON.stringify(res));
    const want = [
      "--json", "--policy", join(dir, "policy.json"), "--signoff", join(dir, "feed.json"),
      "--approver-key", join(dir, "approver.txt"), "--strict-signoff", "--signoff-head-max-age", "72h",
      join(dir, "records", "bundle.json"),
    ];
    assert.deepEqual(args(), want);
    assert.deepEqual(res.structuredContent.arguments, want);
  });
});

test("verify_feed runs --signals with its flags", async () => {
  await withVerifier(async (client, dir, args) => {
    process.env.FAKE_VERIFY_EXIT = "3";
    const after = "12:" + "c".repeat(64);
    const res = await client.callTool({
      name: "verify_feed",
      arguments: { path: "feed.json", signals_after: after, owner_request_key_paths: ["owner-1.txt", "owner-2.txt"], feed_head_max_age: "48h" },
    });
    assert.ok(!res.isError, JSON.stringify(res));
    assert.equal(res.structuredContent.outcome, "partial_coverage");
    assert.equal(res.structuredContent.outcome_meaning, contract.implementation.verifier.feed_exit_codes["3"][1]);
    assert.deepEqual(args(), [
      "--json", "--signals", join(dir, "feed.json"), "--signals-after", after,
      "--owner-request-key", `${join(dir, "owner-1.txt")},${join(dir, "owner-2.txt")}`, "--feed-head-max-age", "48h",
    ]);
  });
});

test("arguments outside the input schema are refused", async () => {
  await withVerifier(async (client) => {
    for (const args of [{}, { path: "records/bundle.json", url: "https://example.com" }, { path: "records/bundle.json", signoff_head_max_age: "1d" }]) {
      const res = await client.callTool({ name: "verify_record", arguments: args });
      assert.equal(res.isError, true, JSON.stringify(args));
    }
  });
});

test("the verifier missing is a plain refusal", async () => {
  const { client } = await connect({ config: config({ workdir: workdir(), verifierPath: "/nonexistent/verdifax-verify" }), grants: { apiKey: null } });
  const res = await client.callTool({ name: "verify_record", arguments: { path: "records/bundle.json" } });
  assert.equal(res.isError, true);
  assert.match(parseResult(res).error, /VERDIFAX_VERIFY_PATH/);
});

test("the read tools return the API's answers through the SDK", async () => {
  const sealed = (i) => ({ specversion: "1.0", id: String(i), data: { kind: "run.sealed", sequence: i, entry: { run_id: i, signoff_required: i === 11 || i === 12 } } });
  const firstPage = Array.from({ length: 500 }, (_, i) => sealed(i + 1));
  const later = [
    { specversion: "1.0", id: "501", data: { kind: "signoff.recorded", sequence: 501, entry: { target: { kind: "record", run_id: 11 }, decision: "approve" } } },
  ];
  const api = await fakeAPI((e) => {
    if (e.path === "/runs/5/artifacts") return { status: 200, body: { bundle_anchor: { anchored_digest: "d".repeat(64) } } };
    if (e.path === "/runs") return { status: 200, body: { ok: true, runs: [{ id: 5, status: "completed" }], total: 1 } };
    if (e.path === "/runs/5/signoffs") return { status: 200, body: [{ decision: "approve", signoff_hash: "e".repeat(64) }] };
    if (e.path === "/signals") {
      assert.equal(e.key, FEED_KEY);
      const after = Number(e.query.get("after") ?? "0");
      const limit = Number(e.query.get("limit") ?? "100");
      if (limit === 500 && after === 0) return { status: 200, body: { events: firstPage, next_after: 500, newest: 501 } };
      if (after === 500 && limit === 500) return { status: 200, body: { events: later, next_after: 501, newest: 501, head: { format: "verdifax.feed-head.v1", account: "account-7", sequence: 501, head_hash: "a".repeat(64), head_statement_hash: "b".repeat(64), stated_at: "2026-11-17T12:00:00Z" } } };
      return { status: 200, body: { events: firstPage.slice(after, after + limit), next_after: after + limit, newest: 501 } };
    }
    if (e.path === "/policies/test") {
      const body = JSON.parse(e.body);
      assert.deepEqual(Object.keys(body).sort(), body.document ? ["document", "inputs"] : ["document_hash", "inputs"]);
      return { status: 200, body: { ok: true, sealed: false, outcome: "deny", fired_rule_id: "r1", reason_code: "TEST" } };
    }
    return keyCheck(e);
  });
  try {
    const dir = workdir();
    const { client } = await connect({
      config: config({ baseURL: api.baseURL, apiKey: MEMBER_KEY, feedKey: FEED_KEY, workdir: dir }),
      grants: { apiKey: null },
    });
    const call = async (name, args = {}) => {
      const res = await client.callTool({ name, arguments: args });
      assert.ok(!res.isError, `${name}: ${JSON.stringify(res)}`);
      return res.structuredContent;
    };
    assert.equal((await call("get_record", { run_id: 5 })).record.bundle_anchor.anchored_digest, "d".repeat(64));
    const listed = await call("list_records", { limit: 5 });
    assert.equal(listed.total, 1);
    assert.equal(listed.limit, 5);
    assert.equal(api.requests.find((r) => r.path === "/runs").query.get("limit"), "5");
    assert.equal((await call("get_signoffs", { run_id: 5 })).signoffs[0].decision, "approve");
    const feed = await call("read_feed", { limit: 1 });
    assert.equal(feed.events.length, 1);
    assert.equal(feed.next_after, 1);
    const pending = await call("list_pending_signoffs");
    assert.deepEqual(pending.run_ids, [12]);
    assert.equal(pending.events_read, 501);
    assert.equal(pending.pages_read, 2);
    assert.equal(pending.head.sequence, 501);
    const tested = await call("test_policy", { inputs: { actor_type: "agent" }, document_path: "policy.json" });
    assert.deepEqual([tested.sealed, tested.outcome, tested.fired_rule_id], [false, "deny", "r1"]);
    await call("test_policy", { inputs: {}, document_hash: "f".repeat(64) });
    const both = await client.callTool({ name: "test_policy", arguments: { inputs: {}, document_hash: "f".repeat(64), document_path: "policy.json" } });
    assert.equal(both.isError, true);
    const sealedNothing = api.requests.filter((r) => r.method === "POST" && r.path === "/execute");
    assert.equal(sealedNothing.length, 0, "no read tool seals anything");
  } finally {
    await api.close();
  }
});

test("an API refusal comes back as a plain tool error", async () => {
  const api = await fakeAPI((e) => (e.path === "/runs/8/artifacts" ? { status: 404, body: { ok: false, error: "run not found" } } : keyCheck(e)));
  try {
    const { client } = await connect({ config: config({ baseURL: api.baseURL, apiKey: MEMBER_KEY }), grants: { apiKey: null } });
    const res = await client.callTool({ name: "get_record", arguments: { run_id: 8 } });
    assert.equal(res.isError, true);
    assert.match(parseResult(res).error, /404/);
    const noFeed = await client.callTool({ name: "read_feed", arguments: {} });
    assert.match(parseResult(noFeed).error, /VERDIFAX_FEED_KEY is not set/);
  } finally {
    await api.close();
  }
});

test("seal_decision signs on this machine and seals the declared client, labelled declared, not verified", async () => {
  const vector = readJSON(join(TESTDATA, "seal-vector.json"));
  const key = Buffer.from(vector.request_key_hex, "hex");
  const api = await fakeAPI((e) => {
    if (e.path === "/execute") return { status: 200, body: { ok: true, run_id: 42, record_hash: "9".repeat(64) } };
    return keyCheck(e);
  });
  try {
    const { client } = await connect(
      { config: config({ baseURL: api.baseURL, apiKey: MEMBER_KEY, requestKey: key }), grants: { apiKey: null } },
      { name: "Claude Code", version: "2.9.0" },
    );
    const res = await client.callTool({ name: "seal_decision", arguments: { ...SEAL_ARGS, policy_context: { data_use: { purpose: "claims-review", categories: ["health"] } } } });
    assert.ok(!res.isError, JSON.stringify(res));
    const out = res.structuredContent;
    assert.deepEqual([out.sealed, out.outcome, out.run_id, out.signed], [true, "completed", 42, true]);
    assert.deepEqual(out.declared_client, { name: "Claude Code", version: "2.9.0", label: "declared, not verified" });
    const sent = JSON.parse(api.requests.find((r) => r.path === "/execute").body);
    assert.deepEqual(Object.keys(sent).sort(), ["request_signature", "signed_request"]);
    assert.equal(sent.signed_request, out.signed_request);
    const inner = JSON.parse(sent.signed_request);
    assert.deepEqual([inner.attested_context.client_name, inner.attested_context.client_version, inner.attested_context.attested], ["Claude Code", "2.9.0", true]);
    assert.equal(inner.reproducibility_context, undefined);
    assert.deepEqual(inner.policy_context.data_use, { purpose: "claims-review", categories: ["health"] });
    const publicKey = createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), key]), format: "der", type: "pkcs8" }));
    const preimage = requestSignaturePreimageV2({
      body_hash: sha256Hex(sent.signed_request), payload_hash: sha256Hex(SEAL_ARGS.payload_text), program_id: SEAL_ARGS.program_id,
      route_id: SEAL_ARGS.route_id, registry_record_hash: SEAL_ARGS.registry_record_hash, ai_output_hash: "",
      signed_at: sent.request_signature.signed_at, nonce: sent.request_signature.nonce,
    });
    assert.ok(verify(null, preimage, publicKey, Buffer.from(sent.request_signature.signature, "base64")));
  } finally {
    await api.close();
  }
});

test("seal_decision without a request key sends the body unsigned; a refusal is a sealed receipt; other errors are errors", async () => {
  let status = 422;
  const api = await fakeAPI((e) => {
    if (e.path === "/execute") {
      if (status === 422) return { status, body: { ok: false, error: "policy refused", run_id: 43, record_hash: "8".repeat(64) } };
      return { status, body: { ok: false, error: "unknown field attested_context.client_name" } };
    }
    return keyCheck(e);
  });
  try {
    const { client } = await connect({ config: config({ baseURL: api.baseURL, apiKey: MEMBER_KEY }), grants: { apiKey: null } });
    const res = await client.callTool({ name: "seal_decision", arguments: SEAL_ARGS });
    assert.ok(!res.isError, JSON.stringify(res));
    assert.deepEqual([res.structuredContent.outcome, res.structuredContent.sealed, res.structuredContent.signed, res.structuredContent.signed_request], ["not_completed", true, false, null]);
    const sent = JSON.parse(api.requests.at(-1).body);
    assert.equal(sent.payload_text, SEAL_ARGS.payload_text);
    assert.equal(sent.attested_context.client_name, "test-client");
    assert.equal(sent.reproducibility_context, undefined);
    status = 400;
    const refused = await client.callTool({ name: "seal_decision", arguments: SEAL_ARGS });
    assert.equal(refused.isError, true);
    assert.match(parseResult(refused).error, /HTTP 400: unknown field/);
  } finally {
    await api.close();
  }
});

test("prepare_signoff makes no request and requires job_id only for a job", async () => {
  const { client } = await connect({ config: config(), grants: { apiKey: null } });
  const ok = await client.callTool({ name: "prepare_signoff", arguments: { kind: "record", run_id: 1, digest: "1".repeat(64), decision: "approve" } });
  assert.ok(!ok.isError);
  assert.equal(ok.structuredContent.steps.length, 4);
  const missing = await client.callTool({ name: "prepare_signoff", arguments: { kind: "job", run_id: 1, digest: "1".repeat(64), decision: "approve" } });
  assert.equal(missing.isError, true);
  const extra = await client.callTool({ name: "prepare_signoff", arguments: { kind: "record", run_id: 1, digest: "1".repeat(64), job_id: "j", decision: "approve" } });
  assert.equal(extra.isError, true);
  const injected = await client.callTool({ name: "prepare_signoff", arguments: { kind: "record", run_id: 1, digest: "1'; rm -rf ~; '".padEnd(64, "a"), decision: "approve" } });
  assert.equal(injected.isError, true);
});

test("HTTP mode serves the same tools on this machine and checks the bearer token", async () => {
  const token = "t".repeat(40);
  const http = await startHttp({ host: "127.0.0.1", port: 0, token, newServer: () => createServer({ config: config(), grants: { apiKey: null } }) });
  const { port } = http.address();
  try {
    const url = new URL(`http://127.0.0.1:${port}/mcp`);
    const denied = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    assert.equal(denied.status, 401);
    const client = new Client({ name: "http-test", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(url, { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
    const listed = await client.listTools();
    assert.deepEqual(listed.tools, contract.tools);
    await client.close();
  } finally {
    await new Promise((r) => http.close(r));
  }
  assert.throws(() => startHttp({ host: "0.0.0.0", port: 0, newServer: () => createServer({ config: config(), grants: { apiKey: null } }) }), StartupError);
});
