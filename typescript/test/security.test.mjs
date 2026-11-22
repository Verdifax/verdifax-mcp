// Security tests: owner-key refusal, refused environment, key file
// permissions, path traversal, hostile record strings and secret leaks.

import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadConfig } from "../dist/config.js";
import { StartupError } from "../dist/errors.js";
import { prepare } from "../dist/startup.js";
import {
  connect, config, fakeAPI, fakeVerifier, keyCheck, parseResult, readJSON, workdir,
  FEED_KEY, MEMBER_KEY, OWNER_KEY, TESTDATA,
} from "./helpers.mjs";

const HOSTILE = readJSON(join(TESTDATA, "hostile-strings.json")).cases;

test("an owner key stops the server at startup, and nothing is sealed", async () => {
  const api = await fakeAPI((e) => keyCheck(e));
  try {
    await assert.rejects(prepare({ VERDIFAX_BASE_URL: api.baseURL, VERDIFAX_API_KEY: OWNER_KEY }), (err) => {
      assert.ok(err instanceof StartupError);
      assert.match(err.message, /VERDIFAX_API_KEY is an account owner key\. This server never holds owner powers/);
      assert.ok(!err.message.includes(OWNER_KEY));
      return true;
    });
    assert.deepEqual(api.requests.map((r) => `${r.method} ${r.path}`), ["GET /stats"]);
  } finally {
    await api.close();
  }
});

test("an owner key given as the feed key is refused too", async () => {
  const api = await fakeAPI((e) => keyCheck(e));
  try {
    await assert.rejects(
      prepare({ VERDIFAX_BASE_URL: api.baseURL, VERDIFAX_API_KEY: MEMBER_KEY, VERDIFAX_FEED_KEY: OWNER_KEY }),
      /VERDIFAX_FEED_KEY is an account owner key/,
    );
    await assert.rejects(
      prepare({ VERDIFAX_BASE_URL: api.baseURL, VERDIFAX_API_KEY: FEED_KEY }),
      /VERDIFAX_API_KEY is a feed key/,
    );
    await assert.rejects(
      prepare({ VERDIFAX_BASE_URL: api.baseURL, VERDIFAX_FEED_KEY: MEMBER_KEY }),
      /not a feed key/,
    );
  } finally {
    await api.close();
  }
});

test("a member key and a feed key start, and the reported grants limit the tools", async () => {
  const api = await fakeAPI((e) => keyCheck(e, { "X-Verdifax-Allowed-Tools": "get_record, list_records, made_up_tool" }));
  try {
    const ready = await prepare({ VERDIFAX_BASE_URL: api.baseURL, VERDIFAX_API_KEY: MEMBER_KEY, VERDIFAX_FEED_KEY: FEED_KEY });
    assert.deepEqual(ready.grants.apiKey, ["get_record", "list_records"]);
    const { client } = await connect(ready);
    assert.match(client.getInstructions(), /granted these tools: get_record, list_records\./);
    const refused = await client.callTool({
      name: "seal_decision",
      arguments: { program_id: "a".repeat(64), route_id: "r", registry_record_hash: "b".repeat(64), payload_text: "x" },
    });
    assert.equal(refused.isError, true);
    assert.match(parseResult(refused).error, /did not grant seal_decision/);
    assert.ok(!api.requests.some((r) => r.path === "/execute"), "a refused tool sends nothing");
  } finally {
    await api.close();
  }
});

test("approver and owner keys in the environment stop the server", () => {
  for (const name of ["VERDIFAX_APPROVER_KEY", "VERDIFAX_APPROVER_KEY_FILE", "VERDIFAX_OWNER_KEY"]) {
    assert.throws(() => loadConfig({ [name]: "anything" }), (err) => err instanceof StartupError && err.message.includes(name));
  }
});

test("a request key file group or others can read is refused; a private one loads in every form", () => {
  const dir = mkdtempSync(join(tmpdir(), "verdifax-mcp-key-"));
  const raw = Buffer.alloc(32, 7);
  const forms = { "raw.key": raw, "hex.key": raw.toString("hex") + "\n", "b64.key": raw.toString("base64") };
  for (const [name, content] of Object.entries(forms)) {
    const path = join(dir, name);
    writeFileSync(path, content);
    chmodSync(path, 0o644);
    assert.throws(() => loadConfig({ VERDIFAX_API_KEY: MEMBER_KEY, VERDIFAX_REQUEST_KEY_FILE: path }), /group or others/);
    chmodSync(path, 0o600);
    assert.deepEqual(Buffer.from(loadConfig({ VERDIFAX_API_KEY: MEMBER_KEY, VERDIFAX_REQUEST_KEY_FILE: path }).requestKey), raw);
  }
  const bad = join(dir, "bad.key");
  writeFileSync(bad, "not a key");
  chmodSync(bad, 0o600);
  assert.throws(() => loadConfig({ VERDIFAX_API_KEY: MEMBER_KEY, VERDIFAX_REQUEST_KEY_FILE: bad }), /32-byte private key/);
});

test("plain http is refused for any host but this machine", () => {
  assert.throws(() => loadConfig({ VERDIFAX_BASE_URL: "http://api.verdifax.com" }), /https/);
  assert.throws(() => loadConfig({ VERDIFAX_BASE_URL: "https://user:pw@api.verdifax.com" }), /user name/);
  assert.equal(loadConfig({ VERDIFAX_BASE_URL: "http://127.0.0.1:8080/" }).baseURL, "http://127.0.0.1:8080");
});

test("paths that leave the working folder are refused before the verifier runs", async () => {
  const dir = workdir();
  const outside = mkdtempSync(join(tmpdir(), "verdifax-mcp-outside-"));
  writeFileSync(join(outside, "secret.json"), "{}");
  symlinkSync(join(outside, "secret.json"), join(dir, "link.json"));
  const verifier = fakeVerifier();
  process.env.FAKE_VERIFY_ARGS_FILE = verifier.argsFile;
  try {
    const { client } = await connect({ config: config({ workdir: dir, verifierPath: verifier.path }), grants: { apiKey: null } });
    const attempts = [
      { path: "../outside.json" },
      { path: "records/../../etc/passwd" },
      { path: "/etc/passwd" },
      { path: "link.json" },
      { path: "records" },
      { path: "missing.json" },
      { path: "records/bundle.json", policy_path: "../policy.json" },
      { path: "records/bundle.json\u0000.txt" },
    ];
    for (const args of attempts) {
      const res = await client.callTool({ name: "verify_record", arguments: args });
      assert.equal(res.isError, true, JSON.stringify(args));
    }
    const feed = await client.callTool({ name: "verify_feed", arguments: { path: "feed.json", owner_request_key_paths: ["../k.txt"] } });
    assert.equal(feed.isError, true);
    const policy = await client.callTool({ name: "test_policy", arguments: { inputs: {}, document_path: "../policy.json" } });
    assert.equal(policy.isError, true);
    assert.ok(!existsSync(verifier.argsFile), "the verifier never ran");
  } finally {
    delete process.env.FAKE_VERIFY_ARGS_FILE;
  }
});

test("hostile record strings come back only as cleaned, quoted fields", async () => {
  const record = { notes: HOSTILE.map((c) => c.raw), [HOSTILE[0].raw]: "key with hidden characters" };
  const api = await fakeAPI((e) => {
    if (e.path === "/runs/7/artifacts") return { status: 200, body: record };
    return keyCheck(e);
  });
  const dir = workdir();
  const verifier = fakeVerifier();
  const stdout = join(dir, "stdout.json");
  writeFileSync(stdout, JSON.stringify({ verdict_tier: "FAILED", reason: HOSTILE[2].raw }));
  process.env.FAKE_VERIFY_STDOUT_FILE = stdout;
  process.env.FAKE_VERIFY_STDERR = HOSTILE[0].raw;
  process.env.FAKE_VERIFY_EXIT = "1";
  try {
    const { client } = await connect({
      config: config({ baseURL: api.baseURL, apiKey: MEMBER_KEY, workdir: dir, verifierPath: verifier.path }),
      grants: { apiKey: null },
    });
    const res = await client.callTool({ name: "get_record", arguments: { run_id: 7 } });
    assert.ok(!res.isError);
    assert.deepEqual(res.structuredContent.record.notes, HOSTILE.map((c) => c.cleaned));
    assert.ok(Object.keys(res.structuredContent.record).includes(HOSTILE[0].cleaned));
    assert.deepEqual(parseResult(res), res.structuredContent);
    const verified = await client.callTool({ name: "verify_record", arguments: { path: "records/bundle.json" } });
    assert.equal(verified.structuredContent.outcome, "failed");
    assert.equal(verified.structuredContent.report.reason, HOSTILE[2].cleaned);
    assert.equal(verified.structuredContent.stderr.trim(), HOSTILE[0].cleaned);
    for (const text of [JSON.stringify(res.structuredContent), JSON.stringify(verified.structuredContent)]) {
      assert.ok(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(text));
      assert.ok(!/[\u{e0000}-\u{e0fff}]/u.test(text));
    }
  } finally {
    delete process.env.FAKE_VERIFY_STDOUT_FILE;
    delete process.env.FAKE_VERIFY_STDERR;
    delete process.env.FAKE_VERIFY_EXIT;
    await api.close();
  }
});

test("seal_decision refuses hidden characters and sends nothing", async () => {
  const api = await fakeAPI((e) => keyCheck(e));
  try {
    const { client } = await connect({ config: config({ baseURL: api.baseURL, apiKey: MEMBER_KEY }), grants: { apiKey: null } });
    const res = await client.callTool({
      name: "seal_decision",
      arguments: { program_id: "a".repeat(64), route_id: "r", registry_record_hash: "b".repeat(64), payload_text: "approve\u200b" },
    });
    assert.equal(res.isError, true);
    assert.match(parseResult(res).error, /control or zero-width/);
    assert.equal(api.requests.length, 0);
  } finally {
    await api.close();
  }
});

test("no secret leaves the server: not in answers, errors, verifier output or the verifier's environment", async () => {
  const requestKey = Buffer.alloc(32, 9);
  const echo = `${MEMBER_KEY} ${FEED_KEY} ${requestKey.toString("hex")} ${requestKey.toString("base64")} vfx_00112233445566778899`;
  const api = await fakeAPI((e) => {
    if (e.path === "/runs/1/artifacts") return { status: 200, body: { leaked: echo } };
    if (e.path === "/runs") return { status: 500, body: { ok: false, error: `bad key ${e.key}` } };
    if (e.path === "/execute") return { status: 400, body: { ok: false, error: `refused ${echo}` } };
    if (e.path === "/signals") return { status: 200, body: { events: [{ id: "1", data: { kind: "x", entry: { note: echo } } }], next_after: 1, newest: 1 } };
    return keyCheck(e);
  });
  const dir = workdir();
  const verifier = fakeVerifier();
  process.env.FAKE_VERIFY_ARGS_FILE = verifier.argsFile;
  process.env.FAKE_VERIFY_STDERR = echo;
  process.env.VERDIFAX_API_KEY = MEMBER_KEY;
  process.env.VERDIFAX_FEED_KEY = FEED_KEY;
  try {
    const cfg = config({ baseURL: api.baseURL, apiKey: MEMBER_KEY, feedKey: FEED_KEY, requestKey, workdir: dir, verifierPath: verifier.path });
    const { client } = await connect({ config: cfg, grants: { apiKey: null } });
    const results = [
      await client.callTool({ name: "get_record", arguments: { run_id: 1 } }),
      await client.callTool({ name: "list_records", arguments: {} }),
      await client.callTool({ name: "read_feed", arguments: {} }),
      await client.callTool({ name: "verify_record", arguments: { path: "records/bundle.json" } }),
      await client.callTool({
        name: "seal_decision",
        arguments: { program_id: "a".repeat(64), route_id: "r", registry_record_hash: "b".repeat(64), payload_text: "x" },
      }),
    ];
    const all = JSON.stringify(results);
    for (const secret of [MEMBER_KEY, FEED_KEY, requestKey.toString("hex"), requestKey.toString("base64"), "vfx_00112233445566778899"]) {
      assert.ok(!all.includes(secret), `a secret leaked: ${secret.slice(0, 8)}`);
    }
    assert.ok(all.includes("[redacted]"));
    const childEnv = readFileSync(verifier.argsFile + ".env", "utf8").trim();
    assert.equal(childEnv, "", "no VERDIFAX_ variable reached the verifier");
  } finally {
    for (const k of ["FAKE_VERIFY_ARGS_FILE", "FAKE_VERIFY_STDERR", "VERDIFAX_API_KEY", "VERDIFAX_FEED_KEY"]) delete process.env[k];
    await api.close();
  }
});
