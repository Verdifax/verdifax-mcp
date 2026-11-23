// Contract conformance: this implementation serves exactly the tools in
// mcp-tools.json, its copy of the contract is byte-identical to the root one,
// and the shared vectors come out the same as in every other language.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { contract, CONTRACT_PATH } from "../dist/contract.js";
import { handlers } from "../dist/tools.js";
import { sealBody, signBody, signingKey, declaredClient } from "../dist/seal.js";
import { prepareSignoff } from "../dist/signoff.js";
import { connect, config, readJSON, REPO, TESTDATA } from "./helpers.mjs";

test("the shipped contract is byte-identical to the repository's mcp-tools.json", () => {
  assert.equal(readFileSync(CONTRACT_PATH, "utf8"), readFileSync(join(REPO, "mcp-tools.json"), "utf8"));
});

test("tools/list serves exactly the contract's tools, in order", async () => {
  const root = readJSON(join(REPO, "mcp-tools.json"));
  const { client } = await connect({ config: config(), grants: { grantedTools: null } });
  const listed = await client.listTools();
  assert.deepEqual(listed.tools, root.tools);
  assert.deepEqual(
    listed.tools.map((t) => t.name),
    ["verify_record", "verify_feed", "get_record", "list_records", "read_feed", "list_pending_signoffs", "get_signoffs", "test_policy", "seal_decision", "prepare_signoff"],
  );
});

test("every contract tool has a handler, and no handler is outside the contract", () => {
  assert.deepEqual(Object.keys(handlers).sort(), contract.tools.map((t) => t.name).sort());
  assert.deepEqual(Object.keys(contract.implementation.uses).sort(), contract.tools.map((t) => t.name).sort());
});

test("no tool takes a secret as input", () => {
  const forbidden = /key|secret|token|password|credential/i;
  const walk = (schema, path) => {
    for (const [name, sub] of Object.entries(schema.properties ?? {})) {
      const allowed = ["approver_public_key_path", "signer_public_key_path", "owner_request_key_paths"].includes(name);
      assert.ok(allowed || !forbidden.test(name), `${path}.${name} looks like a secret field`);
      if (sub.type === "object") walk(sub, `${path}.${name}`);
    }
  };
  for (const tool of contract.tools) walk(tool.inputSchema, tool.name);
});

test("initialize names the contract's server and instructions", async () => {
  const { client } = await connect({ config: config(), grants: { grantedTools: null } });
  assert.equal(client.getServerVersion().name, contract.server.name);
  assert.equal(client.getServerVersion().version, contract.server.version);
  assert.ok(client.getInstructions().startsWith(contract.server.instructions));
  assert.ok(client.getInstructions().endsWith(contract.server.grants_line_none));
});

test("seal_decision builds and signs the shared vector exactly", () => {
  const vector = readJSON(join(TESTDATA, "seal-vector.json"));
  const key = signingKey(Buffer.from(vector.request_key_hex, "hex"));
  for (const c of vector.cases) {
    const body = sealBody(c.arguments, declaredClient(c.client_info));
    const text = JSON.stringify(body);
    assert.equal(text, c.signed_request);
    const signed = signBody(key, text, body, vector.signed_at, vector.nonce);
    assert.deepEqual(signed.request_signature, c.request_signature);
  }
});

test("prepare_signoff prints the shared vector's commands exactly", () => {
  const vector = readJSON(join(TESTDATA, "prepare-signoff-vector.json"));
  for (const c of vector.cases) assert.equal(prepareSignoff(c.arguments).command, c.command);
});

test("the em dash appears nowhere in the contract", () => {
  assert.ok(!readFileSync(CONTRACT_PATH, "utf8").includes("\u2014"));
});
