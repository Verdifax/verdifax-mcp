// seal_decision: builds the request body the contract defines, signs it on
// this machine with signature version 2 when a request key is configured,
// and sends that exact text. The signing preimage comes from the Verdifax
// SDK; the private key never leaves this process.

import { createHash, createPrivateKey, randomBytes, sign, type KeyObject } from "node:crypto";

import { requestSignaturePreimageV2 } from "verdifax";

import { contract } from "./contract.js";
import { hasRefusedCharacter, cleanString } from "./clean.js";
import { ToolError } from "./errors.js";

const PKCS8_ED25519_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");
const SEAL = contract.implementation.seal;

export interface DeclaredClient {
  name: string;
  version: string;
  label: string;
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

/** The client's declared name and version, cleaned to printable ASCII,
 *  clipped to the byte limit and stripped of leading and trailing spaces,
 *  as the server accepts them. The label says that nothing checked them. */
export function declaredClient(info: { name?: unknown; version?: unknown } | undefined): DeclaredClient {
  const short = (v: unknown) =>
    cleanString(typeof v === "string" ? v : "")
      .replace(/[^\x20-\x7e]/g, "")
      .slice(0, SEAL.declared_client_max_bytes)
      .replace(/^ +| +$/g, "");
  return { name: short(info?.name), version: short(info?.version), label: SEAL.declared_client_label };
}

/** Refuses a hidden character anywhere in the arguments, naming the field. */
export function refuseHiddenCharacters(value: unknown, field: string): void {
  if (typeof value === "string") {
    if (hasRefusedCharacter(value)) {
      throw new ToolError(`${field} holds a control or zero-width character; seal plain text only`);
    }
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => refuseHiddenCharacters(v, `${field}[${i}]`));
  } else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      refuseHiddenCharacters(k, field);
      refuseHiddenCharacters(v, `${field}.${k}`);
    }
  }
}

export function sortedDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortedDeep);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) out[k] = sortedDeep((value as Record<string, unknown>)[k]);
    return out;
  }
  return value;
}

/** The body the contract defines, with keys sorted. */
export function sealBody(args: Record<string, unknown>, client: DeclaredClient): Record<string, unknown> {
  const body: Record<string, unknown> = {
    payload_text: args.payload_text,
    program_id: args.program_id,
    route_id: args.route_id,
    registry_record_hash: args.registry_record_hash,
  };
  for (const k of ["ai_output_text", "policy_context", "expected_policy_hash"]) {
    if (args[k] !== undefined) body[k] = args[k];
  }
  const declared: Record<string, string> = {};
  if (client.name !== "") declared.client_name = client.name;
  if (client.version !== "") declared.client_version = client.version;
  if (args.attested_context !== undefined || Object.keys(declared).length > 0) {
    body.attested_context = { ...((args.attested_context as Record<string, unknown> | undefined) ?? {}), ...declared, attested: true };
  }
  return sortedDeep(body) as Record<string, unknown>;
}

export function signingKey(raw: Uint8Array): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_HEADER, Buffer.from(raw)]), format: "der", type: "pkcs8" });
}

export interface SignedBody {
  signed_request: string;
  request_signature: { version: "2"; signature: string; signed_at: string; nonce: string };
}

export function signedAtNow(): string {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

/** Signs the exact text with signature version 2. */
export function signBody(
  key: KeyObject,
  text: string,
  body: Record<string, unknown>,
  signedAt: string = signedAtNow(),
  nonce: string = randomBytes(16).toString("hex"),
): SignedBody {
  const ai = typeof body.ai_output_text === "string" ? body.ai_output_text : "";
  const preimage = requestSignaturePreimageV2({
    body_hash: sha256Hex(text),
    payload_hash: sha256Hex(String(body.payload_text)),
    program_id: String(body.program_id),
    route_id: String(body.route_id),
    registry_record_hash: String(body.registry_record_hash),
    ai_output_hash: ai ? sha256Hex(ai) : "",
    signed_at: signedAt,
    nonce,
  });
  return {
    signed_request: text,
    request_signature: { version: "2", signature: sign(null, preimage, key).toString("base64"), signed_at: signedAt, nonce },
  };
}
