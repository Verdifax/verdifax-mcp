// Configuration from the environment only. Secrets come from environment
// variables and key files; no tool takes a secret as input.

import { realpathSync, readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

import { contract } from "./contract.js";
import { StartupError } from "./errors.js";

export const DEFAULT_BASE_URL = "https://api.verdifax.com";
const LOCAL_HOSTS = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);
const REQUEST_KEY_BYTES = 32;

export interface Config {
  baseURL: string;
  apiKey?: string;
  feedKey?: string;
  requestKey?: Uint8Array;
  workdir?: string;
  verifierPath?: string;
  httpToken?: string;
}

function present(value: string | undefined): value is string {
  return typeof value === "string" && value.trim() !== "";
}

export function checkBaseURL(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new StartupError(`VERDIFAX_BASE_URL is not a URL: ${raw}`);
  }
  if (url.username || url.password) throw new StartupError("VERDIFAX_BASE_URL must not carry a user name or password");
  if (url.search || url.hash) throw new StartupError("VERDIFAX_BASE_URL must not carry a query or fragment");
  if (url.protocol === "http:") {
    if (!LOCAL_HOSTS.has(url.hostname)) {
      throw new StartupError("VERDIFAX_BASE_URL must use https; plain http is accepted only for this machine");
    }
  } else if (url.protocol !== "https:") {
    throw new StartupError("VERDIFAX_BASE_URL must use https");
  }
  return url.toString().replace(/\/+$/, "");
}

/** Reads the request key file: 32 raw bytes, 64 hex characters or base64.
 *  A file group or others can read or write is refused. */
export function loadRequestKey(path: string): Uint8Array {
  if (!isAbsolute(path)) throw new StartupError("VERDIFAX_REQUEST_KEY_FILE must be an absolute path");
  if (process.platform === "win32") {
    throw new StartupError("VERDIFAX_REQUEST_KEY_FILE is supported on Linux and macOS, where its permissions can be checked");
  }
  let info;
  try {
    info = statSync(path);
  } catch {
    throw new StartupError("VERDIFAX_REQUEST_KEY_FILE cannot be read");
  }
  if (!info.isFile()) throw new StartupError("VERDIFAX_REQUEST_KEY_FILE is not a regular file");
  if ((info.mode & 0o077) !== 0) {
    throw new StartupError(
      "VERDIFAX_REQUEST_KEY_FILE can be read or written by group or others; run chmod 600 on it first",
    );
  }
  if (info.size > 1024) throw new StartupError("VERDIFAX_REQUEST_KEY_FILE is too large to be a request key");
  const raw = readFileSync(path);
  if (raw.length === REQUEST_KEY_BYTES) return new Uint8Array(raw);
  const text = raw.toString("utf8").trim();
  if (/^[0-9a-fA-F]{64}$/.test(text)) return new Uint8Array(Buffer.from(text, "hex"));
  if (/^[A-Za-z0-9+/]{43}=$/.test(text)) {
    const decoded = Buffer.from(text, "base64");
    if (decoded.length === REQUEST_KEY_BYTES) return new Uint8Array(decoded);
  }
  throw new StartupError(
    "VERDIFAX_REQUEST_KEY_FILE must hold the 32-byte private key as raw bytes, 64 hex characters or base64",
  );
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  for (const [name, reason] of Object.entries(contract.implementation.refused_environment)) {
    if (present(env[name])) throw new StartupError(`${name} is set. ${reason} Remove it from this server's environment.`);
  }
  const config: Config = {
    baseURL: checkBaseURL(present(env.VERDIFAX_BASE_URL) ? env.VERDIFAX_BASE_URL : present(env.VERDIFAX_API_URL) ? env.VERDIFAX_API_URL : DEFAULT_BASE_URL),
  };
  if (present(env.VERDIFAX_API_KEY)) config.apiKey = env.VERDIFAX_API_KEY.trim();
  if (present(env.VERDIFAX_FEED_KEY)) config.feedKey = env.VERDIFAX_FEED_KEY.trim();
  if (config.apiKey && config.apiKey === config.feedKey) {
    throw new StartupError("VERDIFAX_API_KEY and VERDIFAX_FEED_KEY hold the same key");
  }
  if (present(env.VERDIFAX_REQUEST_KEY_FILE)) {
    if (!config.apiKey) throw new StartupError("VERDIFAX_REQUEST_KEY_FILE is set but VERDIFAX_API_KEY is not");
    config.requestKey = loadRequestKey(env.VERDIFAX_REQUEST_KEY_FILE.trim());
  }
  if (present(env.VERDIFAX_MCP_WORKDIR)) {
    const dir = env.VERDIFAX_MCP_WORKDIR.trim();
    if (!isAbsolute(dir)) throw new StartupError("VERDIFAX_MCP_WORKDIR must be an absolute path");
    let real: string;
    try {
      real = realpathSync(dir);
    } catch {
      throw new StartupError("VERDIFAX_MCP_WORKDIR does not exist");
    }
    if (!statSync(real).isDirectory()) throw new StartupError("VERDIFAX_MCP_WORKDIR is not a folder");
    config.workdir = real;
  }
  if (present(env.VERDIFAX_VERIFY_PATH)) {
    const path = env.VERDIFAX_VERIFY_PATH.trim();
    if (!isAbsolute(path)) throw new StartupError("VERDIFAX_VERIFY_PATH must be an absolute path");
    config.verifierPath = path;
  }
  if (present(env.VERDIFAX_MCP_HTTP_TOKEN)) {
    const token = env.VERDIFAX_MCP_HTTP_TOKEN.trim();
    if (token.length < contract.implementation.http_mode.token_min_chars) {
      throw new StartupError(
        `VERDIFAX_MCP_HTTP_TOKEN must be at least ${contract.implementation.http_mode.token_min_chars} characters`,
      );
    }
    config.httpToken = token;
  }
  return config;
}

/** Every secret the redactor must hide, in each form it could appear. */
export function secretsOf(config: Config): string[] {
  const out: string[] = [];
  if (config.apiKey) out.push(config.apiKey);
  if (config.feedKey) out.push(config.feedKey);
  if (config.httpToken) out.push(config.httpToken);
  if (config.requestKey) {
    const key = Buffer.from(config.requestKey);
    out.push(key.toString("hex"), key.toString("hex").toUpperCase(), key.toString("base64"));
  }
  return out;
}
