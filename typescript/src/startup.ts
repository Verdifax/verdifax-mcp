// Startup: command-line arguments, configuration and the key checks that
// run before anything is served.

import { checkFeedKey, checkMemberKey, type FetchLike } from "./api.js";
import { Redactor } from "./clean.js";
import { loadConfig, secretsOf, type Config } from "./config.js";
import { contract } from "./contract.js";
import { StartupError } from "./errors.js";
import type { Grants } from "./server.js";

export const USAGE = `usage: verdifax-mcp [--http] [--host HOST] [--port PORT] [--version]

Serves the Verdifax tools over stdio, or with --http over Streamable HTTP at
http://HOST:PORT${contract.implementation.http_mode.path} (default ${contract.implementation.http_mode.default_host}:${contract.implementation.http_mode.default_port}).
Keys and paths come from the environment; see the README.`;

interface Args {
  http: boolean;
  host: string;
  port: number;
}

export function parseArgs(argv: string[]): Args | "version" | "help" {
  const out: Args = {
    http: false,
    host: contract.implementation.http_mode.default_host,
    port: contract.implementation.http_mode.default_port,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--version") return "version";
    if (a === "--help" || a === "-h") return "help";
    if (a === "--http") out.http = true;
    else if (a === "--host" && i + 1 < argv.length) out.host = argv[++i]!;
    else if (a === "--port" && i + 1 < argv.length) {
      const port = Number(argv[++i]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new StartupError("--port must be 1 to 65535");
      out.port = port;
    } else throw new StartupError(`unknown argument ${a}\n${USAGE}`);
  }
  if (!out.http && (argv.includes("--host") || argv.includes("--port"))) {
    throw new StartupError("--host and --port apply only with --http");
  }
  return out;
}

/** Loads the configuration and checks the keys: an owner key stops the
 *  server here, before it serves anything. */
export async function prepare(
  env: NodeJS.ProcessEnv = process.env,
  fetchImpl: FetchLike = fetch,
): Promise<{ config: Config; grants: Grants }> {
  const config = loadConfig(env);
  const redactor = new Redactor(secretsOf(config));
  let grants: Grants = { grantedTools: null };
  if (config.apiKey) grants = { grantedTools: (await checkMemberKey(fetchImpl, config.baseURL, config.apiKey, redactor)).grants };
  if (config.feedKey) await checkFeedKey(fetchImpl, config.baseURL, config.feedKey, redactor);
  return { config, grants };
}

