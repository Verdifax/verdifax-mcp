#!/usr/bin/env node
// verdifax-mcp: the Verdifax MCP server over stdio, or with --http over
// Streamable HTTP on this machine. It checks its keys before it serves.

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { contract } from "./contract.js";
import { startHttp } from "./http.js";
import { createServer } from "./server.js";
import { parseArgs, prepare, USAGE } from "./startup.js";

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed === "version") {
    process.stdout.write(`${contract.server.name} ${contract.server.version} (typescript)\n`);
    return;
  }
  if (parsed === "help") {
    process.stdout.write(USAGE + "\n");
    return;
  }
  const { config, grants } = await prepare();
  const grantsText = grants.apiKey === null ? "no tool list reported" : `granted tools: ${grants.apiKey.join(", ") || "none"}`;
  process.stderr.write(`verdifax-mcp: ready (${config.baseURL}; ${grantsText})\n`);
  if (parsed.http) {
    await startHttp({
      host: parsed.host,
      port: parsed.port,
      token: config.httpToken,
      newServer: () => createServer({ config, grants }),
    });
    process.stderr.write(`verdifax-mcp: listening on http://${parsed.host}:${parsed.port}${contract.implementation.http_mode.path}\n`);
    return;
  }
  await createServer({ config, grants }).connect(new StdioServerTransport());
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`verdifax-mcp: ${message}\n`);
  process.exit(1);
});
