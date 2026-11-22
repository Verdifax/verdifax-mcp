// The optional Streamable HTTP mode, for a customer to run on its own
// machines. It listens on 127.0.0.1 unless told otherwise, protects a local
// listener against DNS rebinding, and refuses to listen beyond this machine
// without a bearer token, which it then requires on every request.

import { randomUUID, timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { contract } from "./contract.js";
import { StartupError } from "./errors.js";

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

export interface HttpOptions {
  host: string;
  port: number;
  token?: string;
  newServer: () => { connect(transport: StreamableHTTPServerTransport): Promise<void> };
}

function tokenMatches(req: IncomingMessage, token: string): boolean {
  const header = req.headers.authorization ?? "";
  const given = Buffer.from(header.startsWith("Bearer ") ? header.slice(7) : "", "utf8");
  const want = Buffer.from(token, "utf8");
  return given.length === want.length && timingSafeEqual(given, want);
}

export function startHttp(options: HttpOptions): Promise<HttpServer> {
  const loopback = LOOPBACK.has(options.host);
  if (!loopback && !options.token) {
    throw new StartupError("HTTP mode beyond this machine needs VERDIFAX_MCP_HTTP_TOKEN");
  }
  const path = contract.implementation.http_mode.path;
  const transports = new Map<string, StreamableHTTPServerTransport>();
  const http = createHttpServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://placeholder");
    if (url.pathname !== path) {
      res.writeHead(404).end();
      return;
    }
    if (options.token && !tokenMatches(req, options.token)) {
      res.writeHead(401, { "WWW-Authenticate": "Bearer" }).end();
      return;
    }
    const sessionId = req.headers["mcp-session-id"];
    let transport = typeof sessionId === "string" ? transports.get(sessionId) : undefined;
    if (!transport) {
      if (sessionId !== undefined || req.method !== "POST") {
        res.writeHead(404, { "Content-Type": "application/json" }).end(JSON.stringify({ error: "unknown session" }));
        return;
      }
      const port = (http.address() as { port: number }).port;
      const created: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          transports.set(id, created);
        },
        enableDnsRebindingProtection: loopback,
        allowedHosts: loopback ? [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`] : undefined,
      });
      created.onclose = () => {
        if (created.sessionId) transports.delete(created.sessionId);
      };
      await options.newServer().connect(created);
      transport = created;
    }
    await transport.handleRequest(req, res);
  });
  return new Promise((resolve, reject) => {
    http.once("error", reject);
    http.listen(options.port, options.host, () => resolve(http));
  });
}
