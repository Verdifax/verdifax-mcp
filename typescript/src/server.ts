// The MCP server: tools/list serves the contract's tools exactly; tools/call
// checks the arguments against the contract's input schema, applies the key's
// reported grants, runs the handler, cleans and redacts the answer, and checks
// it against the contract's output schema before it is sent.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import Ajv2020Module from "ajv/dist/2020.js";

import type { FetchLike } from "./api.js";
import { Redactor } from "./clean.js";
import { secretsOf, type Config } from "./config.js";
import { contract, toolDefinition } from "./contract.js";
import { ToolError } from "./errors.js";
import { handlers } from "./tools.js";

type Validate = ((data: unknown) => boolean) & { errors?: Array<{ instancePath: string; message?: string }> | null };
interface AjvLike {
  compile(schema: unknown): Validate;
}
const Ajv2020 = ((Ajv2020Module as unknown as { default?: unknown }).default ?? Ajv2020Module) as new (
  options: Record<string, unknown>,
) => AjvLike;

const ajv = new Ajv2020({ strict: true, allowUnionTypes: true, allErrors: false });
const inputCheck = new Map<string, Validate>();
const outputCheck = new Map<string, Validate>();
for (const tool of contract.tools) {
  inputCheck.set(tool.name, ajv.compile(tool.inputSchema));
  outputCheck.set(tool.name, ajv.compile(tool.outputSchema));
}

export interface Grants {
  /** The tools the server reported this member key may use, or null. */
  apiKey: string[] | null;
}

export interface ServerOptions {
  config: Config;
  grants: Grants;
  fetch?: FetchLike;
}

export function instructionsFor(grants: Grants): string {
  const line =
    grants.apiKey === null
      ? contract.server.grants_line_none
      : contract.server.grants_line_reported.replace("{tools}", grants.apiKey.length ? grants.apiKey.join(", ") : "none");
  return `${contract.server.instructions} ${line}`;
}

function describe(errors: Validate["errors"]): string {
  const first = errors?.[0];
  if (!first) return "the arguments do not match the tool's input schema";
  return `${first.instancePath || "the arguments"} ${first.message ?? "is not allowed"}`;
}

export function createServer(options: ServerOptions): Server {
  const redactor = new Redactor(secretsOf(options.config));
  const server = new Server(
    { name: contract.server.name, version: contract.server.version, title: contract.server.title },
    { capabilities: { tools: {} }, instructions: instructionsFor(options.grants) },
  );

  const failure = (message: string): CallToolResult => ({
    isError: true,
    content: [{ type: "text", text: JSON.stringify({ error: redactor.text(message) }) }],
  });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: JSON.parse(JSON.stringify(contract.tools)),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
    const name = req.params.name;
    const tool = toolDefinition(name);
    const handler = handlers[name];
    if (!tool || !handler) throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${redactor.text(String(name))}`);
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    const check = inputCheck.get(name)!;
    if (!check(args)) return failure(`Refused: ${describe(check.errors)}`);
    const uses = contract.implementation.uses[name];
    if (uses === "api_key" && options.grants.apiKey !== null && !options.grants.apiKey.includes(name)) {
      return failure(`Refused: the Verdifax server reports that this key's owner did not grant ${name}`);
    }
    let answer: unknown;
    try {
      answer = redactor.value(
        await handler(args, {
          config: options.config,
          fetch: options.fetch ?? fetch,
          clientInfo: () => server.getClientVersion(),
        }),
      );
    } catch (err) {
      if (err instanceof ToolError) return failure(err.message);
      return failure(`The tool failed: ${(err as Error)?.message ?? String(err)}`);
    }
    const out = outputCheck.get(name)!;
    if (!out(answer)) return failure(`This server built an answer its contract does not allow: ${describe(out.errors)}`);
    return {
      content: [{ type: "text", text: JSON.stringify(answer) }],
      structuredContent: answer as Record<string, unknown>,
    };
  });

  return server;
}
