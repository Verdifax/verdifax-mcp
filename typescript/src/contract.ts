// The tool contract, mcp-tools.json, shipped beside dist/. The contract test
// fails when this copy differs from the one at the repository's root.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const CONTRACT_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "mcp-tools.json");

export interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  annotations: Record<string, unknown>;
}

export type Range = [number, number];
export type ArgumentRule = [string, string, "path" | "flag" | "value" | "path_list"];

export interface Contract {
  server: {
    name: string;
    version: string;
    title: string;
    instructions: string;
    grants_line_reported: string;
    grants_line_none: string;
  };
  tools: ToolDefinition[];
  implementation: {
    data_notice: string;
    uses: Record<string, "local_verifier" | "api_key" | "feed_key" | "none">;
    refused_environment: Record<string, string>;
    key_check: {
      path: string;
      owner_key_error: string;
      feed_key_error: string;
      allowed_tools_header: string;
    };
    verifier: {
      timeout_seconds: number;
      max_output_bytes: number;
      stderr_max_chars: number;
      environment_removed_prefix: string;
      record_arguments: ArgumentRule[];
      feed_arguments: ArgumentRule[];
      record_exit_codes: Record<string, [string, string]>;
      feed_exit_codes: Record<string, [string, string]>;
      unknown_exit_code: [string, string];
    };
    text_cleaning: { replace_with_space: Range[]; remove: Range[] };
    redaction: { replacement: string; pattern: string };
    seal: { declared_client_label: string; declared_client_max_bytes: number };
    feed_reading: { page_limit: number; max_pages: number };
    limits: { max_answer_bytes: number; max_policy_document_bytes: number; request_timeout_seconds: number };
    http_mode: { default_host: string; default_port: number; path: string; token_min_chars: number };
    prepare_signoff: { command_template: string; steps: string[] };
  };
}

export const contract: Contract = JSON.parse(readFileSync(CONTRACT_PATH, "utf8")) as Contract;

export const toolNames: string[] = contract.tools.map((t) => t.name);

export function toolDefinition(name: string): ToolDefinition | undefined {
  return contract.tools.find((t) => t.name === name);
}

/** The fixed text the contract's output schema gives a field. */
export function outputConst(tool: string, field: string): string {
  const properties = (toolDefinition(tool)?.outputSchema as { properties?: Record<string, { const?: unknown }> })
    ?.properties;
  const value = properties?.[field]?.const;
  if (typeof value !== "string") throw new Error(`mcp-tools.json gives ${tool}.${field} no fixed text`);
  return value;
}
