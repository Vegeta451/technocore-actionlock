import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const expectedTools = [
  "actionlock_execute",
  "actionlock_list_policies",
  "actionlock_preview",
  "actionlock_read_room",
  "actionlock_verify_audit",
];

const stateDirectory = await mkdtemp(join(tmpdir(), "actionlock-mcp-smoke-"));
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [resolve("node_modules/tsx/dist/cli.mjs"), resolve("src/mcp/index.ts")],
  cwd: process.cwd(),
  env: {
    ...getDefaultEnvironment(),
    ACTIONLOCK_ROOT_SECRET: "isolated smoke test root secret with more than thirty two bytes",
    ACTIONLOCK_STATE_DIR: stateDirectory,
  },
  stderr: "pipe",
});
const client = new Client({ name: "actionlock-smoke-check", version: "1.0.0" });

try {
  await client.connect(transport);
  const tools = (await client.listTools()).tools.map((tool) => tool.name).sort();
  if (JSON.stringify(tools) !== JSON.stringify(expectedTools)) {
    throw new Error(`Unexpected MCP tools: ${tools.join(", ")}`);
  }

  const response = await client.callTool({ name: "actionlock_list_policies", arguments: {} });
  const text = response.content.find((item) => item.type === "text")?.text;
  const policies = text ? JSON.parse(text).policies : null;
  if (!Array.isArray(policies) || policies.length !== 0) {
    throw new Error("ActionLock did not start with a fail-closed empty policy list");
  }

  console.log(`MCP connection OK: ${tools.length} tools, execution disabled without trusted config.`);
} finally {
  await transport.close();
  await rm(stateDirectory, { recursive: true, force: true });
}
