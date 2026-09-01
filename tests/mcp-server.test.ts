import { resolve } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { describe, expect, it } from "vitest";

describe("ActionLock MCP server", () => {
  it("starts fail-closed with no gateway config and advertises only ActionLock tools", async () => {
    const stateDirectory = await mkdtemp(join(tmpdir(), "actionlock-mcp-test-"));
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [resolve("node_modules/tsx/dist/cli.mjs"), resolve("src/mcp/index.ts")],
      cwd: process.cwd(),
      env: {
        ...getDefaultEnvironment(),
        ACTIONLOCK_ROOT_SECRET: "test root secret with at least thirty two bytes",
        ACTIONLOCK_STATE_DIR: stateDirectory,
      },
      stderr: "pipe",
    });
    const client = new Client({ name: "actionlock-integration-test", version: "1.0.0" });
    try {
      await client.connect(transport);
      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
        "actionlock_execute",
        "actionlock_list_policies",
        "actionlock_preview",
        "actionlock_read_room",
        "actionlock_verify_audit",
      ]);
      const policies = await client.callTool({ name: "actionlock_list_policies", arguments: {} });
      expect(JSON.stringify(policies)).toContain('\\"policies\\":[]');
    } finally {
      await transport.close();
      await rm(stateDirectory, { recursive: true, force: true });
    }
  });
});
