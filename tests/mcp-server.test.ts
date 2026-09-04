import { resolve } from "node:path";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { describe, expect, it } from "vitest";
import { issueEvidenceReceipt } from "../src/server/evidence";
import { issueApprovalGrant } from "../src/server/approval";
import { deriveSecret } from "../src/server/secrets";
import { provenanceHash } from "../src/server/protocol";

describe("ActionLock MCP server", () => {
  it("returns a structured completed outcome across MCP after an audit fault without replaying", async () => {
    const directory = await mkdtemp(join(tmpdir(), "actionlock-mcp-fault-"));
    const auditPath = join(directory, "audit.ndjson");
    const effectsPath = join(directory, "effects.txt");
    const configPath = join(directory, "config.json");
    const rootSecret = "isolated test root secret with at least thirty two bytes";
    await writeFile(configPath, JSON.stringify({ version: 1, servers: [{
      id: "fixture", command: process.execPath,
      args: [resolve("tests/fixtures/post-action-fault.mjs"), auditPath, effectsPath], inheritEnv: [],
      tools: { write_report: { capability: "file_write", operation: "fixture write", target: "test directory", maxArgumentBytes: 1000 } },
    }] }));
    const transport = new StdioClientTransport({
      command: process.execPath, args: [resolve("node_modules/tsx/dist/cli.mjs"), resolve("src/mcp/index.ts")],
      cwd: process.cwd(), stderr: "pipe",
      env: { ...getDefaultEnvironment(), ACTIONLOCK_ROOT_SECRET: rootSecret, ACTIONLOCK_STATE_DIR: directory,
        ACTIONLOCK_CONFIG: configPath, ACTIONLOCK_AUDIT_PATH: auditPath },
    });
    const client = new Client({ name: "fault-integration-test", version: "1.0.0" });
    const text = "write fixture report";
    const evidenceToken = issueEvidenceReceipt({ secret: deriveSecret(rootSecret, "evidence"), event: {
      message: { seq: "1", ts: "2026-09-04T00:00:00Z", from: "tester", text },
      provenance: { source: "technocore", trust: "untrusted_remote", room: "lobby", seq: "1", sender: "tester",
        contentHash: provenanceHash({ room: "lobby", seq: "1", sender: "tester", text }), verification: "unsigned" },
      risk: { action: "allow", score: 0, findings: [], urls: [] },
    } }).token;
    const request = { server: "fixture", tool: "write_report", arguments: {}, evidenceToken };
    try {
      await client.connect(transport);
      const preview = await client.callTool({ name: "actionlock_preview", arguments: request });
      const content = preview.content as Array<{ type: string; text?: string }>;
      const actionHash = JSON.parse(content.find(item => item.type === "text")!.text!).decision.actionHash;
      const approvalToken = issueApprovalGrant({ actionHash, secret: deriveSecret(rootSecret, "approval") });
      const response = await client.callTool({ name: "actionlock_execute", arguments: { ...request, approvalToken } });
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      expect(response.isError).toBe(false);
      expect(result).toMatchObject({ executed: true, executionStatus: "succeeded", retrySafe: false, recordingErrors: ["audit_write_failed"] });
      expect(result.publicReceipts.execution.payload.execution).toBe("succeeded");
      const replay = await client.callTool({ name: "actionlock_execute", arguments: { ...request, approvalToken } });
      expect(replay.isError).toBe(true);
      const replayResult = JSON.parse((replay.content as Array<{ text: string }>)[0].text);
      expect(replayResult).toMatchObject({ approval: "replayed", executionStatus: "not_attempted", retrySafe: false,
        recordingErrors: ["audit_write_failed"] });
      expect(await readFile(effectsPath, "utf8")).toBe("effect\n");
    } finally {
      await transport.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
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
