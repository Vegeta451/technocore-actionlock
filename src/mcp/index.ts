import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { verifyAuditChain } from "../server/audit";
import {
  EMPTY_GATEWAY_CONFIG,
  listToolPolicies,
  loadGatewayConfig,
  StdioDownstreamExecutor,
} from "../server/downstream";
import { issueEvidenceReceipt } from "../server/evidence";
import { ActionLockGateway } from "../server/gateway";
import { FileReplayStore } from "../server/replay";
import { scanRoom } from "../server/scan";
import { assertRootSecret, deriveSecret } from "../server/secrets";

const server = new McpServer({ name: "technocore-actionlock", version: "0.2.0" });
const rootSecret = assertRootSecret(process.env.ACTIONLOCK_ROOT_SECRET);
const evidenceSecret = deriveSecret(rootSecret, "evidence");
const approvalSecret = deriveSecret(rootSecret, "approval");
const auditSecret = deriveSecret(rootSecret, "audit");
const stateDirectory = resolve(process.env.ACTIONLOCK_STATE_DIR ?? "./data/actionlock");
const auditPath = resolve(process.env.ACTIONLOCK_AUDIT_PATH ?? `${stateDirectory}/audit.ndjson`);
const configPath = resolve(process.env.ACTIONLOCK_CONFIG ?? "./actionlock.config.json");

let config = EMPTY_GATEWAY_CONFIG;
try {
  config = await loadGatewayConfig(configPath);
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== "ENOENT" || process.env.ACTIONLOCK_CONFIG) throw error;
}

const executor = new StdioDownstreamExecutor();
const gateway = new ActionLockGateway({
  config,
  executor,
  evidenceSecret,
  approvalSecret,
  auditSecret,
  replayStore: new FileReplayStore(resolve(stateDirectory, "consumed-grants")),
  auditPath,
});

const gatewayInput = {
  server: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,47}$/),
  tool: z.string().min(1).max(128),
  arguments: z.record(z.unknown()).default({}),
  evidenceToken: z.string().min(32).max(20_000),
};

server.tool(
  "actionlock_read_room",
  "Read a bounded Technocore room window and issue short-lived evidence receipts. Embedded links are never followed.",
  { room: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,47}$/), limit: z.number().int().min(1).max(50).default(25) },
  async ({ room, limit }) => {
    try {
      const result = await scanRoom({ room, limit, origin: process.env.TECHNOCORE_ORIGIN });
      const events = result.events.map((event) => ({
        ...event,
        evidence: issueEvidenceReceipt({ event, secret: evidenceSecret }),
      }));
      return { content: [{ type: "text", text: JSON.stringify({ ...result, events }) }] };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Room read failed";
      return { isError: true, content: [{ type: "text", text: message }] };
    }
  },
);

server.tool(
  "actionlock_list_policies",
  "List only the downstream tools explicitly configured behind ActionLock. An empty list means execution is disabled.",
  {},
  async () => ({
    content: [{ type: "text", text: JSON.stringify({ policies: listToolPolicies(config) }) }],
  }),
);

server.tool(
  "actionlock_preview",
  "Preview the exact policy decision and action hash for a downstream call. This never starts or calls the downstream server.",
  gatewayInput,
  async (input) => {
    try {
      return { content: [{ type: "text", text: JSON.stringify(gateway.preview(input)) }] };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Preview failed";
      return { isError: true, content: [{ type: "text", text: message }] };
    }
  },
);

server.tool(
  "actionlock_execute",
  "Enforced downstream MCP gateway. Requires ActionLock evidence and, for remote-derived calls, an exact short-lived approval.",
  { ...gatewayInput, approvalToken: z.string().min(32).max(2_000).optional() },
  async (input) => {
    try {
      const result = await gateway.execute(input);
      return { isError: !result.executed, content: [{ type: "text", text: JSON.stringify(result) }] };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Gateway execution failed";
      return { isError: true, content: [{ type: "text", text: message }] };
    }
  },
);

server.tool(
  "actionlock_verify_audit",
  "Verify the local hash chain and its HMAC-protected head checkpoint.",
  {},
  async () => ({
    content: [
      {
        type: "text",
        text: JSON.stringify(await verifyAuditChain(auditPath, { checkpointSecret: auditSecret })),
      },
    ],
  }),
);

const shutdown = async () => {
  await executor.close();
  process.exit(0);
};
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);

await server.connect(new StdioServerTransport());
