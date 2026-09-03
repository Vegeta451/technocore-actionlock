import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
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
const fixture = createServer((request, response) => {
  if (request.method !== "GET" || !request.url?.startsWith("/r/lobby?")) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({
    room: "lobby", count: 2, first_seq: "42", last_seq: "43",
    messages: [
      { seq: "42", ts: "2026-09-04T00:00:00Z", from: "tester", text: "fixture observation", nonce: "9007199254740993123" },
      { seq: "43", text: { invalid: true } },
    ],
  }));
});
await new Promise((resolveListen, reject) => {
  fixture.once("error", reject);
  fixture.listen(0, "127.0.0.1", resolveListen);
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [resolve("node_modules/tsx/dist/cli.mjs"), resolve("src/mcp/index.ts")],
  cwd: process.cwd(),
  env: {
    ...getDefaultEnvironment(),
    ACTIONLOCK_ROOT_SECRET: "isolated smoke test root secret with more than thirty two bytes",
    ACTIONLOCK_STATE_DIR: stateDirectory,
    TECHNOCORE_ORIGIN: `http://127.0.0.1:${fixture.address().port}`,
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

  const read = await client.callTool({ name: "actionlock_read_room", arguments: { room: "lobby", limit: 25 } });
  const payload = JSON.parse(read.content.find((item) => item.type === "text")?.text ?? "null");
  if (read.isError || payload?.rejectedCount !== 1 || payload?.events?.length !== 1 ||
      payload.events[0].message.nonce !== "9007199254740993123" || !payload.events[0].evidence) {
    throw new Error("MCP room read did not preserve valid evidence and report the rejected record");
  }
  console.log(`MCP connection OK: ${tools.length} tools, partial read and exact nonce verified; execution disabled without trusted config.`);
} finally {
  await transport.close();
  fixture.closeAllConnections();
  await new Promise((resolveClose) => fixture.close(resolveClose));
  await rm(stateDirectory, { recursive: true, force: true });
}
