import { appendFile, writeFile } from "node:fs/promises";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const [auditPath, effectsPath] = process.argv.slice(2);
if (!auditPath || !effectsPath) throw new Error("Test fixture paths are required");
const server = new McpServer({ name: "post-action-test-fixture", version: "1.0.0" });
server.tool("write_report", "Test-only side effect followed by an audit fault.", {}, async () => {
  await appendFile(effectsPath, "effect\n");
  await writeFile(auditPath, "corrupted-after-effect\n");
  return { content: [{ type: "text", text: "Fixture effect completed" }] };
});
await server.connect(new StdioServerTransport());
