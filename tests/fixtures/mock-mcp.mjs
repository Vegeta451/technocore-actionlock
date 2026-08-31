import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "actionlock-test-downstream", version: "1.0.0" });
server.tool("write_report", "Test-only deterministic downstream tool.", { text: z.string().max(200) }, async ({ text }) => ({
  content: [{ type: "text", text: JSON.stringify({ accepted: true, text }) }],
}));
await server.connect(new StdioServerTransport());
