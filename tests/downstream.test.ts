import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { StdioDownstreamExecutor, type DownstreamServerConfig } from "../src/server/downstream";

const executors: StdioDownstreamExecutor[] = [];
afterEach(async () => {
  await Promise.all(executors.splice(0).map((executor) => executor.close()));
});

describe("stdio downstream MCP boundary", () => {
  it("calls only a tool actually advertised by the configured server", async () => {
    const executor = new StdioDownstreamExecutor();
    executors.push(executor);
    const server: DownstreamServerConfig = {
      id: "fixture",
      command: process.execPath,
      args: [resolve("tests/fixtures/mock-mcp.mjs")],
      inheritEnv: [],
      tools: {
        write_report: {
          capability: "file_write",
          operation: "write fixture report",
          target: "test fixture",
          maxArgumentBytes: 1_000,
        },
      },
    };
    const output = await executor.call(server, "write_report", { text: "reviewed" });
    expect(JSON.stringify(output)).toContain('\\"accepted\\":true');
    await expect(executor.call(server, "not_advertised", {})).rejects.toThrow(/not advertised/);
  });
});
