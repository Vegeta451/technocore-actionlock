import { readFile } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";
import type { GatewayToolPolicy } from "./types";

const capabilitySchema = z.enum([
  "observe",
  "network_read",
  "network_write",
  "file_read",
  "file_write",
  "shell",
  "wallet",
  "social",
]);

const toolPolicySchema = z.object({
  capability: capabilitySchema,
  operation: z.string().min(1).max(160),
  target: z.string().min(1).max(500),
  maxArgumentBytes: z.number().int().min(2).max(64_000).default(16_000),
});

const serverSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,47}$/),
  command: z.string().min(1).max(500),
  args: z.array(z.string().max(1_000)).max(64).default([]),
  cwd: z.string().min(1).max(1_000).optional(),
  inheritEnv: z.array(z.string().regex(/^[A-Z_][A-Z0-9_]*$/)).max(32).default([]),
  tools: z.record(z.string().min(1).max(128), toolPolicySchema),
});

const configSchema = z.object({
  version: z.literal(1),
  servers: z.array(serverSchema).max(16),
});

export type DownstreamServerConfig = z.infer<typeof serverSchema>;
export type GatewayConfig = z.infer<typeof configSchema>;

export const EMPTY_GATEWAY_CONFIG: GatewayConfig = { version: 1, servers: [] };

export async function loadGatewayConfig(path: string): Promise<GatewayConfig> {
  const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
  const config = configSchema.parse(raw);
  const ids = new Set<string>();
  for (const server of config.servers) {
    if (ids.has(server.id)) throw new Error(`Duplicate downstream server id: ${server.id}`);
    ids.add(server.id);
  }
  return config;
}

export function listToolPolicies(config: GatewayConfig): Array<{
  server: string;
  tool: string;
  policy: GatewayToolPolicy;
}> {
  return config.servers.flatMap((server) =>
    Object.entries(server.tools).map(([tool, policy]) => ({ server: server.id, tool, policy })),
  );
}

export function resolveToolPolicy(
  config: GatewayConfig,
  serverId: string,
  toolName: string,
): { server: DownstreamServerConfig; policy: GatewayToolPolicy } | null {
  const server = config.servers.find((candidate) => candidate.id === serverId);
  const policy = server?.tools[toolName];
  return server && policy ? { server, policy } : null;
}

export interface DownstreamExecutor {
  call(server: DownstreamServerConfig, tool: string, argumentsValue: Record<string, unknown>): Promise<unknown>;
  close?(): Promise<void>;
}

interface ConnectedServer {
  client: Client;
  transport: StdioClientTransport;
  tools: Set<string>;
}

export class StdioDownstreamExecutor implements DownstreamExecutor {
  private readonly connections = new Map<string, Promise<ConnectedServer>>();

  private connect(server: DownstreamServerConfig): Promise<ConnectedServer> {
    const current = this.connections.get(server.id);
    if (current) return current;
    const connection = (async () => {
      const env = getDefaultEnvironment();
      for (const name of server.inheritEnv) {
        const value = process.env[name];
        if (value !== undefined) env[name] = value;
      }
      const transport = new StdioClientTransport({
        command: server.command,
        args: server.args,
        cwd: server.cwd,
        env,
        stderr: "inherit",
        maxBufferSize: 2 * 1024 * 1024,
      });
      const client = new Client({ name: `actionlock-${server.id}`, version: "0.2.0" });
      await client.connect(transport);
      const advertised = await client.listTools();
      return { client, transport, tools: new Set(advertised.tools.map((tool) => tool.name)) };
    })();
    this.connections.set(server.id, connection);
    connection.catch(() => this.connections.delete(server.id));
    return connection;
  }

  async call(
    server: DownstreamServerConfig,
    tool: string,
    argumentsValue: Record<string, unknown>,
  ): Promise<unknown> {
    const connection = await this.connect(server);
    if (!connection.tools.has(tool)) {
      throw new Error(`Configured tool ${server.id}/${tool} is not advertised by the downstream server`);
    }
    return connection.client.callTool({ name: tool, arguments: argumentsValue });
  }

  async close(): Promise<void> {
    const connections = await Promise.allSettled(this.connections.values());
    await Promise.all(
      connections
        .filter((result): result is PromiseFulfilledResult<ConnectedServer> => result.status === "fulfilled")
        .map((result) => result.value.transport.close().catch(() => undefined)),
    );
    this.connections.clear();
  }
}
