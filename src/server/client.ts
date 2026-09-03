import JSONbigFactory from "json-bigint";
import { z } from "zod";
import { isValidRoom } from "./protocol";
import type { RoomRead, TechnocoreMessage } from "./types";

const JSONbig = JSONbigFactory({ storeAsString: true, strict: true });
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_EXPORT_BYTES = 12 * 1024 * 1024;
const MAX_EXPORT_LINE_BYTES = 16 * 1024;
const numericString = z.union([z.string(), z.number()]).transform(String).pipe(z.string().regex(/^\d{1,24}$/));

const messageSchema = z.object({
  seq: numericString,
  ts: z.string().min(1).max(80),
  from: z.string().min(1).max(180),
  text: z.string().min(1).max(4_096),
  nonce: z.union([z.string(), z.number()]).transform(String).pipe(z.string().regex(/^\d{1,19}$/)).optional(),
  sig: z.string().regex(/^[A-Za-z0-9_-]{85}[AQgw]$/).optional(),
}).strict();

const roomReadSchema = z.object({
  room: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,47}$/),
  count: z.number().int().min(0).max(200),
  first_seq: numericString,
  last_seq: numericString,
  generation: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
  messages: z.array(z.unknown()).max(200),
}).strict();

export function parseRoomRead(raw: string): RoomRead {
  const envelope = roomReadSchema.parse(JSONbig.parse(raw));
  if (envelope.count !== envelope.messages.length) {
    throw new Error("Technocore response count does not match its message window");
  }
  const messages: TechnocoreMessage[] = [];
  for (const record of envelope.messages) {
    const parsed = messageSchema.safeParse(record);
    if (parsed.success) messages.push(parsed.data);
  }
  return { ...envelope, messages, rejectedCount: envelope.count - messages.length };
}

export interface SequenceLookup {
  message: TechnocoreMessage | null;
  firstSeq: string | null;
  lastSeq: string | null;
  scannedBytes: number;
}

export class TechnocoreClient {
  readonly origin: string;

  constructor(origin = "https://technocore.chat") {
    const parsed = new URL(origin);
    const official = parsed.origin === "https://technocore.chat";
    const local = ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname) &&
      (parsed.protocol === "http:" || parsed.protocol === "https:");
    if ((!official && !local) || parsed.username || parsed.password) {
      throw new Error("Technocore origin must be the official service or a loopback development origin");
    }
    this.origin = parsed.origin;
  }

  async readRoom(room: string, limit = 50): Promise<RoomRead> {
    if (!isValidRoom(room)) throw new Error("Invalid room name");
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
      throw new Error("Limit must be an integer from 1 to 200");
    }
    const url = new URL(`/r/${room}`, this.origin);
    url.searchParams.set("format", "json");
    url.searchParams.set("limit", String(limit));
    const read = parseRoomRead(await this.safeFetch(url));
    if (read.room !== room) throw new Error("Technocore response room does not match the requested room");
    return read;
  }

  async findMessageBySequence(room: string, sequence: string): Promise<SequenceLookup> {
    if (!isValidRoom(room)) throw new Error("Invalid room name");
    if (!/^\d{1,24}$/.test(sequence)) throw new Error("Invalid message sequence");

    const url = new URL(`/r/${room}/export`, this.origin);
    const response = await this.request(url, "application/x-ndjson, application/json");
    const reader = response.body?.getReader();
    if (!reader) return { message: null, firstSeq: null, lastSeq: null, scannedBytes: 0 };

    const decoder = new TextDecoder();
    let buffer = "";
    let scannedBytes = 0;
    let firstSeq: string | null = null;
    let lastSeq: string | null = null;

    const inspectLine = (line: string): TechnocoreMessage | null => {
      if (!line.trim()) return null;
      if (new TextEncoder().encode(line).byteLength > MAX_EXPORT_LINE_BYTES) {
        throw new Error("Technocore export contained an oversized record");
      }
      const message = messageSchema.parse(JSONbig.parse(line)) as TechnocoreMessage;
      firstSeq ??= message.seq;
      lastSeq = message.seq;
      return message.seq === sequence ? message : null;
    };

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        scannedBytes += value.byteLength;
        if (scannedBytes > MAX_EXPORT_BYTES) {
          throw new Error("Technocore export exceeded the 12 MiB safety limit");
        }
        buffer += decoder.decode(value, { stream: true });
        let newline = buffer.indexOf("\n");
        while (newline !== -1) {
          const match = inspectLine(buffer.slice(0, newline).replace(/\r$/, ""));
          buffer = buffer.slice(newline + 1);
          if (match) {
            await reader.cancel();
            return { message: match, firstSeq, lastSeq, scannedBytes };
          }
          newline = buffer.indexOf("\n");
        }
        if (new TextEncoder().encode(buffer).byteLength > MAX_EXPORT_LINE_BYTES) {
          throw new Error("Technocore export contained an oversized record");
        }
      }
      buffer += decoder.decode();
      const match = inspectLine(buffer.replace(/\r$/, ""));
      return { message: match, firstSeq, lastSeq, scannedBytes };
    } catch (error) {
      await reader.cancel().catch(() => undefined);
      throw error;
    }
  }

  async capabilities(): Promise<{
    origin: string;
    exportEndpointAdvertised: boolean;
    signaturesVisibleOnRead: boolean;
    writeMode: "disabled";
  }> {
    const url = new URL("/openapi.json", this.origin);
    const openApi = JSON.parse(await this.safeFetch(url)) as { paths?: Record<string, unknown> };
    const paths = Object.keys(openApi.paths ?? {});
    return {
      origin: this.origin,
      exportEndpointAdvertised: paths.some((path) => path.includes("/export")),
      signaturesVisibleOnRead: false,
      writeMode: "disabled",
    };
  }

  private async safeFetch(url: URL): Promise<string> {
    const response = await this.request(url, "application/json");
    const reader = response.body?.getReader();
    if (!reader) return "";
    const decoder = new TextDecoder();
    let total = 0;
    let body = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Technocore response exceeded the 512 KiB safety limit");
      }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
    return body;
  }

  private async request(url: URL, accept: string): Promise<Response> {
    if (url.origin !== this.origin) throw new Error("Cross-origin fetch denied");
    let response: Response | null = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        headers: { accept },
        signal: AbortSignal.timeout(15_000),
      });
      if (![502, 503, 504].includes(response.status) || attempt === 2) break;
      await response.body?.cancel();
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 250 * (attempt + 1)));
    }
    if (!response) throw new Error("Technocore request did not start");
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new Error(`Redirect denied (${response.status})`);
    }
    if (!response.ok) {
      // Error bodies are untrusted; never echo them into agent tool results.
      await response.body?.cancel();
      throw new Error(`Technocore responded ${response.status}`);
    }
    return response;
  }
}

export function sortMessages(messages: TechnocoreMessage[]): TechnocoreMessage[] {
  return [...messages].sort((left, right) => {
    const leftSeq = BigInt(left.seq);
    const rightSeq = BigInt(right.seq);
    return leftSeq < rightSeq ? -1 : leftSeq > rightSeq ? 1 : 0;
  });
}
