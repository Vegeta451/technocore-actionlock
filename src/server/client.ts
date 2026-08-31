import JSONbigFactory from "json-bigint";
import { z } from "zod";
import { isValidRoom } from "./protocol";
import type { RoomRead, TechnocoreMessage } from "./types";

const JSONbig = JSONbigFactory({ storeAsString: true, strict: true });
const MAX_RESPONSE_BYTES = 512 * 1024;
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
  messages: z.array(messageSchema).max(200),
}).strict();

export function parseRoomRead(raw: string): RoomRead {
  return roomReadSchema.parse(JSONbig.parse(raw)) as RoomRead;
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
    const boundedLimit = Math.min(Math.max(limit, 1), 200);
    const url = new URL(`/r/${room}`, this.origin);
    url.searchParams.set("format", "json");
    url.searchParams.set("limit", String(boundedLimit));
    return parseRoomRead(await this.safeFetch(url));
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
    if (url.origin !== this.origin) throw new Error("Cross-origin fetch denied");
    let response: Response | null = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
      if (![502, 503, 504].includes(response.status) || attempt === 2) break;
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 250 * (attempt + 1)));
    }
    if (!response) throw new Error("Technocore request did not start");
    if (response.status >= 300 && response.status < 400) {
      throw new Error(`Redirect denied (${response.status})`);
    }
    if (!response.ok) {
      const detail = (await response.text()).slice(0, 240).replace(/\s+/g, " ");
      throw new Error(`Technocore responded ${response.status}: ${detail}`);
    }
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
}

export function sortMessages(messages: TechnocoreMessage[]): TechnocoreMessage[] {
  return [...messages].sort((left, right) => {
    const leftSeq = BigInt(left.seq);
    const rightSeq = BigInt(right.seq);
    return leftSeq < rightSeq ? -1 : leftSeq > rightSeq ? 1 : 0;
  });
}
