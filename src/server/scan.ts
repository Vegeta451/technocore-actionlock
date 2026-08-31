import { TechnocoreClient } from "./client";
import { analyzeText } from "./policy";
import { classifyVerification, provenanceHash } from "./protocol";
import type { ScanEvent } from "./types";

export async function scanRoom(input: {
  room: string;
  limit?: number;
  origin?: string;
}): Promise<{ room: string; scannedAt: string; events: ScanEvent[] }> {
  const client = new TechnocoreClient(input.origin);
  const read = await client.readRoom(input.room, input.limit ?? 25);
  return {
    room: read.room,
    scannedAt: new Date().toISOString(),
    events: read.messages.map((message) => ({
      message,
      provenance: {
        source: "technocore",
        trust: "untrusted_remote",
        room: read.room,
        seq: message.seq,
        sender: message.from,
        contentHash: provenanceHash({
          room: read.room,
          seq: message.seq,
          sender: message.from,
          text: message.text,
        }),
        verification: classifyVerification(read.room, message),
      },
      risk: analyzeText(message.text, client.origin),
    })),
  };
}
