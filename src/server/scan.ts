import { TechnocoreClient } from "./client";
import { analyzeText } from "./policy";
import { classifyVerification, provenanceHash } from "./protocol";
import type { ScanEvent } from "./types";

function eventFor(room: string, message: ScanEvent["message"], origin: string): ScanEvent {
  return {
    message,
    provenance: {
      source: "technocore",
      trust: "untrusted_remote",
      room,
      seq: message.seq,
      sender: message.from,
      contentHash: provenanceHash({ room, seq: message.seq, sender: message.from, text: message.text }),
      verification: classifyVerification(room, message),
    },
    risk: analyzeText(message.text, origin),
  };
}

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
    events: read.messages.map((message) => eventFor(read.room, message, client.origin)),
  };
}

export async function lookupRoomSequence(input: {
  room: string;
  sequence: string;
  origin?: string;
}): Promise<{
  room: string;
  sequence: string;
  status: "found" | "not_retained" | "not_found";
  retainedRange: { first: string; last: string } | null;
  scannedBytes: number;
  source: "export";
  event: ScanEvent | null;
}> {
  const client = new TechnocoreClient(input.origin);
  const lookup = await client.findMessageBySequence(input.room, input.sequence);
  const retainedRange = lookup.firstSeq && lookup.lastSeq
    ? { first: lookup.firstSeq, last: lookup.lastSeq }
    : null;
  let status: "found" | "not_retained" | "not_found" = "not_found";
  if (lookup.message) status = "found";
  else if (lookup.firstSeq && BigInt(input.sequence) < BigInt(lookup.firstSeq)) status = "not_retained";

  return {
    room: input.room,
    sequence: input.sequence,
    status,
    retainedRange,
    scannedBytes: lookup.scannedBytes,
    source: "export",
    event: lookup.message ? eventFor(input.room, lookup.message, client.origin) : null,
  };
}
