import { z } from "zod";
import { evaluateCapability } from "@/server/capability";
import { jsonHash } from "@/server/json";
import { readBoundedJson, RequestBodyTooLargeError } from "@/server/http";
import { analyzeText } from "@/server/policy";
import { provenanceHash } from "@/server/protocol";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
const MAX_REQUEST_BYTES = 12_000;

const schema = z.object({
  room: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,47}$/),
  seq: z.string().regex(/^\d{1,24}$/),
  sender: z.string().min(1).max(180),
  text: z.string().min(1).max(8_000),
  verification: z.enum(["verified", "invalid", "server_signed_lane", "unsigned", "not_available"]),
  action: z.object({
    capability: z.enum([
      "observe",
      "network_read",
      "network_write",
      "file_read",
      "file_write",
      "shell",
      "wallet",
      "social",
    ]),
    operation: z.string().min(1).max(160),
    target: z.string().max(500).optional(),
    reversible: z.boolean().optional(),
  }),
});

export async function POST(request: Request): Promise<Response> {
  let raw: unknown;
  try {
    raw = await readBoundedJson(request, MAX_REQUEST_BYTES);
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) {
      return Response.json({ error: "Request body is too large" }, { status: 413 });
    }
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    return Response.json({ error: "Invalid evaluation request" }, { status: 400 });
  }

  const value = parsed.data;
  const contentHash = provenanceHash({
    room: value.room,
    seq: value.seq,
    sender: value.sender,
    text: value.text,
  });
  const risk = analyzeText(value.text);
  const decision = evaluateCapability({
    action: {
      ...value.action,
      boundary: "downstream",
      argumentsHash: jsonHash({ capability: value.action.capability, target: value.action.target ?? null }),
    },
    provenance: {
      source: "technocore",
      trust: "untrusted_remote",
      room: value.room,
      seq: value.seq,
      sender: value.sender,
      contentHash,
      verification: value.verification,
    },
    risk,
  });

  return Response.json({ risk, decision });
}
