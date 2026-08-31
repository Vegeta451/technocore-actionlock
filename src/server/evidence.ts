import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { provenanceHash } from "./protocol";
import type { EvidenceClaims, ScanEvent } from "./types";

const MAX_TTL_SECONDS = 900;
const CLOCK_SKEW_SECONDS = 30;
const verificationSchema = z.enum([
  "verified",
  "invalid",
  "server_signed_lane",
  "unsigned",
  "not_available",
]);

const claimsSchema = z.object({
  version: z.literal(1),
  issuer: z.literal("actionlock"),
  audience: z.literal("actionlock-gateway"),
  issuedAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().positive(),
  evidenceId: z.string().regex(/^[a-f0-9]{32}$/),
  event: z.object({
    room: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,47}$/),
    seq: z.string().regex(/^\d{1,24}$/),
    ts: z.string().min(1).max(80),
    sender: z.string().min(1).max(180),
    text: z.string().min(1).max(8_000),
    verification: verificationSchema,
    contentHash: z.string().regex(/^[a-f0-9]{64}$/),
  }),
});

function encode(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function signature(payload: string, secret: string): string {
  return createHmac("sha256", secret)
    .update("actionlock:evidence:v1\n", "utf8")
    .update(payload, "utf8")
    .digest("base64url");
}

export function issueEvidenceReceipt(input: {
  event: ScanEvent;
  secret: string;
  ttlSeconds?: number;
  nowSeconds?: number;
}): { evidenceId: string; token: string; expiresAt: number } {
  if (Buffer.byteLength(input.secret, "utf8") < 32) throw new Error("Evidence secret is too short");
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const ttl = Math.min(Math.max(input.ttlSeconds ?? 600, 1), MAX_TTL_SECONDS);
  const evidenceId = randomBytes(16).toString("hex");
  const claims: EvidenceClaims = {
    version: 1,
    issuer: "actionlock",
    audience: "actionlock-gateway",
    issuedAt: now,
    expiresAt: now + ttl,
    evidenceId,
    event: {
      room: input.event.provenance.room!,
      seq: input.event.provenance.seq!,
      ts: input.event.message.ts,
      sender: input.event.provenance.sender!,
      text: input.event.message.text,
      verification: input.event.provenance.verification,
      contentHash: input.event.provenance.contentHash,
    },
  };
  const payload = encode(JSON.stringify(claims));
  return { evidenceId, token: `${payload}.${signature(payload, input.secret)}`, expiresAt: claims.expiresAt };
}

export function verifyEvidenceReceipt(input: {
  token: string;
  secret: string;
  nowSeconds?: number;
}): EvidenceClaims | null {
  const [payload, suppliedSignature, extra] = input.token.split(".");
  if (!payload || !suppliedSignature || extra) return null;
  const expected = Buffer.from(signature(payload, input.secret), "utf8");
  const actual = Buffer.from(suppliedSignature, "utf8");
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;

  try {
    const raw = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as unknown;
    const claims = claimsSchema.parse(raw) as EvidenceClaims;
    const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
    if (claims.issuedAt > now + CLOCK_SKEW_SECONDS) return null;
    if (
      claims.expiresAt < now ||
      claims.expiresAt <= claims.issuedAt ||
      claims.expiresAt - claims.issuedAt > MAX_TTL_SECONDS
    ) return null;
    const expectedHash = provenanceHash({
      room: claims.event.room,
      seq: claims.event.seq,
      sender: claims.event.sender,
      text: claims.event.text,
    });
    return expectedHash === claims.event.contentHash ? claims : null;
  } catch {
    return null;
  }
}
