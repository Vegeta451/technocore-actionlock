import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface GrantPayload {
  version: 1;
  issuer: "actionlock";
  audience: "actionlock-gateway";
  actionHash: string;
  issuedAt: number;
  expiresAt: number;
  grantId: string;
}

const MAX_TTL_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 30;

function encode(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function sign(payload: string, secret: string): string {
  return createHmac("sha256", secret)
    .update("actionlock:approval:v1\n", "utf8")
    .update(payload, "utf8")
    .digest("base64url");
}

export function issueApprovalGrant(input: {
  actionHash: string;
  secret: string;
  ttlSeconds?: number;
  nowSeconds?: number;
}): string {
  if (Buffer.byteLength(input.secret) < 32) throw new Error("Approval secret must be at least 32 bytes");
  if (!/^[a-f0-9]{64}$/.test(input.actionHash)) throw new Error("Invalid action hash");
  const ttlSeconds = Math.min(Math.max(input.ttlSeconds ?? 120, 1), MAX_TTL_SECONDS);
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const payload = encode(
    JSON.stringify({
      version: 1,
      issuer: "actionlock",
      audience: "actionlock-gateway",
      actionHash: input.actionHash,
      issuedAt: now,
      expiresAt: now + ttlSeconds,
      grantId: randomBytes(16).toString("hex"),
    } satisfies GrantPayload),
  );
  return `${payload}.${sign(payload, input.secret)}`;
}

export function verifyApprovalGrant(input: {
  token: string;
  actionHash: string;
  secret: string;
  nowSeconds?: number;
}): GrantPayload | null {
  const [payload, signature, extra] = input.token.split(".");
  if (!payload || !signature || extra) return null;
  const expected = Buffer.from(sign(payload, input.secret));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;

  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as GrantPayload;
    const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
    const valid =
      parsed.version === 1 &&
      parsed.issuer === "actionlock" &&
      parsed.audience === "actionlock-gateway" &&
      parsed.actionHash === input.actionHash &&
      /^[a-f0-9]{32}$/.test(parsed.grantId) &&
      Number.isInteger(parsed.issuedAt) &&
      Number.isInteger(parsed.expiresAt) &&
      parsed.issuedAt <= now + CLOCK_SKEW_SECONDS &&
      parsed.expiresAt >= now &&
      parsed.expiresAt > parsed.issuedAt &&
      parsed.expiresAt - parsed.issuedAt <= MAX_TTL_SECONDS;
    return valid ? parsed : null;
  } catch {
    return null;
  }
}
