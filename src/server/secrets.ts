import { createHmac } from "node:crypto";

export function assertRootSecret(secret: string | undefined): string {
  if (!secret || Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("ACTIONLOCK_ROOT_SECRET must contain at least 32 bytes");
  }
  return secret;
}

export function deriveSecret(rootSecret: string, purpose: "approval" | "audit" | "evidence"): string {
  return createHmac("sha256", assertRootSecret(rootSecret))
    .update(`actionlock:${purpose}:v1`, "utf8")
    .digest("base64url");
}
