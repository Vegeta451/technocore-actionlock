import { createHash, createPublicKey, verify } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { z } from "zod";
import { canonicalJson, jsonHash } from "./json";
import { KEY_TRANSITION_DOMAIN, loadReceiptSigner, RECEIPT_CANONICALIZATION, type PublicReceiptSigner } from "./public-receipt";

const canonicalBase64 = (length: number) => z.string().regex(new RegExp(`^[A-Za-z0-9_-]{${length}}$`))
  .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value);
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const identitySchema = z.object({
  algorithm: z.literal("Ed25519"),
  keyId: hashSchema,
  publicKey: canonicalBase64(59),
}).strict();
const statementSchema = z.object({
  version: z.literal(1),
  issuer: z.literal("actionlock"),
  purpose: z.literal("planned-receipt-key-transition"),
  canonicalization: z.literal(RECEIPT_CANONICALIZATION),
  declaredAt: z.string().datetime(),
  previous: identitySchema,
  next: identitySchema,
}).strict();
const transitionSchema = z.object({
  statement: statementSchema,
  signatures: z.object({ previous: canonicalBase64(86), next: canonicalBase64(86) }).strict(),
}).strict();

export type KeyTransitionStatement = z.infer<typeof statementSchema>;
export type KeyTransition = z.infer<typeof transitionSchema>;

function identity(signer: PublicReceiptSigner): KeyTransitionStatement["previous"] {
  return { algorithm: "Ed25519", keyId: signer.keyId, publicKey: signer.publicKey };
}

export function createKeyTransition(previous: PublicReceiptSigner, next: PublicReceiptSigner, now = new Date()): KeyTransition {
  if (previous.keyId === next.keyId) throw new Error("Key transition requires two distinct keys");
  const statement = statementSchema.parse({
    version: 1, issuer: "actionlock", purpose: "planned-receipt-key-transition",
    canonicalization: RECEIPT_CANONICALIZATION, declaredAt: now.toISOString(),
    previous: identity(previous), next: identity(next),
  });
  const transition = { statement, signatures: {
    previous: previous.signKeyTransition(statement), next: next.signKeyTransition(statement),
  } };
  if (!verifyKeyTransition(transition, previous.keyId).valid) throw new Error("Key transition self-check failed");
  return transition;
}

export function verifyKeyTransition(value: unknown, expectedPreviousKeyId: string): {
  valid: boolean; previousKeyId: string | null; nextKeyId: string | null; transitionHash: string | null;
} {
  const invalid = { valid: false, previousKeyId: null, nextKeyId: null, transitionHash: null };
  try {
    if (!hashSchema.safeParse(expectedPreviousKeyId).success) return invalid;
    const parsed = transitionSchema.safeParse(value);
    if (!parsed.success) return invalid;
    const { statement, signatures } = parsed.data;
    if (statement.previous.keyId !== expectedPreviousKeyId || statement.previous.keyId === statement.next.keyId) return invalid;
    const bytes = Buffer.from(`${KEY_TRANSITION_DOMAIN}${canonicalJson(statement)}`, "utf8");
    for (const role of ["previous", "next"] as const) {
      const key = statement[role];
      const der = Buffer.from(key.publicKey, "base64url");
      if (createHash("sha256").update(der).digest("hex") !== key.keyId) return invalid;
      const publicKey = createPublicKey({ key: der, format: "der", type: "spki" });
      if (publicKey.asymmetricKeyType !== "ed25519" || publicKey.export({ format: "der", type: "spki" }).toString("base64url") !== key.publicKey) return invalid;
      if (!verify(null, bytes, publicKey, Buffer.from(signatures[role], "base64url"))) return invalid;
    }
    return { valid: true, previousKeyId: statement.previous.keyId, nextKeyId: statement.next.keyId, transitionHash: jsonHash(parsed.data) };
  } catch {
    return invalid;
  }
}

export async function prepareKeyTransition(previousPath: string, nextPath: string, outputPath: string): Promise<KeyTransition> {
  // Missing input keys must never silently create a new identity.
  const previous = await loadReceiptSigner(previousPath);
  const next = await loadReceiptSigner(nextPath);
  const transition = createKeyTransition(previous, next);
  await writeFile(outputPath, `${canonicalJson(transition)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  return transition;
}
