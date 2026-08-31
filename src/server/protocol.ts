import { createHash, createPublicKey, verify } from "node:crypto";
import type { TechnocoreMessage, VerificationState } from "./types";

const ROOM_PATTERN = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const DID_PREFIX = "did:key:z";
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const CANONICAL_SIGNATURE = /^[A-Za-z0-9_-]{85}[AQgw]$/;

export function isValidRoom(room: string): boolean {
  return ROOM_PATTERN.test(room);
}

export function sweepSingleLine(value: string): string {
  return value.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu, " ").trim();
}

export function canonicalMessage(room: string, nonce: string, text: string): string {
  if (!isValidRoom(room)) {
    throw new Error("Invalid Technocore room name");
  }
  if (!/^\d{1,19}$/.test(nonce)) {
    throw new Error("Nonce must contain 1-19 ASCII digits");
  }
  return `${room}|${nonce}|${sweepSingleLine(text)}`;
}

function decodeBase58(value: string): Buffer {
  if (!value) return Buffer.alloc(0);
  let accumulator = 0n;
  for (const char of value) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index < 0) throw new Error("Invalid base58 character");
    accumulator = accumulator * 58n + BigInt(index);
  }

  let hex = accumulator.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const body = accumulator === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  const leadingZeroes = value.match(/^1+/)?.[0].length ?? 0;
  return Buffer.concat([Buffer.alloc(leadingZeroes), body]);
}

export function didToEd25519PublicKey(did: string): Buffer {
  if (!did.startsWith(DID_PREFIX)) throw new Error("Only base58btc did:key is supported");
  const decoded = decodeBase58(did.slice(DID_PREFIX.length));
  if (decoded.length !== 34 || !decoded.subarray(0, 2).equals(ED25519_MULTICODEC)) {
    throw new Error("DID is not an Ed25519 did:key");
  }
  return decoded.subarray(2);
}

export function verifySignedMessage(input: {
  room: string;
  did: string;
  nonce: string;
  text: string;
  signature: string;
}): boolean {
  if (!CANONICAL_SIGNATURE.test(input.signature)) return false;
  const rawKey = didToEd25519PublicKey(input.did);
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]),
    format: "der",
    type: "spki",
  });
  const signature = Buffer.from(input.signature, "base64url");
  if (signature.length !== 64) return false;
  return verify(
    null,
    Buffer.from(canonicalMessage(input.room, input.nonce, input.text), "utf8"),
    key,
    signature,
  );
}

export function classifyVerification(room: string, message: TechnocoreMessage): VerificationState {
  const isDid = message.from.startsWith("did:key:");
  if (!isDid) return "unsigned";
  if (!message.sig || !message.nonce) return "server_signed_lane";
  try {
    return verifySignedMessage({
      room,
      did: message.from,
      nonce: message.nonce,
      text: message.text,
      signature: message.sig,
    })
      ? "verified"
      : "invalid";
  } catch {
    return "invalid";
  }
}

export function hashMessage(room: string, message: TechnocoreMessage): string {
  const canonical = JSON.stringify({
    room,
    seq: message.seq,
    ts: message.ts,
    from: message.from,
    nonce: message.nonce ?? null,
    text: message.text,
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export function provenanceHash(input: {
  room: string;
  seq: string;
  sender: string;
  text: string;
}): string {
  return createHash("sha256")
    .update(JSON.stringify(input))
    .digest("hex");
}
