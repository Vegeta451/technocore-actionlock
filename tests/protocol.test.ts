import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalMessage, sweepSingleLine, verifySignedMessage } from "../src/server/protocol";
import { parseRoomRead } from "../src/server/client";
import { TechnocoreClient } from "../src/server/client";

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(value: Buffer): string {
  let number = BigInt(`0x${value.toString("hex")}`);
  let output = "";
  while (number > 0n) {
    const remainder = Number(number % 58n);
    output = alphabet[remainder] + output;
    number /= 58n;
  }
  for (const byte of value) {
    if (byte !== 0) break;
    output = `1${output}`;
  }
  return output;
}

describe("Technocore protocol handling", () => {
  it("accepts independent RFC 8032-backed Technocore conformance vectors", () => {
    // Source: techbone/technocore-conformance vectors/message-signing.json (MIT), 2026-08-31.
    const vectors = [
      {
        did: "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
        room: "lobby",
        nonce: "1",
        text: "hello",
        payloadHex: "6c6f6262797c317c68656c6c6f",
        signature: "27I8Pb0K7f5AxWlYEE1m0UeNdj4Ko9dcOp_DVHmNFjKbKsAJ2Fw0O4afLqiQdu9kV9OYQcUp7Y-dUb-tKUaKAQ",
      },
      {
        did: "did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT",
        room: "technocore",
        nonce: "1700000000000000000",
        text: "I published a contribution.",
        payloadHex: "746563686e6f636f72657c313730303030303030303030303030303030307c49207075626c6973686564206120636f6e747269627574696f6e2e",
        signature: "fNdSBCyA4EVSCgGXeTb3e8fpN2KYYurSxH0lvqjSfkd8bjWo9llAga0UhlislA6TCJcKvs08n2e9ViZJX1pSBg",
      },
    ];
    for (const vector of vectors) {
      expect(Buffer.from(canonicalMessage(vector.room, vector.nonce, vector.text)).toString("hex")).toBe(
        vector.payloadHex,
      );
      expect(
        verifySignedMessage({
          room: vector.room,
          did: vector.did,
          nonce: vector.nonce,
          text: vector.text,
          signature: vector.signature,
        }),
      ).toBe(true);
    }
  });

  it("verifies an Ed25519 did:key signature over the canonical message", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const did = `did:key:z${base58(Buffer.concat([Buffer.from([0xed, 0x01]), der.subarray(-32)]))}`;
    const signature = sign(null, Buffer.from(canonicalMessage("lobby", "42", "hello")), privateKey).toString("base64url");
    expect(verifySignedMessage({ room: "lobby", did, nonce: "42", text: "hello", signature })).toBe(true);
    expect(verifySignedMessage({ room: "lobby", did, nonce: "42", text: "changed", signature })).toBe(false);
    const nonCanonical = `${signature.slice(0, -1)}B`;
    expect(verifySignedMessage({ room: "lobby", did, nonce: "42", text: "hello", signature: nonCanonical })).toBe(false);
  });

  it("matches the server single-line sweep boundary", () => {
    expect(sweepSingleLine("  one\r\ntwo  ")).toBe("one  two");
    expect(sweepSingleLine("a\u00a0b")).toBe("a\u00a0b");
    expect(sweepSingleLine("👨‍👩‍👧")).toBe("👨 👩 👧");
  });

  it("preserves nonce and sequence values beyond JavaScript safe integers", () => {
    const parsed = parseRoomRead(
      '{"room":"lobby","count":1,"first_seq":90071992547409931,"last_seq":90071992547409931,"messages":[{"seq":90071992547409931,"ts":"2026-08-31T00:00:00Z","from":"did:key:ztest","text":"hello","nonce":9007199254740993123}]}',
    );
    expect(parsed.first_seq).toBe("90071992547409931");
    expect(parsed.messages[0].nonce).toBe("9007199254740993123");
  });

  it("accepts the bounded room generation returned by the live protocol", () => {
    const parsed = parseRoomRead(
      '{"room":"lobby","count":0,"first_seq":0,"last_seq":0,"generation":0,"messages":[]}',
    );
    expect(parsed.generation).toBe(0);
    expect(() => parseRoomRead(
      '{"room":"lobby","count":0,"first_seq":0,"last_seq":0,"generation":-1,"messages":[]}',
    )).toThrow();
  });

  it("pins production reads to the official origin", () => {
    expect(() => new TechnocoreClient("https://example.com")).toThrow(/official service/);
    expect(() => new TechnocoreClient("https://technocore.chat.evil.example")).toThrow(/official service/);
    expect(new TechnocoreClient("https://technocore.chat").origin).toBe("https://technocore.chat");
    expect(new TechnocoreClient("http://127.0.0.1:8080").origin).toBe("http://127.0.0.1:8080");
  });
});
