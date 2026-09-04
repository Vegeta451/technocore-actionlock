import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalJson, jsonHash } from "../src/server/json";
import { RECEIPT_CANONICALIZATION } from "../src/server/public-receipt";

const fixture = JSON.parse(readFileSync(new URL("../public/conformance/canonical-json-v1.json", import.meta.url), "utf8")) as {
  profile: string;
  vectors: { name: string; input: unknown; canonical: string; utf8Hex: string; sha256: string }[];
};

describe("published canonical JSON v1 conformance vectors", () => {
  it("pins the receipt canonicalization profile", () => {
    expect(fixture.profile).toBe(RECEIPT_CANONICALIZATION);
  });

  for (const vector of fixture.vectors) {
    it(vector.name, () => {
      expect(canonicalJson(vector.input)).toBe(vector.canonical);
      expect(Buffer.from(vector.canonical, "utf8").toString("hex")).toBe(vector.utf8Hex);
      expect(createHash("sha256").update(Buffer.from(vector.utf8Hex, "hex")).digest("hex")).toBe(vector.sha256);
      expect(jsonHash(vector.input)).toBe(vector.sha256);
    });
  }

  it.each([NaN, Infinity, -Infinity, 1n, undefined, () => 1, Symbol("test")])("rejects unsupported scalar %#", (value) => {
    expect(() => canonicalJson(value)).toThrow();
    expect(() => canonicalJson({ value })).toThrow();
  });

  it.each(["__proto__", "prototype", "constructor"])("rejects unsafe property %s", (name) => {
    expect(() => canonicalJson(JSON.parse(`{"${name}":1}`))).toThrow("Unsafe JSON property name");
  });

  it("rejects cycles without rejecting repeated non-cyclic references", () => {
    const cycle: unknown[] = [];
    cycle.push(cycle);
    expect(() => canonicalJson(cycle)).toThrow("Circular JSON value");
    const shared = { a: 1 };
    expect(canonicalJson([shared, shared])).toBe('[{"a":1},{"a":1}]');
  });
});
