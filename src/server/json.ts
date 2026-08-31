import { createHash } from "node:crypto";

function normalize(value: unknown, seen: Set<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JSON values must contain only finite numbers");
    return value;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("Circular JSON value");
    seen.add(value);
    const result = value.map((item) => normalize(item, seen));
    seen.delete(value);
    return result;
  }
  if (typeof value === "object") {
    if (seen.has(value)) throw new Error("Circular JSON value");
    seen.add(value);
    const object = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(object).sort()) {
      if (key === "__proto__" || key === "prototype" || key === "constructor") {
        throw new Error("Unsafe JSON property name");
      }
      const item = object[key];
      if (item === undefined || typeof item === "function" || typeof item === "symbol") {
        throw new Error("Unsupported JSON value");
      }
      result[key] = normalize(item, seen);
    }
    seen.delete(value);
    return result;
  }
  throw new Error("Unsupported JSON value");
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value, new Set()));
}

export function jsonHash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}
