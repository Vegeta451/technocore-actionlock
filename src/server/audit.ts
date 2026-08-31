import { createHmac, randomBytes } from "node:crypto";
import { appendFile, mkdir, open, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalJson, jsonHash } from "./json";

export interface AuditInput {
  actionHash: string;
  decision: string;
  rule: string;
  evidenceId?: string;
  server?: string;
  tool?: string;
  execution?: "not_attempted" | "succeeded" | "failed";
  outputHash?: string;
  errorCode?: string;
}

export interface AuditEntry {
  version: 1;
  timestamp: string;
  actionHash: string;
  decision: string;
  rule: string;
  evidenceId: string | null;
  server: string | null;
  tool: string | null;
  execution: "not_attempted" | "succeeded" | "failed";
  outputHash: string | null;
  errorCode: string | null;
  previousHash: string | null;
  entryHash: string;
}

interface AuditCheckpointV1 {
  version: 1;
  entries: number;
  headHash: string | null;
  updatedAt: string;
  signature: string | null;
}

interface AuditCheckpointV2 {
  version: 2;
  entries: number;
  headHash: string | null;
  fileBytes: number;
  updatedAt: string;
  signature: string | null;
}

type AuditCheckpoint = AuditCheckpointV1 | AuditCheckpointV2;

const LOCK_STALE_MS = 30_000;
const DEFAULT_MAX_AUDIT_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_AUDIT_ENTRIES = 50_000;

function hashEntry(value: Omit<AuditEntry, "entryHash">): string {
  return jsonHash(value);
}

function validateEntries(entries: AuditEntry[]): { valid: boolean; headHash: string | null } {
  let previousHash: string | null = null;
  for (const entry of entries) {
    const unsigned: Omit<AuditEntry, "entryHash"> = {
      version: entry.version,
      timestamp: entry.timestamp,
      actionHash: entry.actionHash,
      decision: entry.decision,
      rule: entry.rule,
      evidenceId: entry.evidenceId,
      server: entry.server,
      tool: entry.tool,
      execution: entry.execution,
      outputHash: entry.outputHash,
      errorCode: entry.errorCode,
      previousHash: entry.previousHash,
    };
    if (entry.version !== 1 || entry.previousHash !== previousHash || hashEntry(unsigned) !== entry.entryHash) {
      return { valid: false, headHash: previousHash };
    }
    previousHash = entry.entryHash;
  }
  return { valid: true, headHash: previousHash };
}

async function readEntries(path: string): Promise<AuditEntry[]> {
  try {
    const raw = await readFile(path, "utf8");
    return raw.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as AuditEntry);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}

async function withFileLock<T>(path: string, callback: () => Promise<T>): Promise<T> {
  const lockPath = `${path}.lock`;
  await mkdir(dirname(path), { recursive: true });
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      try {
        await handle.writeFile(`${process.pid}:${randomBytes(8).toString("hex")}\n`, "utf8");
        return await callback();
      } finally {
        await handle.close();
        await unlink(lockPath).catch(() => undefined);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        const details = await stat(lockPath);
        if (Date.now() - details.mtimeMs > LOCK_STALE_MS) {
          await unlink(lockPath).catch(() => undefined);
          continue;
        }
      } catch (statError) {
        if ((statError as NodeJS.ErrnoException).code !== "ENOENT") throw statError;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  throw new Error("Timed out acquiring the ActionLock audit lock");
}

function checkpointSignature(value: Omit<AuditCheckpoint, "signature">, secret: string): string {
  return createHmac("sha256", secret)
    .update(`actionlock:audit-head:v${value.version}\n`, "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("base64url");
}

async function writeCheckpoint(
  path: string,
  entries: number,
  headHash: string | null,
  fileBytes: number,
  secret?: string,
): Promise<void> {
  const unsigned = { version: 2 as const, entries, headHash, fileBytes, updatedAt: new Date().toISOString() };
  const checkpoint: AuditCheckpointV2 = {
    ...unsigned,
    signature: secret ? checkpointSignature(unsigned, secret) : null,
  };
  const checkpointPath = `${path}.head.json`;
  const temporaryPath = `${checkpointPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(temporaryPath, `${canonicalJson(checkpoint)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, checkpointPath);
}

async function readAppendState(
  path: string,
  _checkpointSecret?: string,
): Promise<{ entries: number; headHash: string | null; fileBytes: number }> {
  const entries = await readEntries(path);
  const chain = validateEntries(entries);
  if (!chain.valid) throw new Error("Refusing to append to an invalid ActionLock audit chain");
  let fileBytes = 0;
  try {
    fileBytes = (await stat(path)).size;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return { entries: entries.length, headHash: chain.headHash, fileBytes };
}

export async function appendAuditEntry(
  path: string,
  value: AuditInput,
  options: { checkpointSecret?: string; maxBytes?: number; maxEntries?: number } = {},
): Promise<AuditEntry> {
  return withFileLock(path, async () => {
    const current = await readAppendState(path, options.checkpointSecret);
    const maxBytes = options.maxBytes ?? DEFAULT_MAX_AUDIT_BYTES;
    const maxEntries = options.maxEntries ?? DEFAULT_MAX_AUDIT_ENTRIES;
    if (current.entries >= maxEntries || current.fileBytes >= maxBytes) {
      throw new Error("ActionLock audit quota exceeded");
    }
    const unsigned: Omit<AuditEntry, "entryHash"> = {
      version: 1,
      timestamp: new Date().toISOString(),
      actionHash: value.actionHash,
      decision: value.decision,
      rule: value.rule,
      evidenceId: value.evidenceId ?? null,
      server: value.server ?? null,
      tool: value.tool ?? null,
      execution: value.execution ?? "not_attempted",
      outputHash: value.outputHash ?? null,
      errorCode: value.errorCode ?? null,
      previousHash: current.headHash,
    };
    const entry = { ...unsigned, entryHash: hashEntry(unsigned) };
    const line = `${canonicalJson(entry)}\n`;
    const nextBytes = current.fileBytes + Buffer.byteLength(line, "utf8");
    if (nextBytes > maxBytes) throw new Error("ActionLock audit quota exceeded");
    await appendFile(path, line, { encoding: "utf8", mode: 0o600 });
    await writeCheckpoint(path, current.entries + 1, entry.entryHash, nextBytes, options.checkpointSecret);
    return entry;
  });
}

export async function verifyAuditChain(
  path: string,
  options: { checkpointSecret?: string } = {},
): Promise<{ valid: boolean; entries: number; headHash: string | null; checkpointValid: boolean | null }> {
  let entries: AuditEntry[];
  try {
    entries = await readEntries(path);
  } catch {
    return { valid: false, entries: 0, headHash: null, checkpointValid: false };
  }
  const chain = validateEntries(entries);
  let checkpointValid: boolean | null = null;
  try {
    const checkpoint = JSON.parse(await readFile(`${path}.head.json`, "utf8")) as AuditCheckpoint;
    const fileBytes = (await stat(path)).size;
    const unsigned = checkpoint.version === 2
      ? {
          version: checkpoint.version,
          entries: checkpoint.entries,
          headHash: checkpoint.headHash,
          fileBytes: checkpoint.fileBytes,
          updatedAt: checkpoint.updatedAt,
        }
      : {
          version: checkpoint.version,
          entries: checkpoint.entries,
          headHash: checkpoint.headHash,
          updatedAt: checkpoint.updatedAt,
        };
    const matchesHead =
      (checkpoint.version === 1 || checkpoint.version === 2) &&
      checkpoint.entries === entries.length &&
      checkpoint.headHash === chain.headHash &&
      (checkpoint.version !== 2 || checkpoint.fileBytes === fileBytes);
    if (options.checkpointSecret) {
      checkpointValid = Boolean(
        matchesHead && checkpoint.signature === checkpointSignature(unsigned, options.checkpointSecret),
      );
    } else {
      checkpointValid = matchesHead;
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") checkpointValid = false;
  }
  return {
    valid: chain.valid && checkpointValid !== false,
    entries: entries.length,
    headHash: chain.headHash,
    checkpointValid,
  };
}
