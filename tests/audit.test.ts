import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { appendAuditEntry, verifyAuditChain } from "../src/server/audit";

const directories: string[] = [];
const checkpointSecret = "audit checkpoint secret with sufficient length";

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("audit chain", () => {
  it("detects an edited decision record", async () => {
    const directory = await mkdtemp(join(tmpdir(), "actionlock-audit-"));
    directories.push(directory);
    const path = join(directory, "audit.ndjson");
    await appendAuditEntry(
      path,
      { actionHash: "a".repeat(64), decision: "block", rule: "ACTIONLOCK-020" },
      { checkpointSecret },
    );
    await appendAuditEntry(
      path,
      { actionHash: "b".repeat(64), decision: "allow", rule: "ACTIONLOCK-010" },
      { checkpointSecret },
    );
    const valid = await verifyAuditChain(path, { checkpointSecret });
    expect(valid.valid).toBe(true);
    expect(valid.entries).toBe(2);
    expect(valid.checkpointValid).toBe(true);

    const tampered = (await readFile(path, "utf8")).replace('"decision":"block"', '"decision":"allow"');
    await writeFile(path, tampered);
    expect((await verifyAuditChain(path, { checkpointSecret })).valid).toBe(false);
    await expect(
      appendAuditEntry(
        path,
        { actionHash: "c".repeat(64), decision: "block", rule: "ACTIONLOCK-020" },
        { checkpointSecret },
      ),
    ).rejects.toThrow(/invalid ActionLock audit chain/);
  });

  it("serializes concurrent appenders into one valid chain", async () => {
    const directory = await mkdtemp(join(tmpdir(), "actionlock-audit-race-"));
    directories.push(directory);
    const path = join(directory, "audit.ndjson");
    await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        appendAuditEntry(
          path,
          {
            actionHash: index.toString(16).padStart(64, "0"),
            decision: "approval_required",
            rule: "ACTIONLOCK-030",
          },
          { checkpointSecret },
        ),
      ),
    );
    const result = await verifyAuditChain(path, { checkpointSecret });
    expect(result.valid).toBe(true);
    expect(result.entries).toBe(20);
    expect(result.checkpointValid).toBe(true);
  });

  it("fails closed when the configured audit quota is reached", async () => {
    const directory = await mkdtemp(join(tmpdir(), "actionlock-audit-quota-"));
    directories.push(directory);
    const path = join(directory, "audit.ndjson");
    await appendAuditEntry(
      path,
      { actionHash: "a".repeat(64), decision: "block", rule: "ACTIONLOCK-020" },
      { checkpointSecret, maxEntries: 1 },
    );
    await expect(
      appendAuditEntry(
        path,
        { actionHash: "b".repeat(64), decision: "block", rule: "ACTIONLOCK-020" },
        { checkpointSecret, maxEntries: 1 },
      ),
    ).rejects.toThrow(/quota exceeded/);
    expect((await verifyAuditChain(path, { checkpointSecret })).valid).toBe(true);
  });
});
