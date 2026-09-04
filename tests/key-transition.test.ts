import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { createKeyTransition, prepareKeyTransition, verifyKeyTransition } from "../src/server/key-transition";
import { loadOrCreateReceiptSigner, loadReceiptSigner, verifyPublicReceipt } from "../src/server/public-receipt";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "actionlock-transition-"));
  directories.push(directory);
  const previousPath = join(directory, "old-private.json");
  const nextPath = join(directory, "new-private.json");
  const previous = await loadOrCreateReceiptSigner(previousPath);
  const next = await loadOrCreateReceiptSigner(nextPath);
  const transition = createKeyTransition(previous, next, new Date("2026-09-04T00:00:00.000Z"));
  return { directory, previousPath, nextPath, previous, next, transition };
}

describe("planned receipt-key transitions", () => {
  it("requires an independently pinned old key and both signatures", async () => {
    const { previous, next, transition } = await fixture();
    expect(verifyKeyTransition(transition, previous.keyId)).toMatchObject({ valid: true, previousKeyId: previous.keyId, nextKeyId: next.keyId });
    expect(verifyKeyTransition(transition, next.keyId).valid).toBe(false);
    expect(verifyKeyTransition(transition, "").valid).toBe(false);
    for (const role of ["previous", "next"] as const) {
      expect(verifyKeyTransition({ ...transition, signatures: { ...transition.signatures, [role]: "A".repeat(86) } }, previous.keyId).valid).toBe(false);
    }
  });

  it("rejects modified, incomplete, and unknown statement fields", async () => {
    const { previous, transition } = await fixture();
    const { next: _next, ...missingNext } = transition.statement;
    for (const statement of [
      { ...transition.statement, declaredAt: "2026-09-05T00:00:00.000Z" },
      { ...transition.statement, purpose: "revocation" },
      { ...transition.statement, latest: true },
      missingNext,
    ]) expect(verifyKeyTransition({ ...transition, statement }, previous.keyId).valid).toBe(false);
    expect(verifyKeyTransition(null, previous.keyId).valid).toBe(false);
    expect(verifyKeyTransition({ ...transition, extra: true }, previous.keyId).valid).toBe(false);
  });

  it("rejects non-canonical signature aliases", async () => {
    const { previous, transition } = await fixture();
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const sig = transition.signatures.previous;
    const alias = sig.slice(0, -1) + alphabet[alphabet.indexOf(sig.at(-1)!) + 1];
    expect(Buffer.from(alias, "base64url")).toEqual(Buffer.from(sig, "base64url"));
    expect(verifyKeyTransition({ ...transition, signatures: { ...transition.signatures, previous: alias } }, previous.keyId).valid).toBe(false);
  });

  it("rejects a no-op transition", async () => {
    const { previous } = await fixture();
    expect(() => createKeyTransition(previous, previous)).toThrow("distinct keys");
  });

  it("writes only a public artifact without changing either private key", async () => {
    const { directory, previousPath, nextPath, previous } = await fixture();
    const before = [await readFile(previousPath, "utf8"), await readFile(nextPath, "utf8")];
    const outputPath = join(directory, "transition.json");
    const result = await prepareKeyTransition(previousPath, nextPath, outputPath);
    expect(verifyKeyTransition(result, previous.keyId).valid).toBe(true);
    const output = await readFile(outputPath, "utf8");
    expect(output).not.toContain("privateKey");
    for (const keyFile of before) expect(output).not.toContain(JSON.parse(keyFile).privateKey);
    expect(await readFile(previousPath, "utf8")).toBe(before[0]);
    expect(await readFile(nextPath, "utf8")).toBe(before[1]);
    expect((await loadReceiptSigner(previousPath)).keyId).toBe(previous.keyId);
  });

  it("never overwrites an existing output or a private key", async () => {
    const { directory, previousPath, nextPath } = await fixture();
    const outputPath = join(directory, "transition.json");
    await writeFile(outputPath, "existing record");
    await expect(prepareKeyTransition(previousPath, nextPath, outputPath)).rejects.toMatchObject({ code: "EEXIST" });
    expect(await readFile(outputPath, "utf8")).toBe("existing record");
    const before = await readFile(previousPath, "utf8");
    await expect(prepareKeyTransition(previousPath, nextPath, previousPath)).rejects.toMatchObject({ code: "EEXIST" });
    expect(await readFile(previousPath, "utf8")).toBe(before);
  });

  it("does not create missing source identities", async () => {
    const { directory, previousPath } = await fixture();
    const missing = join(directory, "missing-key.json");
    const output = join(directory, "transition.json");
    await expect(prepareKeyTransition(missing, previousPath, output)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(prepareKeyTransition(previousPath, missing, output)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(missing)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("does not alter historical receipt verification or authorize receipts by itself", async () => {
    const { previous, next, transition } = await fixture();
    const receipt = previous.signExecution({ actionHash: "a".repeat(64), approvalReceiptHash: "b".repeat(64), execution: "succeeded", outputHash: "c".repeat(64), errorCode: null });
    expect(verifyKeyTransition(transition, previous.keyId).valid).toBe(true);
    expect(verifyPublicReceipt(receipt, { expectedKeyIds: [previous.keyId] }).valid).toBe(true);
    expect(verifyPublicReceipt(receipt, { expectedKeyIds: [next.keyId] }).valid).toBe(false);
    expect(verifyPublicReceipt(transition, { expectedKeyIds: [previous.keyId] }).valid).toBe(false);
  });

  it("supports a manually checked next hop but rejects a chain with the wrong starting pin", async () => {
    const { directory, previous, next, transition } = await fixture();
    const third = await loadOrCreateReceiptSigner(join(directory, "third-private.json"));
    const second = createKeyTransition(next, third);
    const firstResult = verifyKeyTransition(transition, previous.keyId);
    expect(verifyKeyTransition(second, firstResult.nextKeyId!).valid).toBe(true);
    expect(verifyKeyTransition(second, previous.keyId).valid).toBe(false);
  });

  it("prepares and verifies through the CLI without activating or exposing keys", async () => {
    const { directory, previousPath, nextPath, previous, next } = await fixture();
    const run = promisify(execFile);
    const output = join(directory, "transition.json");
    const prepared = await run(process.execPath, ["--import", "tsx", "src/cli/prepare-key-transition.ts", previousPath, nextPath, output]);
    expect(JSON.parse(prepared.stdout)).toMatchObject({ valid: true, activated: false });
    const verifyArgs = ["--import", "tsx", "src/cli/verify-key-transition.ts", output];
    const verified = await run(process.execPath, [...verifyArgs, previous.keyId]);
    expect(JSON.parse(verified.stdout).valid).toBe(true);
    await expect(run(process.execPath, [...verifyArgs, next.keyId])).rejects.toMatchObject({ code: 1 });
    await expect(run(process.execPath, verifyArgs)).rejects.toMatchObject({ code: 1 });
    await writeFile(output, " ".repeat(16_385));
    await expect(run(process.execPath, [...verifyArgs, previous.keyId])).rejects.toMatchObject({ code: 1 });
  });

  it("creates a separate key through an explicit CLI path without touching the default key", async () => {
    const { directory, previousPath, previous } = await fixture();
    const before = await readFile(previousPath, "utf8");
    const newPath = join(directory, "explicit-private.json");
    const run = promisify(execFile);
    const result = await run(process.execPath, ["--import", "tsx", "src/cli/receipt-key.ts", "--path", newPath], {
      env: { ...process.env, ACTIONLOCK_RECEIPT_KEY_PATH: previousPath },
    });
    const publicIdentity = JSON.parse(result.stdout);
    expect(publicIdentity.keyId).not.toBe(previous.keyId);
    expect(publicIdentity).not.toHaveProperty("privateKey");
    expect((await loadReceiptSigner(newPath)).keyId).toBe(publicIdentity.keyId);
    expect(await readFile(previousPath, "utf8")).toBe(before);
  });
});
