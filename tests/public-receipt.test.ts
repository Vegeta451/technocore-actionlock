import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createPrivateKey, sign } from "node:crypto";
import { canonicalJson } from "../src/server/json";
import { evaluateCapability } from "../src/server/capability";
import {
  loadOrCreateReceiptSigner,
  publicReceiptHash,
  verifyPublicReceipt,
  verifyPublicReceiptBundle,
} from "../src/server/public-receipt";
import type { ActionIntent, Provenance, RiskAssessment } from "../src/server/types";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

const action: ActionIntent = {
  capability: "file_write",
  operation: "write reviewed report",
  target: "local report workspace",
  boundary: "downstream",
  argumentsHash: "a".repeat(64),
  evidenceContextHash: "b".repeat(64),
  executionPolicyHash: "c".repeat(64),
};
const provenance: Provenance = {
  source: "technocore",
  trust: "untrusted_remote",
  room: "lobby",
  seq: "42",
  sender: "did:key:zexample",
  contentHash: "d".repeat(64),
  verification: "server_signed_lane",
};
const risk: RiskAssessment = { action: "allow", score: 0, findings: [], urls: [] };

async function signerFixture() {
  const directory = await mkdtemp(join(tmpdir(), "actionlock-receipt-"));
  directories.push(directory);
  const path = join(directory, "receipt-key.json");
  return { signer: await loadOrCreateReceiptSigner(path), path };
}

async function resignFixture(value: object, path: string) {
  const keyFile = JSON.parse(await readFile(path, "utf8"));
  const key = createPrivateKey({ key: Buffer.from(keyFile.privateKey, "base64url"), format: "der", type: "pkcs8" });
  const { signature: _signature, ...unsigned } = value as Record<string, unknown>;
  return { ...unsigned, signature: sign(null, Buffer.from(`actionlock:public-receipt:v1\n${canonicalJson(unsigned)}`), key).toString("base64url") };
}

async function approvalFixture() {
  const fixture = await signerFixture();
  const initial = evaluateCapability({ action, provenance, risk });
  const decision = evaluateCapability({ action, provenance, risk, approvedActionHash: initial.actionHash });
  const approval = fixture.signer.signApproval({ grantId: "e".repeat(32), server: "trusted", tool: "write_report", action, provenance, decision });
  return { ...fixture, approval };
}

describe("public Ed25519 receipts", () => {
  it("checks malformed signed fields without relying on signature failure", async () => {
    const { approval, path } = await approvalFixture();
    const malformed = [
      { ...approval, extra: "unsupported extension" },
      { ...approval, payload: { ...approval.payload, extra: true } },
      { ...approval, payload: { ...approval.payload, tool: 42 } },
      { ...approval, payload: { ...approval.payload, approvedAt: "2026-09-04" } },
    ];
    for (const value of malformed) {
      expect(verifyPublicReceipt(await resignFixture(value, path)).valid).toBe(false);
    }
  });

  it("exits unsuccessfully from the standalone CLI for a malformed signed receipt", async () => {
    const { approval, signer, path } = await approvalFixture();
    const receiptPath = join(path, "..", "receipt.json");
    const run = promisify(execFile);
    const args = ["--import", "tsx", "src/cli/verify-receipt.ts", receiptPath, signer.keyId];
    await writeFile(receiptPath, JSON.stringify(approval));
    const valid = await run(process.execPath, args);
    expect(JSON.parse(valid.stdout).valid).toBe(true);
    const malformed = await resignFixture({ ...approval, payload: { ...approval.payload, tool: null } }, path);
    await writeFile(receiptPath, JSON.stringify(malformed));
    await expect(run(process.execPath, args)).rejects.toMatchObject({ code: 1 });
  });

  it("rejects signed unknown outcome states", async () => {
    const { signer, path } = await signerFixture();
    const receipt = signer.signExecution({ actionHash: "a".repeat(64), approvalReceiptHash: "b".repeat(64), execution: "succeeded", outputHash: "c".repeat(64), errorCode: null });
    const malformed = { ...receipt, payload: { ...receipt.payload, execution: "unknown" } };
    expect(verifyPublicReceipt(await resignFixture(malformed, path)).valid).toBe(false);
  });

  it("rejects signed approval payloads with missing routing fields", async () => {
    const { approval, path } = await approvalFixture();
    const { server: _server, ...payload } = approval.payload;
    expect(verifyPublicReceipt(await resignFixture({ ...approval, payload }, path)).valid).toBe(false);
  });

  it("rejects a signed failed receipt with a non-string error code", async () => {
    const { signer, path } = await signerFixture();
    const receipt = signer.signExecution({ actionHash: "a".repeat(64), approvalReceiptHash: "b".repeat(64), execution: "failed", outputHash: null, errorCode: "downstream_failed" });
    expect(verifyPublicReceipt(receipt).valid).toBe(true);
    expect(verifyPublicReceipt(await resignFixture({ ...receipt, payload: { ...receipt.payload, errorCode: 42 } }, path)).valid).toBe(false);
  });

  it("rejects non-canonical signature encoding even when decoded bytes are unchanged", async () => {
    const { approval } = await approvalFixture();
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(approval.signature.at(-1)!);
    const signature = approval.signature.slice(0, -1) + alphabet[last + 1];
    expect(Buffer.from(signature, "base64url")).toEqual(Buffer.from(approval.signature, "base64url"));
    expect(verifyPublicReceipt({ ...approval, signature }).valid).toBe(false);
  });

  it("requires an approval receipt in the approval slot", async () => {
    const { signer } = await signerFixture();
    const approval = signer.signExecution({ actionHash: "a".repeat(64), approvalReceiptHash: "b".repeat(64), execution: "succeeded", outputHash: "c".repeat(64), errorCode: null });
    const execution = signer.signExecution({ actionHash: approval.payload.actionHash, approvalReceiptHash: publicReceiptHash(approval), execution: "succeeded", outputHash: "d".repeat(64), errorCode: null });
    expect(verifyPublicReceipt(approval).valid).toBe(true);
    expect(verifyPublicReceiptBundle({ approval, execution }).valid).toBe(false);
  });

  it("requires the same signer for a V1 approval/result pair", async () => {
    const { signer, approval } = await approvalFixture();
    const other = await signerFixture();
    const execution = other.signer.signExecution({ actionHash: approval.payload.actionHash, approvalReceiptHash: publicReceiptHash(approval), execution: "succeeded", outputHash: "d".repeat(64), errorCode: null });
    const options = { expectedKeyIds: [signer.keyId, other.signer.keyId] };
    expect(verifyPublicReceipt(execution, options).valid).toBe(true);
    expect(verifyPublicReceiptBundle({ approval, execution }, options).valid).toBe(false);
  });

  it("signs a recomputable approval commitment and pins the expected key", async () => {
    const { signer, path } = await signerFixture();
    const initial = evaluateCapability({ action, provenance, risk });
    const decision = evaluateCapability({ action, provenance, risk, approvedActionHash: initial.actionHash });
    const receipt = signer.signApproval({
      grantId: "e".repeat(32),
      server: "trusted",
      tool: "write_report",
      action,
      provenance,
      decision,
      now: new Date("2026-09-01T00:00:00.000Z"),
    });

    expect(verifyPublicReceipt(receipt, { expectedKeyIds: [signer.keyId] })).toEqual({
      valid: true,
      keyId: signer.keyId,
      kind: "approval",
      receiptHash: publicReceiptHash(receipt),
    });
    expect(verifyPublicReceipt(receipt, { expectedKeyIds: ["f".repeat(64)] }).valid).toBe(false);
    expect((await readFile(path, "utf8"))).not.toContain(receipt.signature);
  });

  it("rejects payload substitution and keeps execution separate from approval", async () => {
    const { signer } = await signerFixture();
    const initial = evaluateCapability({ action, provenance, risk });
    const decision = evaluateCapability({ action, provenance, risk, approvedActionHash: initial.actionHash });
    const approval = signer.signApproval({
      grantId: "e".repeat(32),
      server: "trusted",
      tool: "write_report",
      action,
      provenance,
      decision,
    });
    const execution = signer.signExecution({
      actionHash: decision.actionHash,
      approvalReceiptHash: publicReceiptHash(approval),
      execution: "succeeded",
      outputHash: "f".repeat(64),
      errorCode: null,
    });

    expect(verifyPublicReceipt(execution).valid).toBe(true);
    expect(verifyPublicReceiptBundle({ approval, execution }).valid).toBe(true);
    const tampered = structuredClone(approval);
    tampered.payload.server = "attacker";
    expect(verifyPublicReceipt(tampered).valid).toBe(false);

    const mismatchedExecution = structuredClone(execution);
    mismatchedExecution.payload.approvalReceiptHash = "0".repeat(64);
    expect(verifyPublicReceiptBundle({ approval, execution: mismatchedExecution }).valid).toBe(false);
  });

  it("reopens the same key file with a stable public identity", async () => {
    const { signer, path } = await signerFixture();
    const reopened = await loadOrCreateReceiptSigner(path);
    expect(reopened.keyId).toBe(signer.keyId);
    expect(reopened.publicKey).toBe(signer.publicKey);
  });
});
