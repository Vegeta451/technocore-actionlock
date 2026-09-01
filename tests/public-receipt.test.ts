import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
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

describe("public Ed25519 receipts", () => {
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
