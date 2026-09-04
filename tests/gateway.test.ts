import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyAuditChain } from "../src/server/audit";
import { issueApprovalGrant } from "../src/server/approval";
import type { DownstreamExecutor, DownstreamServerConfig, GatewayConfig } from "../src/server/downstream";
import { issueEvidenceReceipt } from "../src/server/evidence";
import { ActionLockGateway } from "../src/server/gateway";
import { provenanceHash } from "../src/server/protocol";
import { loadOrCreateReceiptSigner, verifyPublicReceipt, verifyPublicReceiptBundle } from "../src/server/public-receipt";
import { createKeyTransition, verifyKeyTransition } from "../src/server/key-transition";
import { FileReplayStore } from "../src/server/replay";
import type { ScanEvent } from "../src/server/types";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

const evidenceSecret = "evidence secret with at least thirty two bytes";
const approvalSecret = "approval secret with at least thirty two bytes";
const auditSecret = "audit secret with at least thirty two bytes";

const config: GatewayConfig = {
  version: 1,
  servers: [
    {
      id: "trusted",
      command: "unused-in-tests",
      args: [],
      inheritEnv: [],
      tools: {
        write_report: {
          capability: "file_write",
          operation: "write reviewed report",
          target: "local report workspace",
          maxArgumentBytes: 2_000,
        },
        write_shadow: {
          capability: "file_write",
          operation: "write reviewed report",
          target: "local report workspace",
          maxArgumentBytes: 2_000,
        },
        run_shell: {
          capability: "shell",
          operation: "run command",
          target: "local shell",
          maxArgumentBytes: 2_000,
        },
      },
    },
    {
      id: "alternate",
      command: "different-unused-command",
      args: ["--alternate"],
      cwd: "alternate-workspace",
      inheritEnv: ["PATH"],
      tools: {
        write_report: {
          capability: "file_write",
          operation: "write reviewed report",
          target: "local report workspace",
          maxArgumentBytes: 2_000,
        },
      },
    },
  ],
};

class FakeExecutor implements DownstreamExecutor {
  calls = 0;
  fail = false;

  async call(server: DownstreamServerConfig, tool: string, argumentsValue: Record<string, unknown>) {
    this.calls += 1;
    if (this.fail) throw new Error("expected downstream failure");
    return { server: server.id, tool, arguments: argumentsValue, ok: true };
  }
}

function scanEvent(text = "write the reviewed report"): ScanEvent {
  const contentHash = provenanceHash({ room: "lobby", seq: "77", sender: "did:key:zexample", text });
  return {
    message: { seq: "77", ts: "2026-08-31T00:00:00Z", from: "did:key:zexample", text },
    provenance: {
      source: "technocore",
      trust: "untrusted_remote",
      room: "lobby",
      seq: "77",
      sender: "did:key:zexample",
      contentHash,
      verification: "server_signed_lane",
    },
    risk: { action: "allow", score: 0, findings: [], urls: [] },
  };
}

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "actionlock-gateway-"));
  directories.push(directory);
  const executor = new FakeExecutor();
  const receiptSigner = await loadOrCreateReceiptSigner(join(directory, "receipt-key.json"));
  const auditPath = join(directory, "audit.ndjson");
  const gateway = new ActionLockGateway({
    config,
    executor,
    evidenceSecret,
    approvalSecret,
    auditSecret,
    replayStore: new FileReplayStore(join(directory, "replay")),
    auditPath,
    receiptSigner,
  });
  const evidenceToken = issueEvidenceReceipt({ event: scanEvent(), secret: evidenceSecret }).token;
  return { gateway, executor, evidenceToken, receiptSigner, auditPath, directory };
}

describe("enforced MCP gateway", () => {
  it("preserves replay protection and historical receipts across a planned signer restart", async () => {
    const { gateway, executor, evidenceToken, receiptSigner, auditPath, directory } = await fixture();
    const request = { server: "trusted", tool: "write_report", arguments: { title: "Before rotation" }, evidenceToken };
    const approvalToken = issueApprovalGrant({ actionHash: gateway.preview(request).decision.actionHash, secret: approvalSecret });
    const before = await gateway.execute({ ...request, approvalToken });
    expect(before.executed).toBe(true);

    const nextSigner = await loadOrCreateReceiptSigner(join(directory, "next-receipt-key.json"));
    const transition = createKeyTransition(receiptSigner, nextSigner);
    expect(verifyKeyTransition(transition, receiptSigner.keyId).valid).toBe(true);
    const restarted = new ActionLockGateway({
      config, executor, evidenceSecret, approvalSecret, auditSecret, auditPath,
      replayStore: new FileReplayStore(join(directory, "replay")),
      receiptSigner: nextSigner,
    });
    const replay = await restarted.execute({ ...request, approvalToken });
    expect(replay.approval).toBe("replayed");
    expect(replay.executed).toBe(false);
    expect(executor.calls).toBe(1);

    const nextRequest = { ...request, arguments: { title: "After rotation" } };
    const nextToken = issueApprovalGrant({ actionHash: restarted.preview(nextRequest).decision.actionHash, secret: approvalSecret });
    const after = await restarted.execute({ ...nextRequest, approvalToken: nextToken });
    expect(after.executed).toBe(true);
    expect(executor.calls).toBe(2);
    expect(verifyPublicReceiptBundle(before.publicReceipts, { expectedKeyIds: [receiptSigner.keyId] }).valid).toBe(true);
    expect(verifyPublicReceiptBundle(after.publicReceipts, { expectedKeyIds: [nextSigner.keyId] }).valid).toBe(true);
    expect(verifyPublicReceiptBundle(before.publicReceipts, { expectedKeyIds: [nextSigner.keyId] }).valid).toBe(false);
    expect(verifyPublicReceiptBundle(after.publicReceipts, { expectedKeyIds: [receiptSigner.keyId] }).valid).toBe(false);
  });

  it("derives policy from trusted config and never executes without exact approval", async () => {
    const { gateway, executor, evidenceToken } = await fixture();
    const request = {
      server: "trusted",
      tool: "write_report",
      arguments: { title: "Evidence", body: "Reviewed" },
      evidenceToken,
    };
    const preview = gateway.preview(request);
    expect(preview.decision.decision).toBe("approval_required");
    expect((await gateway.execute(request)).executed).toBe(false);
    expect(executor.calls).toBe(0);

    const approvalToken = issueApprovalGrant({
      actionHash: preview.decision.actionHash,
      secret: approvalSecret,
    });
    const changed = await gateway.execute({
      ...request,
      arguments: { title: "Evidence", body: "Changed after approval" },
      approvalToken,
    });
    expect(changed.approval).toBe("invalid");
    expect(executor.calls).toBe(0);

    const allowed = await gateway.execute({ ...request, approvalToken });
    expect(allowed.executed).toBe(true);
    expect(allowed.approval).toBe("consumed");
    expect(allowed.publicReceipts?.approval.kind).toBe("approval");
    expect(allowed.publicReceipts?.execution.kind).toBe("execution");
    expect(verifyPublicReceipt(allowed.publicReceipts?.approval).valid).toBe(true);
    expect(verifyPublicReceipt(allowed.publicReceipts?.execution).valid).toBe(true);
    expect(executor.calls).toBe(1);

    const replay = await gateway.execute({ ...request, approvalToken });
    expect(replay.executed).toBe(false);
    expect(replay.approval).toBe("replayed");
    expect(executor.calls).toBe(1);
  });

  it("blocks remote shell capability even when an approval token is supplied", async () => {
    const { gateway, executor, evidenceToken } = await fixture();
    const request = { server: "trusted", tool: "run_shell", arguments: { command: "echo no" }, evidenceToken };
    const preview = gateway.preview(request);
    expect(preview.decision.decision).toBe("block");
    const token = issueApprovalGrant({ actionHash: preview.decision.actionHash, secret: approvalSecret });
    const result = await gateway.execute({ ...request, approvalToken: token });
    expect(result.executed).toBe(false);
    expect(executor.calls).toBe(0);
  });

  it("uses canonical argument hashing and rejects fabricated evidence", async () => {
    const { gateway, evidenceToken } = await fixture();
    const first = gateway.preview({
      server: "trusted",
      tool: "write_report",
      arguments: { a: 1, b: 2 },
      evidenceToken,
    });
    const reordered = gateway.preview({
      server: "trusted",
      tool: "write_report",
      arguments: { b: 2, a: 1 },
      evidenceToken,
    });
    expect(first.decision.actionHash).toBe(reordered.decision.actionHash);
    expect(() =>
      gateway.preview({
        server: "trusted",
        tool: "write_report",
        arguments: {},
        evidenceToken: `${evidenceToken}x`,
      }),
    ).toThrow(/Evidence receipt/);
  });

  it("binds approval to the exact server, tool, executable policy, and evidence receipt", async () => {
    const { gateway, evidenceToken } = await fixture();
    const request = {
      server: "trusted",
      tool: "write_report",
      arguments: { title: "Evidence", body: "Reviewed" },
      evidenceToken,
    };
    const approved = gateway.preview(request);
    const approvalToken = issueApprovalGrant({ actionHash: approved.decision.actionHash, secret: approvalSecret });

    expect(gateway.preview({ ...request, tool: "write_shadow" }).decision.actionHash)
      .not.toBe(approved.decision.actionHash);
    expect(gateway.preview({ ...request, server: "alternate" }).decision.actionHash)
      .not.toBe(approved.decision.actionHash);
    expect((await gateway.execute({ ...request, tool: "write_shadow", approvalToken })).approval).toBe("invalid");

    const secondEvidence = issueEvidenceReceipt({ event: scanEvent(), secret: evidenceSecret }).token;
    const secondPreview = gateway.preview({ ...request, evidenceToken: secondEvidence });
    expect(secondPreview.decision.actionHash).not.toBe(approved.decision.actionHash);
    expect((await gateway.execute({ ...request, evidenceToken: secondEvidence, approvalToken })).approval).toBe("invalid");
  });

  it("reports unknown outcome after an executor error without signing a false failure", async () => {
    const { gateway, executor, evidenceToken } = await fixture();
    executor.fail = true;
    const request = {
      server: "trusted",
      tool: "write_report",
      arguments: { title: "Evidence" },
      evidenceToken,
    };
    const preview = gateway.preview(request);
    const approvalToken = issueApprovalGrant({ actionHash: preview.decision.actionHash, secret: approvalSecret });
    const result = await gateway.execute({ ...request, approvalToken });

    expect(result.executed).toBe(false);
    expect(result.executionStatus).toBe("unknown");
    expect(result.retrySafe).toBe(false);
    expect(result.approvalReceipt?.payload.actionHash).toBe(preview.decision.actionHash);
    expect(result.publicReceipts).toBeUndefined();
    expect(verifyPublicReceipt(result.approvalReceipt).valid).toBe(true);
    expect((await gateway.execute({ ...request, approvalToken })).approval).toBe("replayed");
    expect(executor.calls).toBe(1);
  });

  it("preserves success and refuses replay when post-action signing fails", async () => {
    const { gateway, executor, evidenceToken, receiptSigner, auditPath } = await fixture();
    const request = {
      server: "trusted",
      tool: "write_report",
      arguments: { title: "Evidence" },
      evidenceToken,
    };
    const preview = gateway.preview(request);
    const approvalToken = issueApprovalGrant({ actionHash: preview.decision.actionHash, secret: approvalSecret });
    vi.spyOn(receiptSigner, "signExecution").mockImplementation(() => {
      throw new Error("receipt signer unavailable");
    });

    const result = await gateway.execute({ ...request, approvalToken });
    expect(result).toMatchObject({ executed: true, executionStatus: "succeeded", retrySafe: false });
    expect(result.recordingErrors).toContain("receipt_signing_failed");
    expect(result.approvalReceipt).toBeDefined();
    expect(executor.calls).toBe(1);
    expect((await verifyAuditChain(auditPath, { checkpointSecret: auditSecret })).entries).toBe(2);
    expect((await gateway.execute({ ...request, approvalToken })).approval).toBe("replayed");
    expect(executor.calls).toBe(1);
  });

  it("preserves the outcome when output serialization fails", async () => {
    const { gateway, executor, evidenceToken } = await fixture();
    vi.spyOn(executor, "call").mockResolvedValue({ unsupported: 1n } as never);
    const request = { server: "trusted", tool: "write_report", arguments: {}, evidenceToken };
    const approvalToken = issueApprovalGrant({ actionHash: gateway.preview(request).decision.actionHash, secret: approvalSecret });
    const result = await gateway.execute({ ...request, approvalToken });
    expect(result).toMatchObject({ executed: true, executionStatus: "succeeded", retrySafe: false });
    expect(result.recordingErrors).toContain("output_serialization_failed");
    expect(result.output).toBeUndefined();
    expect(() => JSON.stringify(result)).not.toThrow();
  });

  it("does not sign an MCP isError response as successful execution", async () => {
    const { gateway, executor, evidenceToken } = await fixture();
    const call = vi.spyOn(executor, "call").mockResolvedValue({ isError: true, content: [{ type: "text", text: "partial write then error" }] } as never);
    const request = { server: "trusted", tool: "write_report", arguments: {}, evidenceToken };
    const approvalToken = issueApprovalGrant({ actionHash: gateway.preview(request).decision.actionHash, secret: approvalSecret });
    const result = await gateway.execute({ ...request, approvalToken });
    expect(result).toMatchObject({ executed: false, executionStatus: "unknown", retrySafe: false });
    expect(result.publicReceipts).toBeUndefined();
    expect(result.error).not.toContain("partial write then error");
    await gateway.execute({ ...request, approvalToken });
    expect(call).toHaveBeenCalledOnce();
  });

  it("still attempts audit when signing fails, and reports both failures", async () => {
    const { gateway, executor, evidenceToken, auditPath, receiptSigner } = await fixture();
    vi.spyOn(executor, "call").mockImplementation(async () => {
      await writeFile(auditPath, "corrupted-after-effect\n");
      return { ok: true } as never;
    });
    vi.spyOn(receiptSigner, "signExecution").mockImplementation(() => { throw new Error("signer fault"); });
    const request = { server: "trusted", tool: "write_report", arguments: {}, evidenceToken };
    const approvalToken = issueApprovalGrant({ actionHash: gateway.preview(request).decision.actionHash, secret: approvalSecret });
    const result = await gateway.execute({ ...request, approvalToken });
    expect(result.executionStatus).toBe("succeeded");
    expect(result.recordingErrors).toEqual(["receipt_signing_failed", "audit_write_failed"]);
    expect(() => JSON.stringify(result)).not.toThrow();
  });

  it("stops before dispatch when the audit destination is unavailable", async () => {
    const { gateway, executor, evidenceToken, auditPath } = await fixture();
    await writeFile(auditPath, "not-json\n");
    const request = { server: "trusted", tool: "write_report", arguments: {}, evidenceToken };
    const approvalToken = issueApprovalGrant({ actionHash: gateway.preview(request).decision.actionHash, secret: approvalSecret });
    const result = await gateway.execute({ ...request, approvalToken });
    expect(result).toMatchObject({ executed: false, executionStatus: "not_attempted", approval: "consumed" });
    expect(result.recordingErrors).toContain("audit_write_failed");
    expect(executor.calls).toBe(0);
  });

  it("does not rerun after an audit failure following a real effect, including restart", async () => {
    const { gateway, executor, evidenceToken, auditPath, directory, receiptSigner } = await fixture();
    const call = vi.spyOn(executor, "call").mockImplementation(async () => {
      await writeFile(auditPath, "corrupted-after-effect\n");
      return { ok: true } as never;
    });
    const request = { server: "trusted", tool: "write_report", arguments: {}, evidenceToken };
    const approvalToken = issueApprovalGrant({ actionHash: gateway.preview(request).decision.actionHash, secret: approvalSecret });
    const result = await gateway.execute({ ...request, approvalToken });
    expect(result).toMatchObject({ executed: true, executionStatus: "succeeded", retrySafe: false });
    expect(result.recordingErrors).toContain("audit_write_failed");
    const restarted = new ActionLockGateway({ config, executor, evidenceSecret, approvalSecret, auditSecret,
      replayStore: new FileReplayStore(join(directory, "replay")), auditPath, receiptSigner });
    const replay = await restarted.execute({ ...request, approvalToken });
    expect(replay).toMatchObject({ approval: "replayed", executionStatus: "not_attempted", retrySafe: false });
    expect(replay.recordingErrors).toContain("audit_write_failed");
    expect(replay.error).toContain("previous attempt may have produced effects");
    expect(call).toHaveBeenCalledOnce();
  });
});
