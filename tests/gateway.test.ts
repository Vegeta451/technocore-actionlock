import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyAuditChain } from "../src/server/audit";
import { issueApprovalGrant } from "../src/server/approval";
import type { DownstreamExecutor, DownstreamServerConfig, GatewayConfig } from "../src/server/downstream";
import { issueEvidenceReceipt } from "../src/server/evidence";
import { ActionLockGateway } from "../src/server/gateway";
import { provenanceHash } from "../src/server/protocol";
import { loadOrCreateReceiptSigner, verifyPublicReceipt } from "../src/server/public-receipt";
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
  return { gateway, executor, evidenceToken, receiptSigner, auditPath };
}

describe("enforced MCP gateway", () => {
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

  it("records a separately signed failed execution without changing the approval commitment", async () => {
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
    expect(result.publicReceipts?.approval.payload.actionHash).toBe(preview.decision.actionHash);
    expect(result.publicReceipts?.execution.payload.execution).toBe("failed");
    expect(result.publicReceipts?.execution.payload.outputHash).toBeNull();
    expect(verifyPublicReceipt(result.publicReceipts?.execution).valid).toBe(true);
  });

  it("does not misreport a receipt-signing failure as a downstream failure", async () => {
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

    await expect(gateway.execute({ ...request, approvalToken })).rejects.toThrow(/receipt signer unavailable/);
    expect(executor.calls).toBe(1);
    expect((await verifyAuditChain(auditPath, { checkpointSecret: auditSecret })).entries).toBe(0);
  });
});
