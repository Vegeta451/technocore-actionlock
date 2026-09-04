import { appendAuditEntry } from "./audit";
import { verifyApprovalGrant } from "./approval";
import { evaluateCapability } from "./capability";
import {
  resolveToolPolicy,
  type DownstreamExecutor,
  type DownstreamServerConfig,
  type GatewayConfig,
} from "./downstream";
import { verifyEvidenceReceipt } from "./evidence";
import { canonicalJson, jsonHash } from "./json";
import { analyzeText } from "./policy";
import {
  publicReceiptHash,
  type ApprovalCommitment,
  type ExecutionCommitment,
  type PublicReceipt,
  type PublicReceiptSigner,
} from "./public-receipt";
import type { ReplayStore } from "./replay";
import type {
  ActionIntent,
  ActionLockDecision,
  EvidenceClaims,
  GatewayToolPolicy,
  Provenance,
  RiskAssessment,
} from "./types";

export interface GatewayRequest {
  server: string;
  tool: string;
  arguments: Record<string, unknown>;
  evidenceToken: string;
  approvalToken?: string;
}

export interface GatewayPreview {
  evidence: EvidenceClaims;
  risk: RiskAssessment;
  decision: ActionLockDecision;
  review: {
    server: string;
    tool: string;
    arguments: Record<string, unknown>;
    argumentsHash: string;
    evidenceContextHash: string;
    executionPolicyHash: string;
    policy: GatewayToolPolicy;
  };
}

export interface GatewayResult extends GatewayPreview {
  executed: boolean;
  executionStatus: "not_attempted" | "succeeded" | "unknown";
  retrySafe: false;
  recordingErrors?: Array<"output_serialization_failed" | "receipt_signing_failed" | "audit_write_failed">;
  approvalReceipt?: PublicReceipt<ApprovalCommitment>;
  approval: "not_required" | "required" | "invalid" | "replayed" | "consumed";
  output?: unknown;
  error?: string;
  publicReceipts?: {
    approval: PublicReceipt<ApprovalCommitment>;
    execution: PublicReceipt<ExecutionCommitment>;
  };
}

export class ActionLockGateway {
  constructor(
    private readonly options: {
      config: GatewayConfig;
      executor: DownstreamExecutor;
      evidenceSecret: string;
      approvalSecret: string;
      auditSecret: string;
      replayStore: ReplayStore;
      auditPath: string;
      receiptSigner?: PublicReceiptSigner;
    },
  ) {}

  preview(request: Omit<GatewayRequest, "approvalToken">): GatewayPreview {
    const prepared = this.prepare(request);
    return {
      evidence: prepared.evidence,
      risk: prepared.risk,
      review: prepared.review,
      decision: evaluateCapability({
        action: prepared.action,
        provenance: prepared.provenance,
        risk: prepared.risk,
      }),
    };
  }

  async execute(request: GatewayRequest): Promise<GatewayResult> {
    const prepared = this.prepare(request);
    const initial = evaluateCapability({
      action: prepared.action,
      provenance: prepared.provenance,
      risk: prepared.risk,
    });

    if (initial.decision === "block") {
      await this.audit(prepared.evidence, request, initial, "not_attempted");
      return {
        evidence: prepared.evidence,
        risk: prepared.risk,
        review: prepared.review,
        decision: initial,
        executed: false,
        executionStatus: "not_attempted",
        retrySafe: false,
        approval: "not_required",
      };
    }

    if (initial.decision === "approval_required") {
      if (!request.approvalToken) {
        await this.audit(prepared.evidence, request, initial, "not_attempted");
        return {
          evidence: prepared.evidence,
          risk: prepared.risk,
          review: prepared.review,
          decision: initial,
          executed: false,
          executionStatus: "not_attempted",
          retrySafe: false,
          approval: "required",
        };
      }
      const grant = verifyApprovalGrant({
        token: request.approvalToken,
        actionHash: initial.actionHash,
        secret: this.options.approvalSecret,
      });
      if (!grant) {
        await this.audit(prepared.evidence, request, initial, "not_attempted", undefined, "invalid_approval");
        return {
          evidence: prepared.evidence,
          risk: prepared.risk,
          review: prepared.review,
          decision: initial,
          executed: false,
          executionStatus: "not_attempted",
          retrySafe: false,
          approval: "invalid",
        };
      }
      const consumed = await this.options.replayStore.consume(grant.grantId, grant.expiresAt);
      if (!consumed) {
        const recordingErrors: NonNullable<GatewayResult["recordingErrors"]> = [];
        try {
          await this.audit(prepared.evidence, request, initial, "not_attempted", undefined, "approval_replay");
        } catch {
          recordingErrors.push("audit_write_failed");
        }
        return {
          evidence: prepared.evidence,
          risk: prepared.risk,
          review: prepared.review,
          decision: initial,
          executed: false,
          executionStatus: "not_attempted",
          retrySafe: false,
          approval: "replayed",
          recordingErrors,
          error: "Approval already consumed. This request was not forwarded; a previous attempt may have produced effects. Reconcile before seeking a new approval.",
        };
      }
      const allowed = evaluateCapability({
        action: prepared.action,
        provenance: prepared.provenance,
        risk: prepared.risk,
        approvedActionHash: initial.actionHash,
      });
      const approvalReceipt = this.options.receiptSigner?.signApproval({
        grantId: grant.grantId,
        server: request.server,
        tool: request.tool,
        action: prepared.action,
        provenance: prepared.provenance,
        decision: allowed,
      });
      return this.forward(prepared, request, allowed, "consumed", approvalReceipt);
    }

    return this.forward(prepared, request, initial, "not_required");
  }

  private prepare(request: Omit<GatewayRequest, "approvalToken">): {
    evidence: EvidenceClaims;
    risk: RiskAssessment;
    provenance: Provenance;
    action: ActionIntent;
    server: DownstreamServerConfig;
    review: GatewayPreview["review"];
  } {
    const resolved = resolveToolPolicy(this.options.config, request.server, request.tool);
    if (!resolved) throw new Error("Downstream server/tool is not present in the trusted ActionLock config");
    const evidence = verifyEvidenceReceipt({ token: request.evidenceToken, secret: this.options.evidenceSecret });
    if (!evidence) throw new Error("Evidence receipt is invalid, expired, or not issued by this ActionLock instance");
    const serializedArguments = canonicalJson(request.arguments);
    if (Buffer.byteLength(serializedArguments, "utf8") > resolved.policy.maxArgumentBytes) {
      throw new Error("Downstream tool arguments exceed the configured byte limit");
    }
    const provenance: Provenance = {
      source: "technocore",
      trust: "untrusted_remote",
      room: evidence.event.room,
      seq: evidence.event.seq,
      sender: evidence.event.sender,
      contentHash: evidence.event.contentHash,
      verification: evidence.event.verification,
    };
    const argumentsHash = jsonHash(request.arguments);
    const evidenceContextHash = jsonHash({
      domain: "actionlock:evidence-context:v1",
      claims: evidence,
    });
    const executionPolicyHash = jsonHash({
      domain: "actionlock:execution-policy:v1",
      server: {
        id: resolved.server.id,
        command: resolved.server.command,
        args: resolved.server.args,
        cwd: resolved.server.cwd ?? null,
        inheritEnv: resolved.server.inheritEnv,
      },
      tool: request.tool,
      policy: resolved.policy,
    });
    return {
      evidence,
      risk: analyzeText(evidence.event.text),
      provenance,
      action: {
        capability: resolved.policy.capability,
        operation: resolved.policy.operation,
        target: resolved.policy.target,
        boundary: "downstream",
        argumentsHash,
        evidenceContextHash,
        executionPolicyHash,
      },
      server: resolved.server,
      review: {
        server: request.server,
        tool: request.tool,
        arguments: request.arguments,
        argumentsHash,
        evidenceContextHash,
        executionPolicyHash,
        policy: resolved.policy,
      },
    };
  }

  private async forward(
    prepared: ReturnType<ActionLockGateway["prepare"]>,
    request: GatewayRequest,
    decision: ActionLockDecision,
    approval: GatewayResult["approval"],
    approvalReceipt?: PublicReceipt<ApprovalCommitment>,
  ): Promise<GatewayResult> {
    const recordingErrors: NonNullable<GatewayResult["recordingErrors"]> = [];
    const result: GatewayResult = {
      evidence: prepared.evidence,
      risk: prepared.risk,
      review: prepared.review,
      decision,
      executed: false,
      executionStatus: "not_attempted",
      retrySafe: false,
      approval,
      approvalReceipt,
      recordingErrors,
    };

    // Refuse dispatch if we cannot record intent. An intent is not proof of execution.
    try {
      await this.audit(prepared.evidence, request, decision, "dispatch_intent");
    } catch {
      recordingErrors.push("audit_write_failed");
      result.error = "Audit intent could not be confirmed; no downstream call was made. Approval remains consumed.";
      return result;
    }

    let output: unknown;
    let errorCode: string | undefined;
    try {
      output = await this.options.executor.call(prepared.server, request.tool, request.arguments);
      if (output !== null && typeof output === "object" && "isError" in output && output.isError === true) {
        result.executionStatus = "unknown";
        errorCode = "downstream_tool_error";
      } else {
        result.executed = true;
        result.executionStatus = "succeeded";
      }
    } catch {
      // Transport errors can happen after a side effect. Never infer rollback.
      result.executionStatus = "unknown";
      errorCode = "downstream_outcome_unknown";
    }
    if (result.executionStatus === "unknown") {
      result.error = "Downstream outcome is unknown; effects may have occurred. Do not retry automatically or obtain a new approval before reconciliation.";
    }

    let outputHash: string | undefined;
    if (result.executed) {
      try {
        // Return the same JSON snapshot that was hashed; never return an unserializable object.
        const serialized = canonicalJson(output);
        result.output = JSON.parse(serialized) as unknown;
        outputHash = jsonHash(result.output);
      } catch {
        recordingErrors.push("output_serialization_failed");
      }
    }

    if (result.executed && outputHash && approvalReceipt && this.options.receiptSigner) {
      try {
        const execution = this.options.receiptSigner.signExecution({
          actionHash: decision.actionHash,
          approvalReceiptHash: publicReceiptHash(approvalReceipt),
          execution: "succeeded",
          outputHash,
          errorCode: null,
        });
        result.publicReceipts = { approval: approvalReceipt, execution };
      } catch {
        recordingErrors.push("receipt_signing_failed");
      }
    }
    try {
      await this.audit(prepared.evidence, request, decision, result.executionStatus, outputHash, errorCode ?? recordingErrors[0]);
    } catch {
      // The append may have succeeded before checkpoint failure; do not claim no record exists.
      recordingErrors.push("audit_write_failed");
    }
    return result;
  }

  private async audit(
    evidence: EvidenceClaims,
    request: Pick<GatewayRequest, "server" | "tool">,
    decision: ActionLockDecision,
    execution: "not_attempted" | "dispatch_intent" | "succeeded" | "failed" | "unknown",
    outputHash?: string,
    errorCode?: string,
  ): Promise<void> {
    await appendAuditEntry(
      this.options.auditPath,
      {
        actionHash: decision.actionHash,
        decision: decision.decision,
        rule: decision.rule,
        evidenceId: evidence.evidenceId,
        server: request.server,
        tool: request.tool,
        execution,
        outputHash,
        errorCode,
      },
      { checkpointSecret: this.options.auditSecret },
    );
  }
}
