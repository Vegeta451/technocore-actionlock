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
    policy: GatewayToolPolicy;
  };
}

export interface GatewayResult extends GatewayPreview {
  executed: boolean;
  approval: "not_required" | "required" | "invalid" | "replayed" | "consumed";
  output?: unknown;
  error?: string;
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
          approval: "invalid",
        };
      }
      const consumed = await this.options.replayStore.consume(grant.grantId, grant.expiresAt);
      if (!consumed) {
        await this.audit(prepared.evidence, request, initial, "not_attempted", undefined, "approval_replay");
        return {
          evidence: prepared.evidence,
          risk: prepared.risk,
          review: prepared.review,
          decision: initial,
          executed: false,
          approval: "replayed",
        };
      }
      const allowed = evaluateCapability({
        action: prepared.action,
        provenance: prepared.provenance,
        risk: prepared.risk,
        approvedActionHash: initial.actionHash,
      });
      return this.forward(prepared, request, allowed, "consumed");
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
      },
      server: resolved.server,
      review: {
        server: request.server,
        tool: request.tool,
        arguments: request.arguments,
        argumentsHash,
        policy: resolved.policy,
      },
    };
  }

  private async forward(
    prepared: ReturnType<ActionLockGateway["prepare"]>,
    request: GatewayRequest,
    decision: ActionLockDecision,
    approval: GatewayResult["approval"],
  ): Promise<GatewayResult> {
    try {
      const output = await this.options.executor.call(prepared.server, request.tool, request.arguments);
      await this.audit(prepared.evidence, request, decision, "succeeded", jsonHash(output));
      return {
        evidence: prepared.evidence,
        risk: prepared.risk,
        review: prepared.review,
        decision,
        executed: true,
        approval,
        output,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Downstream execution failed";
      await this.audit(prepared.evidence, request, decision, "failed", undefined, "downstream_error");
      return {
        evidence: prepared.evidence,
        risk: prepared.risk,
        review: prepared.review,
        decision,
        executed: false,
        approval,
        error: message,
      };
    }
  }

  private async audit(
    evidence: EvidenceClaims,
    request: Pick<GatewayRequest, "server" | "tool">,
    decision: ActionLockDecision,
    execution: "not_attempted" | "succeeded" | "failed",
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
