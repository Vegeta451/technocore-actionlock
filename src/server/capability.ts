import { jsonHash } from "./json";
import type {
  ActionIntent,
  ActionLockDecision,
  Provenance,
  RiskAssessment,
} from "./types";

const READ_ONLY = new Set(["observe", "network_read", "file_read"]);
const ALWAYS_SENSITIVE = new Set(["shell", "wallet", "social"]);

export function actionHash(action: ActionIntent, provenance: Provenance): string {
  return jsonHash({
    capability: action.capability,
    operation: action.operation,
    target: action.target ?? null,
    boundary: action.boundary ?? "inspection",
    argumentsHash: action.argumentsHash ?? null,
    sourceHash: provenance.contentHash,
  });
}

export function evaluateCapability(input: {
  action: ActionIntent;
  provenance: Provenance;
  risk: RiskAssessment;
  approvedActionHash?: string;
}): ActionLockDecision {
  const { action, provenance, risk, approvedActionHash } = input;
  const hash = actionHash(action, provenance);
  const approved = approvedActionHash === hash;

  let decision: ActionLockDecision["decision"];
  let rule: string;
  let reason: string;
  let approvalEligible = false;

  if (risk.findings.some((finding) => finding.code === "technocore_get_write_url")) {
    decision = "block";
    rule = "ACTIONLOCK-001";
    reason = "Technocore GET-write URLs are never fetched from message content.";
  } else if (provenance.trust === "untrusted_remote" && ALWAYS_SENSITIVE.has(action.capability)) {
    decision = "block";
    rule = "ACTIONLOCK-020";
    reason = "Remote messages cannot authorize shell, wallet, or social capabilities.";
  } else if (provenance.trust === "untrusted_remote" && action.boundary === "downstream") {
    approvalEligible = true;
    if (approved) {
      decision = "allow";
      rule = "ACTIONLOCK-031";
      reason = "A matching one-action approval was supplied for this exact evidence, tool, and arguments.";
    } else {
      decision = "approval_required";
      rule = "ACTIONLOCK-030";
      reason = "Every downstream call derived from remote content requires an exact approval.";
    }
  } else if (READ_ONLY.has(action.capability) && risk.action !== "block") {
    decision = "allow";
    rule = "ACTIONLOCK-010";
    reason = "Bounded built-in inspection is permitted; provenance remains attached.";
  } else if (provenance.trust === "untrusted_remote") {
    approvalEligible = true;
    if (approved) {
      decision = "allow";
      rule = "ACTIONLOCK-031";
      reason = "A matching one-action approval was supplied for this exact source and target.";
    } else {
      decision = "approval_required";
      rule = "ACTIONLOCK-030";
      reason = "Remote-derived side effects require explicit approval bound to this action.";
    }
  } else if (ALWAYS_SENSITIVE.has(action.capability) && !approved) {
    decision = "approval_required";
    rule = "ACTIONLOCK-040";
    reason = "Sensitive local actions require an explicit one-action approval.";
    approvalEligible = true;
  } else {
    decision = "allow";
    rule = "ACTIONLOCK-050";
    reason = "The local action is within the read/write policy boundary.";
  }

  return {
    decision,
    rule,
    reason,
    approvalEligible,
    actionHash: hash,
    receiptHash: jsonHash({ decision, rule, hash, riskScore: risk.score }),
  };
}
