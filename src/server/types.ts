export type VerificationState =
  | "verified"
  | "invalid"
  | "server_signed_lane"
  | "unsigned"
  | "not_available";

export type RiskAction = "allow" | "quarantine" | "block";
export type RiskSeverity = "low" | "medium" | "high" | "critical";

export type Capability =
  | "observe"
  | "network_read"
  | "network_write"
  | "file_read"
  | "file_write"
  | "shell"
  | "wallet"
  | "social";

export type Decision = "allow" | "approval_required" | "block";
export type TrustLevel = "local_user" | "untrusted_remote";

export interface TechnocoreMessage {
  seq: string;
  ts: string;
  from: string;
  text: string;
  nonce?: string;
  sig?: string;
}

export interface RoomRead {
  rejectedCount: number;
  room: string;
  count: number;
  first_seq: string;
  last_seq: string;
  generation?: number;
  messages: TechnocoreMessage[];
}

export interface RiskFinding {
  code: string;
  title: string;
  severity: RiskSeverity;
  evidence: string;
}

export interface RiskAssessment {
  action: RiskAction;
  score: number;
  findings: RiskFinding[];
  urls: string[];
}

export interface Provenance {
  source: "technocore" | "local_user";
  trust: TrustLevel;
  room?: string;
  seq?: string;
  sender?: string;
  contentHash: string;
  verification: VerificationState;
}

export interface ActionIntent {
  capability: Capability;
  operation: string;
  target?: string;
  reversible?: boolean;
  boundary?: "inspection" | "downstream";
  argumentsHash?: string;
  evidenceContextHash?: string;
  executionPolicyHash?: string;
}

export interface ActionLockDecision {
  decision: Decision;
  rule: string;
  reason: string;
  approvalEligible: boolean;
  actionHash: string;
  receiptHash: string;
}

export interface EvidenceEvent {
  room: string;
  seq: string;
  ts: string;
  sender: string;
  text: string;
  verification: VerificationState;
  contentHash: string;
}

export interface EvidenceClaims {
  version: 1;
  issuer: "actionlock";
  audience: "actionlock-gateway";
  issuedAt: number;
  expiresAt: number;
  evidenceId: string;
  event: EvidenceEvent;
}

export interface GatewayToolPolicy {
  capability: Capability;
  operation: string;
  target: string;
  maxArgumentBytes: number;
}

export interface ScanEvent {
  message: TechnocoreMessage;
  provenance: Provenance;
  risk: RiskAssessment;
}

export interface StoredEvent {
  room: string;
  seq: string;
  ts: string;
  sender: string;
  text: string;
  nonce: string | null;
  verification: VerificationState;
  riskAction: RiskAction;
  riskScore: number;
  findings: RiskFinding[];
  contentHash: string;
  observedAt: string;
}
