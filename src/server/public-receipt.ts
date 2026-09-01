import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalJson, jsonHash } from "./json";
import type { ActionIntent, ActionLockDecision, Provenance } from "./types";

const RECEIPT_DOMAIN = "actionlock:public-receipt:v1\n";
export const RECEIPT_CANONICALIZATION = "actionlock-cjson-v1" as const;

interface ReceiptKeyFile {
  version: 1;
  algorithm: "Ed25519";
  createdAt: string;
  keyId: string;
  privateKey: string;
  publicKey: string;
}

export interface ApprovalCommitment {
  commitment: "actionlock:approval-commitment:v1";
  approvedAt: string;
  grantId: string;
  server: string;
  tool: string;
  actionHash: string;
  action: {
    capability: ActionIntent["capability"];
    operation: string;
    target: string | null;
    boundary: "inspection" | "downstream";
    argumentsHash: string | null;
    sourceHash: string;
    evidenceContextHash: string | null;
    executionPolicyHash: string | null;
  };
  decision: Pick<ActionLockDecision, "decision" | "rule">;
}

export interface ExecutionCommitment {
  commitment: "actionlock:execution-result:v1";
  completedAt: string;
  actionHash: string;
  approvalReceiptHash: string;
  execution: "succeeded" | "failed";
  outputHash: string | null;
  errorCode: string | null;
}

export interface PublicReceipt<T extends ApprovalCommitment | ExecutionCommitment = ApprovalCommitment | ExecutionCommitment> {
  version: 1;
  issuer: "actionlock";
  kind: T extends ApprovalCommitment ? "approval" : "execution";
  canonicalization: typeof RECEIPT_CANONICALIZATION;
  key: {
    algorithm: "Ed25519";
    keyId: string;
    publicKey: string;
  };
  payload: T;
  signature: string;
}

type UnsignedReceipt<T extends ApprovalCommitment | ExecutionCommitment> = Omit<PublicReceipt<T>, "signature">;

function keyId(publicKey: string): string {
  return createHash("sha256").update(Buffer.from(publicKey, "base64url")).digest("hex");
}

function encodePublicKey(key: KeyObject): string {
  return key.export({ format: "der", type: "spki" }).toString("base64url");
}

function encodePrivateKey(key: KeyObject): string {
  return key.export({ format: "der", type: "pkcs8" }).toString("base64url");
}

function privateKeyFrom(value: string): KeyObject {
  return createPrivateKey({ key: Buffer.from(value, "base64url"), format: "der", type: "pkcs8" });
}

function publicKeyFrom(value: string): KeyObject {
  return createPublicKey({ key: Buffer.from(value, "base64url"), format: "der", type: "spki" });
}

function signingBytes(value: object): Buffer {
  return Buffer.from(`${RECEIPT_DOMAIN}${canonicalJson(value)}`, "utf8");
}

function assertHash(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`Invalid ${name}`);
}

function isHashOrNull(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && /^[a-f0-9]{64}$/.test(value));
}

function recomputeActionHash(payload: ApprovalCommitment): string {
  return jsonHash({
    domain: "actionlock:action:v2",
    capability: payload.action.capability,
    operation: payload.action.operation,
    target: payload.action.target,
    boundary: payload.action.boundary,
    argumentsHash: payload.action.argumentsHash,
    sourceHash: payload.action.sourceHash,
    evidenceContextHash: payload.action.evidenceContextHash,
    executionPolicyHash: payload.action.executionPolicyHash,
  });
}

function validatePayload(receipt: PublicReceipt): boolean {
  const payload = receipt.payload;
  if (receipt.kind === "approval") {
    if (payload.commitment !== "actionlock:approval-commitment:v1") return false;
    const approval = payload as ApprovalCommitment;
    assertHash(approval.actionHash, "action hash");
    assertHash(approval.action.sourceHash, "source hash");
    if (
      approval.decision.decision !== "allow" ||
      approval.decision.rule !== "ACTIONLOCK-031" ||
      approval.action.boundary !== "downstream" ||
      !isHashOrNull(approval.action.argumentsHash) ||
      !isHashOrNull(approval.action.evidenceContextHash) ||
      !isHashOrNull(approval.action.executionPolicyHash)
    ) return false;
    if (!/^[a-f0-9]{32}$/.test(approval.grantId)) return false;
    if (!Number.isFinite(Date.parse(approval.approvedAt))) return false;
    return recomputeActionHash(approval) === approval.actionHash;
  }
  if (receipt.kind === "execution") {
    if (payload.commitment !== "actionlock:execution-result:v1") return false;
    const execution = payload as ExecutionCommitment;
    assertHash(execution.actionHash, "action hash");
    assertHash(execution.approvalReceiptHash, "approval receipt hash");
    if (execution.outputHash !== null) assertHash(execution.outputHash, "output hash");
    if (
      (execution.execution === "succeeded" && (execution.outputHash === null || execution.errorCode !== null)) ||
      (execution.execution === "failed" && (execution.outputHash !== null || execution.errorCode === null))
    ) return false;
    return Number.isFinite(Date.parse(execution.completedAt));
  }
  return false;
}

export class PublicReceiptSigner {
  readonly keyId: string;
  readonly publicKey: string;

  constructor(private readonly privateKey: KeyObject, publicKey: KeyObject) {
    this.publicKey = encodePublicKey(publicKey);
    this.keyId = keyId(this.publicKey);
  }

  signApproval(input: {
    grantId: string;
    server: string;
    tool: string;
    action: ActionIntent;
    provenance: Provenance;
    decision: ActionLockDecision;
    now?: Date;
  }): PublicReceipt<ApprovalCommitment> {
    const payload: ApprovalCommitment = {
      commitment: "actionlock:approval-commitment:v1",
      approvedAt: (input.now ?? new Date()).toISOString(),
      grantId: input.grantId,
      server: input.server,
      tool: input.tool,
      actionHash: input.decision.actionHash,
      action: {
        capability: input.action.capability,
        operation: input.action.operation,
        target: input.action.target ?? null,
        boundary: input.action.boundary ?? "inspection",
        argumentsHash: input.action.argumentsHash ?? null,
        sourceHash: input.provenance.contentHash,
        evidenceContextHash: input.action.evidenceContextHash ?? null,
        executionPolicyHash: input.action.executionPolicyHash ?? null,
      },
      decision: { decision: input.decision.decision, rule: input.decision.rule },
    };
    return this.sign("approval", payload);
  }

  signExecution(input: Omit<ExecutionCommitment, "commitment" | "completedAt"> & { now?: Date }): PublicReceipt<ExecutionCommitment> {
    return this.sign("execution", {
      commitment: "actionlock:execution-result:v1",
      completedAt: (input.now ?? new Date()).toISOString(),
      actionHash: input.actionHash,
      approvalReceiptHash: input.approvalReceiptHash,
      execution: input.execution,
      outputHash: input.outputHash,
      errorCode: input.errorCode,
    });
  }

  private sign<T extends ApprovalCommitment | ExecutionCommitment>(
    kind: T extends ApprovalCommitment ? "approval" : "execution",
    payload: T,
  ): PublicReceipt<T> {
    const unsigned: UnsignedReceipt<T> = {
      version: 1,
      issuer: "actionlock",
      kind,
      canonicalization: RECEIPT_CANONICALIZATION,
      key: { algorithm: "Ed25519", keyId: this.keyId, publicKey: this.publicKey },
      payload,
    };
    return { ...unsigned, signature: sign(null, signingBytes(unsigned), this.privateKey).toString("base64url") };
  }
}

export async function loadOrCreateReceiptSigner(path: string): Promise<PublicReceiptSigner> {
  await mkdir(dirname(path), { recursive: true });
  try {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const encodedPublicKey = encodePublicKey(publicKey);
    const keyFile: ReceiptKeyFile = {
      version: 1,
      algorithm: "Ed25519",
      createdAt: new Date().toISOString(),
      keyId: keyId(encodedPublicKey),
      privateKey: encodePrivateKey(privateKey),
      publicKey: encodedPublicKey,
    };
    await writeFile(path, `${canonicalJson(keyFile)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    return new PublicReceiptSigner(privateKey, publicKey);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }

  const parsed = JSON.parse(await readFile(path, "utf8")) as ReceiptKeyFile;
  if (parsed.version !== 1 || parsed.algorithm !== "Ed25519" || parsed.keyId !== keyId(parsed.publicKey)) {
    throw new Error("Invalid ActionLock receipt signing key file");
  }
  const privateKey = privateKeyFrom(parsed.privateKey);
  const derivedPublic = encodePublicKey(createPublicKey(privateKey));
  if (derivedPublic !== parsed.publicKey) throw new Error("Receipt signing key pair does not match");
  return new PublicReceiptSigner(privateKey, publicKeyFrom(parsed.publicKey));
}

export function publicReceiptHash(receipt: PublicReceipt): string {
  return jsonHash(receipt);
}

export function verifyPublicReceipt(
  value: unknown,
  options: { expectedKeyIds?: string[] } = {},
): { valid: boolean; keyId: string | null; kind: "approval" | "execution" | null; receiptHash: string | null } {
  try {
    const receipt = value as PublicReceipt;
    if (
      !receipt ||
      receipt.version !== 1 ||
      receipt.issuer !== "actionlock" ||
      (receipt.kind !== "approval" && receipt.kind !== "execution") ||
      receipt.canonicalization !== RECEIPT_CANONICALIZATION ||
      receipt.key?.algorithm !== "Ed25519" ||
      receipt.key.keyId !== keyId(receipt.key.publicKey) ||
      !/^[A-Za-z0-9_-]{86}$/.test(receipt.signature) ||
      !validatePayload(receipt)
    ) {
      return { valid: false, keyId: null, kind: null, receiptHash: null };
    }
    if (options.expectedKeyIds?.length && !options.expectedKeyIds.includes(receipt.key.keyId)) {
      return { valid: false, keyId: receipt.key.keyId, kind: receipt.kind, receiptHash: null };
    }
    const { signature, ...unsigned } = receipt;
    const valid = verify(null, signingBytes(unsigned), publicKeyFrom(receipt.key.publicKey), Buffer.from(signature, "base64url"));
    return {
      valid,
      keyId: receipt.key.keyId,
      kind: receipt.kind,
      receiptHash: valid ? publicReceiptHash(receipt) : null,
    };
  } catch {
    return { valid: false, keyId: null, kind: null, receiptHash: null };
  }
}

export function verifyPublicReceiptBundle(
  value: unknown,
  options: { expectedKeyIds?: string[] } = {},
): {
  valid: boolean;
  approval: ReturnType<typeof verifyPublicReceipt>;
  execution: ReturnType<typeof verifyPublicReceipt>;
} {
  const bundle = value as { approval?: unknown; execution?: unknown };
  const approval = verifyPublicReceipt(bundle?.approval, options);
  const execution = verifyPublicReceipt(bundle?.execution, options);
  if (!approval.valid || !execution.valid) return { valid: false, approval, execution };
  const approvalReceipt = bundle.approval as PublicReceipt<ApprovalCommitment>;
  const executionReceipt = bundle.execution as PublicReceipt<ExecutionCommitment>;
  return {
    valid:
      executionReceipt.payload.actionHash === approvalReceipt.payload.actionHash &&
      executionReceipt.payload.approvalReceiptHash === publicReceiptHash(approvalReceipt),
    approval,
    execution,
  };
}
