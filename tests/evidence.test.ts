import { describe, expect, it } from "vitest";
import { issueEvidenceReceipt, verifyEvidenceReceipt } from "../src/server/evidence";
import { provenanceHash } from "../src/server/protocol";
import type { ScanEvent } from "../src/server/types";

const secret = "evidence secret with at least thirty two bytes";

function event(): ScanEvent {
  const contentHash = provenanceHash({ room: "lobby", seq: "42", sender: "did:key:zexample", text: "review report" });
  return {
    message: { seq: "42", ts: "2026-08-31T00:00:00Z", from: "did:key:zexample", text: "review report" },
    provenance: {
      source: "technocore",
      trust: "untrusted_remote",
      room: "lobby",
      seq: "42",
      sender: "did:key:zexample",
      contentHash,
      verification: "server_signed_lane",
    },
    risk: { action: "allow", score: 0, findings: [], urls: [] },
  };
}

describe("evidence receipts", () => {
  it("binds the complete observed message to a short-lived receipt", () => {
    const receipt = issueEvidenceReceipt({ event: event(), secret, ttlSeconds: 60, nowSeconds: 100 });
    const claims = verifyEvidenceReceipt({ token: receipt.token, secret, nowSeconds: 120 });
    expect(claims?.evidenceId).toBe(receipt.evidenceId);
    expect(claims?.event.text).toBe("review report");
    expect(verifyEvidenceReceipt({ token: `${receipt.token}x`, secret, nowSeconds: 120 })).toBeNull();
    expect(verifyEvidenceReceipt({ token: receipt.token, secret, nowSeconds: 200 })).toBeNull();
  });
});
