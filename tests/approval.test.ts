import { describe, expect, it } from "vitest";
import { issueApprovalGrant, verifyApprovalGrant } from "../src/server/approval";

const secret = "correct horse battery staple with enough entropy";

describe("approval grants", () => {
  it("binds a short-lived grant to one action and nonce", () => {
    const actionHash = "b".repeat(64);
    const token = issueApprovalGrant({ actionHash, secret, ttlSeconds: 60, nowSeconds: 100 });
    const grant = verifyApprovalGrant({ token, actionHash, secret, nowSeconds: 120 });
    expect(grant?.actionHash).toBe(actionHash);
    expect(grant?.grantId).toMatch(/^[a-f0-9]{32}$/);
    expect(verifyApprovalGrant({ token, actionHash: "c".repeat(64), secret, nowSeconds: 120 })).toBeNull();
  });

  it("rejects tampering and expiration", () => {
    const actionHash = "d".repeat(64);
    const token = issueApprovalGrant({ actionHash, secret, ttlSeconds: 1, nowSeconds: 100 });
    expect(verifyApprovalGrant({ token: `${token}x`, actionHash, secret, nowSeconds: 100 })).toBeNull();
    expect(verifyApprovalGrant({ token, actionHash, secret, nowSeconds: 105 })).toBeNull();
  });
});
