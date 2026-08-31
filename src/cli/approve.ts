import { issueApprovalGrant } from "../server/approval";
import { assertRootSecret, deriveSecret } from "../server/secrets";

const [actionHash] = process.argv.slice(2);
if (!actionHash || !/^[a-f0-9]{64}$/.test(actionHash)) {
  throw new Error("Usage: pnpm approve -- <64-character-action-hash>");
}

const rootSecret = assertRootSecret(process.env.ACTIONLOCK_ROOT_SECRET);
const token = issueApprovalGrant({
  actionHash,
  secret: deriveSecret(rootSecret, "approval"),
  ttlSeconds: 120,
});
process.stdout.write(`${JSON.stringify({ token, expiresInSeconds: 120 })}\n`);
