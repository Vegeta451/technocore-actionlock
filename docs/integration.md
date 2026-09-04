# Agent integration

ActionLock is a local stdio MCP boundary. The hosted Vercel console is an inspection surface and cannot execute tools.

## Connection model

```text
agent MCP client
  -> ActionLock MCP server
     -> evidence and policy decision
     -> exact human approval when eligible
     -> allow-listed downstream MCP tool
     -> append-only local audit chain
```

Do not also expose the same downstream MCP server, shell, wallet, or social tool directly to the agent. That bypasses ActionLock.

## 1. Install

Use Node.js 20 or newer.

```bash
git clone https://github.com/Vegeta451/technocore-actionlock.git
cd technocore-actionlock
npm install
npm run check
npm run check:mcp
```

`check:mcp` performs a real local stdio handshake using the official MCP client SDK. It must report five tools and a fail-closed empty policy list.

## 2. Define the downstream policy

Copy `actionlock.config.example.json` to the ignored local file `actionlock.config.json`. Use absolute executable paths. Each exposed downstream tool must have a fixed capability, operation, target, and maximum argument size.

Keep `inheritEnv` empty unless the downstream server requires a specifically named variable. Never place secrets in this policy file.

## 3. Set the local secret

Generate at least 32 random bytes. Keep this value local and never commit it.

```bash
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
```

Set the output as `ACTIONLOCK_ROOT_SECRET`. Optionally set `ACTIONLOCK_CONFIG`, `ACTIONLOCK_STATE_DIR`, `ACTIONLOCK_AUDIT_PATH`, and `ACTIONLOCK_RECEIPT_KEY_PATH` to absolute paths. `TECHNOCORE_ORIGIN` should remain `https://technocore.chat` outside loopback development. The MCP gateway creates its Ed25519 receipt key on first startup; keep that file private and back it up if stable receipt identity matters.

Print only the public receipt identity with `npm run receipt:key`. Publish its `keyId` through a separately trusted project page, release note, or DNS record. Never publish the signing-key file.

## 4. Add ActionLock to the agent

Use the agent client's local stdio MCP settings. Replace the paths and secret locally:

```json
{
  "mcpServers": {
    "actionlock": {
      "command": "npm",
      "args": ["--prefix", "/absolute/path/technocore-actionlock", "run", "mcp"],
      "env": {
        "ACTIONLOCK_ROOT_SECRET": "<local-secret-at-least-32-bytes>",
        "ACTIONLOCK_CONFIG": "/absolute/path/actionlock.config.json"
      }
    }
  }
}
```

Restart the MCP client. It should discover only these ActionLock tools:

- `actionlock_read_room`
- `actionlock_list_policies`
- `actionlock_preview`
- `actionlock_execute`
- `actionlock_verify_audit`

## 5. Execute an approved call

1. Call `actionlock_read_room` and retain the short-lived evidence token.
2. Call `actionlock_list_policies`; an empty list means execution is disabled.
3. Call `actionlock_preview` with the exact server, tool, and arguments.
4. Review the action hash outside the agent process.
5. Run `npm run approve -- <action-hash>` locally.
6. Pass the returned one-time token to `actionlock_execute` without changing any argument.
7. Call `actionlock_verify_audit` after execution.
8. Save the returned `publicReceipts.approval` and `publicReceipts.execution` objects when independent review is required.

Approvals expire after 120 seconds and are consumed before the downstream call starts. Shell, wallet, and social actions derived from remote content remain blocked rather than approval-eligible.

When completion and receipt signing succeed, `actionlock_execute` returns the linked pair at `publicReceipts.approval` and `publicReceipts.execution`. Save the complete `publicReceipts` object to verify the pair, or save one member to verify that receipt without the gateway secret. For incomplete results, follow the outcome handling below:

```bash
npm run verify:receipt -- receipt.json <expected-key-id>
```

Always obtain the expected key ID through a separately trusted channel. Reading it only from the receipt verifies signature integrity but not the operator's identity. The approval receipt records what the gateway allowed before execution; the execution receipt separately records success or failure and links back to the approval receipt hash.

V1 verification checks the complete envelope and payload shape, UTC ISO timestamps,
canonical unpadded base64url encoding, and an actual Ed25519 SPKI public key. Missing,
mistyped, and unknown fields are rejected, even if signed. A linked pair must contain
an approval in the approval slot and an execution in the execution slot, signed by
the same key. Listing multiple trusted key IDs does not authorize cross-key pairs.
Keep a rotation between calls, not between approval and result; authenticated
rotation history is not implemented. A timestamp is still an operator assertion,
not independent time evidence. Valid historical `failed` receipts remain readable.

## Execution outcomes and reconciliation

Read `executionStatus`, not only the legacy `executed` boolean:

- `not_attempted`: this request was not forwarded. An approval may already have been consumed.
- `succeeded`: the executor returned without a tool error. This is a gateway observation, not independent proof of the real-world effect.
- `unknown`: the executor threw or returned an MCP `isError` result. Effects may already have occurred; this does not imply rollback.

Every result has `retrySafe: false`. Do not automatically resubmit or obtain a fresh approval after an uncertain outcome. Reconcile using the downstream system's records and the action hash. A new approval has a new grant ID and can cause a second effect; replay protection is per grant, not exactly-once execution across approvals.

The gateway records `dispatch_intent` before calling the executor. If that audit write cannot be confirmed, no call is made. An intent alone does not prove dispatch or completion: a crash can occur on either side of the call. After the call, output serialization, receipt signing, and audit failures appear separately in `recordingErrors`; they do not erase the observed outcome. `audit_write_failed` means recording was not confirmed, not that no bytes were written (append may precede a failed checkpoint).

`approvalReceipt` preserves the signed approval when available. A complete `publicReceipts` pair is returned only when a successful response was hashed and signed. Unknown outcomes have no execution receipt; the legacy V1 `failed` receipt format remains readable but is not used to claim that a transport error caused no effect. Preserve the response and repair recording before further execution. Process termination or connection loss can still prevent delivery of this response.
