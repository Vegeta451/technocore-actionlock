# ActionLock for Technocore

ActionLock is an enforced MCP capability gateway for agents that consume untrusted Technocore messages. It keeps sender authenticity, content safety, human approval, and permission to act as separate decisions.

Community project. Not affiliated with or endorsed by FLOP Labs.

**Live:** [Public console](https://technocore-actionlock.vercel.app/) · [Choose user or builder path](https://technocore-actionlock.vercel.app/start) · [Documentation](https://technocore-actionlock.vercel.app/docs) · [Machine-readable overview](https://technocore-actionlock.vercel.app/llms.txt)

## Why it exists

Technocore rooms are world-writable. A valid `did:key` signature proves that a key signed a message; it does not make the message safe or authorize that message to control tools.

ActionLock closes the gap between reading a message and performing a side effect:

1. `actionlock_read_room` fetches a bounded room window from the pinned Technocore origin.
2. Each observed message receives a short-lived HMAC evidence receipt.
3. A trusted local config maps an exact downstream MCP tool to its capability, operation, target, and argument limit.
4. `actionlock_preview` derives a versioned action hash from the complete evidence receipt, server, tool, executable policy, and canonical argument hash.
5. A human may issue one short-lived approval for that exact action hash.
6. `actionlock_execute` consumes the approval atomically before forwarding the call to the configured MCP server.
7. The gateway signs the approved action and the later execution result as separate Ed25519 receipts.
8. The decision and execution outcome are appended to a locked hash chain with an HMAC-protected head checkpoint.

The model cannot declare its own capability class, invent evidence, substitute the evidence/server/tool/policy/arguments after approval, or replay an approval after restart.

## Security properties

- Technocore message URLs are data and are never followed automatically.
- GET-shaped Technocore write URLs embedded in content are always blocked.
- Shell, wallet, and social actions derived from remote content remain blocked even when an approval token is supplied.
- Every downstream call derived from remote content requires an exact approval.
- Capability, operation, target, command, and environment inheritance come only from trusted local config.
- Approval replay protection uses atomic exclusive file creation and survives process restarts.
- Audit appenders use an inter-process lock and refuse to extend an invalid chain.
- Ed25519 approval receipts contain the complete action-hash inputs; execution receipts link to the approval receipt without rewriting what was approved.
- The hosted web console has no root secret, downstream config, private key, write tool, or approval issuer.

## Policy rules

| Rule | Condition | Result |
| --- | --- | --- |
| `ACTIONLOCK-001` | Message embeds a Technocore GET-write URL | Block |
| `ACTIONLOCK-010` | Bounded built-in inspection | Allow with provenance |
| `ACTIONLOCK-020` | Remote content requests shell, wallet, or social access | Block |
| `ACTIONLOCK-030` | Remote content reaches a configured downstream tool | Exact approval required |
| `ACTIONLOCK-031` | Approval matches evidence, tool policy, target, and canonical arguments | Allow once |
| `ACTIONLOCK-040` | Sensitive local action lacks approval | Approval required |
| `ACTIONLOCK-050` | Local action is inside the configured policy boundary | Allow |

## Run the public console

Requirements: Node.js 20 or newer.

```bash
npm install
npm run check
npm run check:mcp
npm run dev
```

Open `http://127.0.0.1:3000`. The web console is a read-only inspection and policy-simulation surface. It cannot issue evidence receipts or execute tools.

Console users can scan the newest 25, 50, 100, or 200 retained room messages, enable a 30- or 60-second refresh, search and filter the current window, or run a user-triggered exact-sequence lookup. Current-window matches resolve locally; older sequences use the bounded room export. A found record enters the same signature, provenance, and risk pipeline as a live scan. Users can pin up to 100 evidence records in browser-local IndexedDB and export the selected evidence as JSON. These actions remain inspection operations; they do not post to Technocore or execute a downstream tool.

The console distinguishes an empty retained window, a record that has rotated out, an unexplained sequence gap, and a temporary Technocore outage. Exact lookup is capped at 12 MiB and never runs on refresh. Browser pins stay on that browser profile; the hosted application remains stateless and is not a historical archive.

## Run the enforced MCP gateway

### Partial reads and upstream failures

Room scans validate the response envelope before checking each record. Malformed records are excluded, never repaired or issued evidence receipts. Both the console and MCP response report `rejectedCount`; a nonzero value means partial coverage, not a clean room. A malformed envelope, inconsistent count, or mismatched room fails the entire read. Exact-sequence exports remain fail-closed on malformed records.

Nonce and sequence values retain their exact integer text, including values beyond JavaScript's safe integer range. Upstream error bodies are discarded rather than passed into agent tool results. Redirects are not followed; transient 502/503/504 responses have bounded retries. These controls do not make message content trustworthy.

The browser stops a scan after 20 seconds and enables retry. A failed refresh preserves the previous window with an explicit stale-results warning. A response containing only malformed records is distinct from an empty retained window.

### Browser regression checks

After installing dependencies, run `npx playwright install chromium`, `npm run build`, then `npm run test:e2e`. The suite starts an isolated production server on loopback port 4327 and closes it afterward; an occupied port is an error rather than permission to reuse another server. Tests use synthetic scan responses, not live Technocore traffic, and cover desktop and mobile partial reads, empty/all-invalid windows, upstream outages, stale-result recovery, and timeouts. Screenshots are written to ignored `test-results/`. CI runs these checks in addition to the unit and MCP tests.

Generate a local root secret:

```bash
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
```

Set that value as `ACTIONLOCK_ROOT_SECRET`. Copy `actionlock.config.example.json` to the ignored `actionlock.config.json`, then replace the example command with an absolute path to a trusted MCP server. Do not put secrets in the config; use `inheritEnv` to name only the environment variables that server needs.

```bash
npm run mcp
```

The MCP server exposes:

- `actionlock_read_room`
- `actionlock_list_policies`
- `actionlock_preview`
- `actionlock_execute`
- `actionlock_verify_audit`

A missing config produces an empty policy list and disables all downstream execution.

On first local MCP startup, ActionLock creates an Ed25519 receipt key at
`<ACTIONLOCK_STATE_DIR>/receipt-signing-key.json` with owner-only file permissions. Set
`ACTIONLOCK_RECEIPT_KEY_PATH` to use another absolute path. Back up this file separately from the
HMAC root secret if historical receipt identity matters.

Print the public identity without exposing the private key:

```bash
npm run receipt:key
```

Publish the returned `keyId` through a separately trusted project page, release note, or DNS record.
Do not publish `receipt-signing-key.json`; it contains the private signing key.

Verify the real stdio handshake before connecting an agent:

```bash
npm run check:mcp
```

The smoke test starts ActionLock with an isolated temporary state directory, connects with the official MCP client SDK, verifies the five advertised tools, confirms that the policy list is empty without trusted config, and closes without retaining local state.

## Approve one exact call

Run `actionlock_preview` first and review the evidence, downstream server, tool, arguments, policy, and action hash. Issue an approval outside the agent process:

```bash
npm run approve -- <64-character-action-hash>
```

Pass the returned token to `actionlock_execute` without changing any argument. The token expires within 120 seconds and is consumed before the downstream call starts. A failed downstream call still consumes it.

An approved execution returns two public receipts under `publicReceipts`: an `approval` commitment signed before the downstream call and an `execution` commitment signed after it. Save the complete `publicReceipts` object to verify the linked pair, or save either receipt to verify it independently:

```bash
npm run verify:receipt -- receipt.json <expected-key-id>
```

The embedded public key verifies the signature but does not establish who owns that key. Pin the expected key ID from a separately trusted channel. Key rotation uses a new key file; retain the old public key ID when historical receipts must remain attributable.

## Vercel profile

The hosted application is stateless by design:

- no server-side database or scheduled polling; optional pins use browser-local IndexedDB only;
- no wallet, Technocore signing key, root secret, or gateway config;
- room scans run only on request;
- scan responses are bounded to the newest 200 retained messages and cached at the edge for 30 seconds;
- exact-sequence lookups are user-triggered, uncached, streamed from the room export, and fail closed above 12 MiB;
- Technocore exposes no backwards pagination. Export lookup can find a record only while it remains in the room ring, and reports `not_retained` after rotation.

Create it as a separate Vercel project. Do not attach another project's environment variables, domains, or deployment settings.

## Brand assets

The ActionLock mark combines an `A` boundary with an `L` controlled exit. The white crossbar is an observed message and the amber point is its evidence commitment.

- `public/brand/actionlock-x-avatar.png` — X profile image, 400 × 400
- `public/brand/actionlock-x-banner.png` — X banner, 1500 × 500
- `public/brand/actionlock-mark-master.png` — transparent raster master, 1024 × 1024
- `public/brand/actionlock-mark.svg` — scalable dark-on-light mark

## Verification

```bash
npm run check
npm run check:mcp
npm run build
```

Tests cover canonical Technocore signatures, big-integer evidence, HMAC receipt tampering and expiry, independently verifiable Ed25519 approval/result receipts, expected-key pinning, exact evidence/server/tool/policy/argument approval binding, bounded HTTP bodies, persistent replay protection, audit quotas, concurrent audit appends, blocked sensitive capabilities, and end-to-end gateway execution.

Protocol verification includes fixed RFC 8032-backed vectors from [`techbone/technocore-conformance`](https://github.com/techbone/technocore-conformance), rather than relying only on values generated by ActionLock itself.

See [SECURITY.md](./SECURITY.md), [docs/architecture.md](./docs/architecture.md), and [docs/landscape.md](./docs/landscape.md).

For a complete agent setup, MCP client example, approval sequence, and bypass warning, see [docs/integration.md](./docs/integration.md) or the hosted [`/docs`](https://technocore-actionlock.vercel.app/docs) page.

Coding agents should read [AGENTS.md](./AGENTS.md). Runtime agents and crawlers can use the hosted [`/llms.txt`](https://technocore-actionlock.vercel.app/llms.txt) overview.

## Limits

ActionLock protects only tools routed through its gateway. An agent with a separate unrestricted shell, wallet, social, or downstream MCP connection can bypass it; remove those bypass paths from the agent's capability set.

The local HMAC checkpoint detects edits to the current audit head. It cannot detect coordinated rollback of both the audit log and checkpoint unless the head hash is copied to an external append-only system.

Public receipts use the pinned `actionlock-cjson-v1` canonicalization profile. They prove that the holder of the corresponding Ed25519 private key signed the included commitment. They do not prove that the observed message was true, the action succeeded beyond the recorded result, or the key belongs to ActionLock unless its key ID was obtained independently.

## Sources

- [Technocore Chat repository](https://github.com/flop-labs/technocore-chat)
- [Technocore security policy](https://github.com/flop-labs/technocore-chat/blob/main/SECURITY.md)
- [MCP specification](https://modelcontextprotocol.io/specification/)

## License

MIT
