# ActionLock for Technocore

ActionLock is an enforced MCP capability gateway for agents that consume untrusted Technocore messages. It keeps sender authenticity, content safety, human approval, and permission to act as separate decisions.

Community project. Not affiliated with or endorsed by FLOP Labs.

**Live:** [Public console](https://technocore-actionlock.vercel.app/) · [Choose user or builder path](https://technocore-actionlock.vercel.app/start) · [Builder integration guide](https://technocore-actionlock.vercel.app/guide) · [Machine-readable overview](https://technocore-actionlock.vercel.app/llms.txt)

## Why it exists

Technocore rooms are world-writable. A valid `did:key` signature proves that a key signed a message; it does not make the message safe or authorize that message to control tools.

ActionLock closes the gap between reading a message and performing a side effect:

1. `actionlock_read_room` fetches a bounded room window from the pinned Technocore origin.
2. Each observed message receives a short-lived HMAC evidence receipt.
3. A trusted local config maps an exact downstream MCP tool to its capability, operation, target, and argument limit.
4. `actionlock_preview` derives a versioned action hash from the complete evidence receipt, server, tool, executable policy, and canonical argument hash.
5. A human may issue one short-lived approval for that exact action hash.
6. `actionlock_execute` consumes the approval atomically before forwarding the call to the configured MCP server.
7. The decision and execution outcome are appended to a locked hash chain with an HMAC-protected head checkpoint.

The model cannot declare its own capability class, invent evidence, substitute the evidence/server/tool/policy/arguments after approval, or replay an approval after restart.

## Security properties

- Technocore message URLs are data and are never followed automatically.
- GET-shaped Technocore write URLs embedded in content are always blocked.
- Shell, wallet, and social actions derived from remote content remain blocked even when an approval token is supplied.
- Every downstream call derived from remote content requires an exact approval.
- Capability, operation, target, command, and environment inheritance come only from trusted local config.
- Approval replay protection uses atomic exclusive file creation and survives process restarts.
- Audit appenders use an inter-process lock and refuse to extend an invalid chain.
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

Console users can scan the newest 25, 50, 100, or 200 retained room messages, enable a 30- or 60-second refresh, search and filter the current window, inspect pasted untrusted text, evaluate one or every capability, and download the resulting decision report as JSON. These actions remain local inspection operations; they do not post to Technocore or execute a downstream tool.

The console distinguishes an empty retained window from a temporary Technocore outage. It shows the scan time and current result count, but it is not a historical archive.

## Run the enforced MCP gateway

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

## Vercel profile

The hosted application is stateless by design:

- no database or scheduled polling;
- no wallet, Technocore signing key, root secret, or gateway config;
- room scans run only on request;
- scan responses are bounded to the newest 200 retained messages and cached at the edge for 30 seconds;
- Technocore exposes forward polling through `since`, but no backwards pagination, so the console never claims to retrieve history outside that retained window.

Create it as a separate Vercel project. Do not attach another project's environment variables, domains, or deployment settings.

## Verification

```bash
npm run check
npm run check:mcp
npm run build
```

Tests cover canonical Technocore signatures, big-integer evidence, signed receipt tampering and expiry, exact evidence/server/tool/policy/argument approval binding, bounded HTTP bodies, persistent replay protection, audit quotas, concurrent audit appends, blocked sensitive capabilities, and end-to-end gateway execution.

Protocol verification includes fixed RFC 8032-backed vectors from [`techbone/technocore-conformance`](https://github.com/techbone/technocore-conformance), rather than relying only on values generated by ActionLock itself.

See [SECURITY.md](./SECURITY.md), [docs/architecture.md](./docs/architecture.md), and [docs/landscape.md](./docs/landscape.md).

For a complete agent setup, MCP client example, approval sequence, and bypass warning, see [docs/integration.md](./docs/integration.md) or the hosted [`/guide`](https://technocore-actionlock.vercel.app/guide) page.

Coding agents should read [AGENTS.md](./AGENTS.md). Runtime agents and crawlers can use the hosted [`/llms.txt`](https://technocore-actionlock.vercel.app/llms.txt) overview.

## Limits

ActionLock protects only tools routed through its gateway. An agent with a separate unrestricted shell, wallet, social, or downstream MCP connection can bypass it; remove those bypass paths from the agent's capability set.

The local HMAC checkpoint detects edits to the current audit head. It cannot detect coordinated rollback of both the audit log and checkpoint unless the head hash is copied to an external append-only system.

## Sources

- [Technocore Chat repository](https://github.com/flop-labs/technocore-chat)
- [Technocore security policy](https://github.com/flop-labs/technocore-chat/blob/main/SECURITY.md)
- [MCP specification](https://modelcontextprotocol.io/specification/)

## License

MIT
