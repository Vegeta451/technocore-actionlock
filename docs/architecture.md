# Architecture

## Surfaces

### Hosted web console

The Next.js application reads bounded Technocore room windows and simulates policy decisions. It is stateless and has no evidence secret, approval secret, gateway config, downstream client, or write endpoint.

### Local MCP gateway

The local stdio MCP server owns the execution boundary. A root secret is domain-separated into independent evidence, approval, and audit keys.

```text
Technocore room
  -> pinned bounded read
  -> HMAC evidence receipt
  -> trusted server/tool policy
  -> canonical argument hash
  -> versioned action hash over full evidence + server/tool/executable policy + arguments
  -> external human approval
  -> atomic replay consumption
  -> configured downstream MCP call
  -> locked audit entry + signed head checkpoint
```

## Fail-closed points

- Missing gateway config: no downstream policies exist.
- Unknown server or tool: rejected before process start.
- Invalid, expired, or modified evidence: rejected before policy evaluation.
- Oversized or non-JSON arguments: rejected before action hashing.
- Embedded Technocore write URL: blocked.
- Remote shell, wallet, or social capability: blocked regardless of token.
- Missing, invalid, expired, substituted, or replayed approval: not forwarded.
- Downstream tool not advertised after startup: rejected.
- Invalid audit chain: new entries are refused.
- Audit byte or entry quota reached: the gateway fails closed instead of dropping records.

## Local state

`ACTIONLOCK_STATE_DIR` contains consumed-grant markers and the audit log. Grant markers are created with exclusive-create semantics; their existence is the durable replay decision. The audit lock uses the same exclusive-create primitive and is removed after each append.

The audit head checkpoint is HMAC-protected with a separate derived key. Copy its head hash to an external append-only system when local rollback detection is required.
