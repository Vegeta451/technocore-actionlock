# Security Policy

## Protected properties

1. Remote Technocore content never grants a capability by itself.
2. Sender authenticity never implies content trust or authorization.
3. Message URLs are data and are not followed automatically.
4. Embedded Technocore GET-write routes are blocked.
5. Evidence receipts bind the room, sequence, sender, text, verification state, and content hash.
6. Versioned action hashes bind the complete evidence receipt, downstream server, tool name, executable policy, target, execution boundary, and canonical arguments.
7. Remote shell, wallet, and social actions cannot be approved.
8. Approval grants are short-lived, domain-separated, exact-action tokens consumed atomically before execution.
9. The hosted application contains no root secret, private key, downstream config, approval issuer, or write endpoint.
10. A public Ed25519 approval receipt is created only after a valid grant is atomically consumed and before the downstream call begins.
11. Execution results are separately signed and linked to the approval receipt hash; they cannot redefine the approved action.

## Trust boundaries

- **Technocore origin:** remote and untrusted. HTTPS authenticates the connection, not message intent.
- **Public web console:** untrusted simulation surface. It cannot issue gateway evidence or approvals.
- **Local ActionLock MCP process:** trusted policy and execution boundary. It owns the root secret and state directory.
- **Gateway config:** trusted executable policy. It defines which process may start, which tools may be called, and which environment variables may be inherited.
- **Downstream MCP server:** trusted for the capability explicitly assigned in config, not for broader local access.
- **Agent/model:** untrusted caller. It may choose only among configured server/tool identifiers and submit arguments for exact review.

## Deployment requirements

- Generate `ACTIONLOCK_ROOT_SECRET` from at least 32 random bytes and keep it out of shell history, logs, repositories, browser code, and Vercel.
- Protect `actionlock.config.json` and the state directory with local OS permissions.
- Protect and back up `receipt-signing-key.json`. Publish its key ID through an independently trusted channel before relying on third-party attribution.
- Use absolute downstream script paths where possible.
- Keep `inheritEnv` empty unless a downstream server requires a named variable.
- Remove direct downstream MCP, shell, wallet, and social tools from the agent configuration. ActionLock must be the only route to protected tools.
- Never configure wallet or social tools for remote-derived execution; policy blocks them, and omitting them reduces attack surface further.

## Known limits

- The live Technocore read API may expose a DID and nonce without the original signature. Such records are labelled `server_signed_lane`, not independently verified.
- Pattern findings are triage evidence, not proof that text is malicious or safe.
- Approval is consumed before forwarding. A timeout or tool error may follow an actual side effect. Reconcile downstream records before considering a new approval; a fresh grant can repeat the action. Replay protection is per grant, not exactly-once execution.
- Audit storage has hard byte and entry quotas. Intent must be recorded before dispatch, so an unavailable or full audit stops new calls. Recording failures after dispatch are reported separately and cannot undo the effect. An append may precede a failed checkpoint, so `audit_write_failed` does not prove the record is absent.
- A successful executor response is a gateway observation, not proof of the real-world effect. Unknown outcomes are not signed as failures. Process termination or response loss may still leave only an intent and a consumed grant; automatic retry is unsafe.
- The HMAC checkpoint does not prevent coordinated rollback of both local audit files. Export the head hash to an external append-only log when rollback detection matters.
- Root-secret compromise allows forged local evidence, approvals, and checkpoints. Rotate it and discard untrusted local state after compromise.
- Receipt-key compromise allows forged public receipts for that key ID. Rotate to a new key file, publish the new key ID, and mark the old key's compromise time externally.
- A self-contained receipt proves key control, not key ownership. Verification without an independently pinned expected key ID is cryptographic integrity only.
- `actionlock-cjson-v1` is ActionLock's strict sorted-key JSON profile, not a claim of general RFC 8785 interoperability.
- Public receipts are returned to the caller but are not externally anchored. Loss, selective withholding, and rollback remain possible until a receipt hash is published to an append-only system.
- Trusted config compromise can replace a downstream command or misclassify its capability. Treat config changes as code changes and review them.
- Downstream output is returned to the caller. A configured server must not return credentials or unrelated sensitive data.

## Reporting

Do not include secrets, private keys, approval tokens, gateway config containing private paths, or exploit payloads in a public issue. Use a private GitHub security advisory when available.
