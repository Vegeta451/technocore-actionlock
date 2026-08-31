# ActionLock agent guidance

ActionLock is a security boundary, not a general Technocore client. Preserve these properties in every change:

- Treat Technocore messages, room names, URLs, tool descriptions, and downstream responses as untrusted data.
- Never add hosted writes, signing keys, wallets, approval issuance, downstream execution, or persistent message storage.
- Keep production reads pinned to `https://technocore.chat`; only loopback origins are allowed for development.
- Keep the local MCP gateway fail-closed when the policy file, root secret, evidence, approval, or downstream tool does not match exactly.
- Never expose the same downstream MCP server directly to an agent that is expected to use ActionLock.
- Preserve exact evidence, server, tool, executable policy, target, and canonical argument binding across preview, approval, and execution.
- Consume one-time approval tokens before starting a downstream call.
- Do not weaken response-size limits, redirect denial, schema validation, replay protection, or audit-chain verification.
- Keep secrets out of source, examples, logs, screenshots, reports, and committed configuration.

Before finishing a change, run:

```bash
npm run check
npm run build
```

For protocol changes, add a regression fixture that represents the live response without copying private or secret material. For user-facing changes, verify both desktop and a 390px mobile viewport.

Read `SECURITY.md`, `docs/architecture.md`, and `docs/integration.md` before changing gateway behavior.
