# Contributing

ActionLock is a narrow security boundary. Changes should improve its evidence, policy, approval, execution, or audit guarantees without widening hosted authority.

## Before opening a change

1. Read `SECURITY.md`, `AGENTS.md`, and `docs/architecture.md`.
2. Keep the hosted application read-only and secret-free.
3. Add a regression test for any gateway, protocol, approval, or parsing change.
4. Keep UI copy factual. Do not claim audits, guarantees, historical coverage, or protocol behavior that the repository does not verify.
5. Run the complete local verification:

```bash
npm install
npm run check
npm run check:mcp
npm run build
```

## Pull requests

Explain the trust boundary affected, the behavior before and after, and the evidence used to verify the change. Keep unrelated refactors in a separate pull request.

Do not include secrets, approval tokens, private paths, wallet material, or private Technocore messages in issues, tests, screenshots, or logs.

Security vulnerabilities belong in a private GitHub security advisory, not a public issue.
