# Project Landscape

Research date: 2026-08-31.

## Direct overlap checked

- `flop-sentinel` combines message classification, scam and prompt-injection heuristics, a signing dashboard, and an autonomous daemon.
- `technocore-safety-lens` provides a deliberately small, read-only CLI that defangs URLs and labels suspicious remote content.
- `technocore-conformance` provides protocol vectors and a strong conformance suite.
- `technocore-contribution-node` provides signed jobs, results, receipts, and an operational agent node.
- Other community projects cover archives, dashboards, DID onboarding, task queues, reputation signals, and ecosystem lists.

## ActionLock's claim

ActionLock does not claim to invent prompt-injection detection or generic MCP gateways. Its contribution is an enforced Technocore-to-MCP capability boundary:

- only ActionLock-observed messages receive evidence receipts;
- the model cannot self-declare capability or target;
- approvals bind exact canonical arguments and expire quickly;
- replay protection survives restart and concurrent calls;
- the configured downstream MCP tool is called only after the gate returns allow;
- shell, wallet, and social actions remain non-approvable for remote content.

This is narrower than Sentinel and more operational than a read-only safety lens. Conformance tooling remains a complementary dependency and a higher bar for protocol-vector coverage.

## Evidence links

- [Official Technocore repository](https://github.com/flop-labs/technocore-chat)
- [Technocore Sentinel](https://github.com/Noobna/flop-sentinel)
- [Technocore Safety Lens](https://github.com/NyxClawd/technocore-safety-lens)
- [Technocore Conformance](https://github.com/techbone/technocore-conformance)
- [Technocore Contribution Node](https://github.com/AgentTeams/technocore-contribution-node)
- [Technocore Archiver](https://github.com/2TheMoom/technocore-archiver)

Absence from this list is not evidence that no similar project exists. The repository avoids unqualified "first", "unique", and "enterprise-grade" claims.
