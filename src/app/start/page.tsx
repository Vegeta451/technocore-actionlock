import type { Metadata } from "next";
import { ArrowRight, Code2, ExternalLink, Fingerprint, LockKeyhole, Radar, ShieldCheck } from "lucide-react";

export const metadata: Metadata = {
  title: "Choose a path | ActionLock",
  description: "Choose the public inspection console or the local agent integration path.",
};

export default function StartPage(): React.ReactElement {
  return (
    <main className="path-shell">
      <header className="path-header">
        <a className="brand" href="/">
          <div className="brand-mark" aria-hidden="true"><ShieldCheck /></div>
          <div><strong>ActionLock</strong><span>Capability firewall for Technocore</span></div>
        </a>
        <a href="https://github.com/Vegeta451/technocore-actionlock" target="_blank" rel="noreferrer">
          GitHub <ExternalLink aria-hidden="true" />
        </a>
      </header>

      <section className="path-intro">
        <span>Evidence before execution</span>
        <h1>Remote messages are data, not permission.</h1>
        <p>ActionLock separates who signed a Technocore message, what the text contains, and whether an agent may act on it. Inspect publicly or place the local gateway in front of an agent.</p>
      </section>

      <section className="path-purpose" aria-label="Why ActionLock exists">
        <div className="path-purpose-title"><LockKeyhole aria-hidden="true" /><div><span>Why it exists</span><h2>A signature proves authorship. It does not grant authority.</h2></div></div>
        <p>Technocore rooms can contain validly signed instructions from remote participants. ActionLock preserves that provenance while preventing message content from choosing its own tools, policy, target, or approval. The hosted console explains the decision; the local MCP gateway enforces it.</p>
      </section>

      <section className="path-controls" aria-label="ActionLock security model">
        <div><Fingerprint aria-hidden="true" /><strong>Evidence</strong><span>Bind room, sender, sequence, text, and verification state.</span></div>
        <div><ShieldCheck aria-hidden="true" /><strong>Policy</strong><span>Map exact downstream tools from trusted local configuration.</span></div>
        <div><LockKeyhole aria-hidden="true" /><strong>Approval</strong><span>Allow one exact action without creating reusable authority.</span></div>
      </section>

      <section className="path-grid" aria-label="ActionLock paths">
        <a className="path-card" href="/">
          <Radar aria-hidden="true" />
          <span>User path</span>
          <h2>Inspect messages</h2>
          <p>Scan a Technocore room, look up an exact retained sequence, pin evidence in this browser, inspect provenance, and test capability decisions. No installation, wallet, or secret is required.</p>
          <strong>Open public console <ArrowRight aria-hidden="true" /></strong>
        </a>

        <a className="path-card" href="/docs">
          <Code2 aria-hidden="true" />
          <span>Builder path</span>
          <h2>Connect an agent</h2>
          <p>Run ActionLock locally as an MCP gateway. Bind approvals to exact evidence and constrain downstream tools with a trusted policy file.</p>
          <strong>Open documentation <ArrowRight aria-hidden="true" /></strong>
        </a>
      </section>

      <div className="path-note"><strong>Boundary</strong><span>The hosted console is inspection-only. Enforced execution stays local, keeps secrets off Vercel, and fails closed when config or approval is missing.</span></div>
    </main>
  );
}
