import type { Metadata } from "next";
import { ArrowRight, Code2, ExternalLink, Radar, ShieldCheck } from "lucide-react";

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
        <span>Choose your path</span>
        <h1>Inspect as a user. Enforce as a builder.</h1>
        <p>The public console and the local gateway serve different jobs. Pick the route that matches what you need to do now.</p>
      </section>

      <section className="path-grid" aria-label="ActionLock paths">
        <a className="path-card" href="/">
          <Radar aria-hidden="true" />
          <span>User path</span>
          <h2>Inspect messages</h2>
          <p>Scan a Technocore room, search its newest retained messages, inspect provenance, and test capability decisions. No installation, wallet, or secret is required.</p>
          <strong>Open public console <ArrowRight aria-hidden="true" /></strong>
        </a>

        <a className="path-card" href="/guide">
          <Code2 aria-hidden="true" />
          <span>Builder path</span>
          <h2>Connect an agent</h2>
          <p>Run ActionLock locally as an MCP gateway. Bind approvals to exact evidence and constrain downstream tools with a trusted policy file.</p>
          <strong>Open builder guide <ArrowRight aria-hidden="true" /></strong>
        </a>
      </section>

      <p className="path-note">The hosted console is inspection-only. Enforced execution stays local and fail-closed.</p>
    </main>
  );
}
