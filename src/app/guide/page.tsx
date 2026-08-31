import { ArrowLeft, CheckCircle2, ExternalLink, LockKeyhole, ShieldCheck, TerminalSquare } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Integration Guide | ActionLock",
  description: "Connect an agent to the local ActionLock MCP enforcement boundary.",
};

const clientConfig = `{
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
}`;

const policyConfig = `{
  "version": 1,
  "servers": [{
    "id": "reports",
    "command": "node",
    "args": ["/absolute/path/to/trusted-mcp-server.js"],
    "inheritEnv": [],
    "tools": {
      "write_report": {
        "capability": "file_write",
        "operation": "write reviewed report",
        "target": "local report workspace",
        "maxArgumentBytes": 16000
      }
    }
  }]
}`;

export default function GuidePage(): React.ReactElement {
  return (
    <main className="guide-shell">
      <header className="guide-topbar">
        <a href="/" aria-label="Back to ActionLock console"><ArrowLeft aria-hidden="true" />Console</a>
        <div><ShieldCheck aria-hidden="true" /><strong>ActionLock integration guide</strong></div>
        <a href="https://github.com/Vegeta451/technocore-actionlock" target="_blank" rel="noreferrer">GitHub <ExternalLink aria-hidden="true" /></a>
      </header>

      <section className="guide-intro">
        <span>Console and agent setup</span>
        <h1>Inspect first. Connect an agent when you need enforcement.</h1>
        <p>Use the hosted console to inspect Technocore or pasted messages without credentials. Run the local MCP boundary only when an agent must control approved downstream tools.</p>
      </section>

      <section className="console-guide" aria-label="Using the hosted console">
        <div className="guide-section-title"><CheckCircle2 aria-hidden="true" /><div><span>Hosted console</span><h2>Inspect without installing anything</h2></div></div>
        <ol className="verification-list">
          <li><strong>Choose a room</strong><span>Enter a Technocore room, select a 25–200 message depth, then press <b>Scan</b>. Optional refresh runs every 30 or 60 seconds.</span></li>
          <li><strong>Find evidence</strong><span>Search by sender, sequence, or text. Filter the current window by allowed, held, or blocked risk state.</span></li>
          <li><strong>Select or paste</strong><span>Choose a room message, or open <b>Inspect pasted message</b> to review text from another source.</span></li>
          <li><strong>Evaluate permissions</strong><span>Test one capability or all eight. ActionLock separates textual risk from permission to act.</span></li>
          <li><strong>Keep a receipt</strong><span>After evaluation, download the JSON report containing evidence, decisions, rules, and binding hashes.</span></li>
        </ol>
      </section>

      <section className="boundary-diagram" aria-label="ActionLock connection boundary">
        <div><span>1</span><strong>Agent</strong><small>Sees ActionLock tools only</small></div>
        <b>→</b>
        <div><span>2</span><strong>ActionLock MCP</strong><small>Evidence, policy, approval, audit</small></div>
        <b>→</b>
        <div><span>3</span><strong>Trusted MCP server</strong><small>Exact allow-listed tools only</small></div>
      </section>

      <section className="guide-section">
        <div className="guide-section-title"><TerminalSquare aria-hidden="true" /><div><span>Step 1</span><h2>Install and verify</h2></div></div>
        <div className="command-list"><code>git clone https://github.com/Vegeta451/technocore-actionlock.git</code><code>cd technocore-actionlock</code><code>npm install</code><code>npm run check</code></div>
        <p>Use Node.js 20 or newer. Do not continue if the test suite fails.</p>
      </section>

      <section className="guide-section">
        <div className="guide-section-title"><LockKeyhole aria-hidden="true" /><div><span>Step 2</span><h2>Define the downstream boundary</h2></div></div>
        <p>Copy <code>actionlock.config.example.json</code> to the ignored local file <code>actionlock.config.json</code>. Every exposed tool needs a fixed capability, operation, target, and argument-size limit.</p>
        <pre><code>{policyConfig}</code></pre>
        <div className="guide-warning"><strong>Keep the boundary narrow.</strong><span>Use absolute executable paths. Leave <code>inheritEnv</code> empty unless the downstream server needs a named variable. Never store secrets in this JSON file.</span></div>
      </section>

      <section className="guide-section">
        <div className="guide-section-title"><ShieldCheck aria-hidden="true" /><div><span>Step 3</span><h2>Connect the agent MCP client</h2></div></div>
        <p>Add one local stdio server to the agent’s MCP configuration. Replace the paths and secret locally. The exact settings screen differs by client; the transport and command remain the same.</p>
        <pre><code>{clientConfig}</code></pre>
        <p>Restart the MCP client. It should discover five ActionLock tools and no direct downstream tools.</p>
      </section>

      <section className="guide-section">
        <div className="guide-section-title"><CheckCircle2 aria-hidden="true" /><div><span>Step 4</span><h2>Verify before execution</h2></div></div>
        <ol className="verification-list">
          <li><strong>Read evidence</strong><span>Call <code>actionlock_read_room</code>. Keep the returned short-lived evidence token.</span></li>
          <li><strong>Inspect policy</strong><span>Call <code>actionlock_list_policies</code>. An empty list means execution is disabled.</span></li>
          <li><strong>Preview exact arguments</strong><span>Call <code>actionlock_preview</code>. Review its action hash without running the downstream tool.</span></li>
          <li><strong>Approve outside the agent</strong><span>Run <code>npm run approve -- &lt;action-hash&gt;</code>. The one-time token expires after 120 seconds.</span></li>
          <li><strong>Execute once</strong><span>Call <code>actionlock_execute</code> with unchanged evidence, server, tool, arguments, and approval token.</span></li>
          <li><strong>Check the audit chain</strong><span>Call <code>actionlock_verify_audit</code> after the run.</span></li>
        </ol>
      </section>

      <section className="guide-limits">
        <h2>Security limits</h2>
        <p>ActionLock protects only calls routed through it. Remove direct shell, wallet, social, and downstream MCP access from the agent. The hosted Vercel console has no execution secret and cannot approve or run tools.</p>
        <a href="https://github.com/Vegeta451/technocore-actionlock/blob/main/SECURITY.md" target="_blank" rel="noreferrer">Read SECURITY.md <ExternalLink aria-hidden="true" /></a>
      </section>
    </main>
  );
}
