import { ArrowLeft, CheckCircle2, ExternalLink, Fingerprint, LockKeyhole, ShieldCheck, TerminalSquare } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Documentation | ActionLock",
  description: "Understand ActionLock, inspect remote evidence, and connect an agent to the local MCP enforcement boundary.",
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

const policyRules = [
  ["ACTIONLOCK-001", "Message embeds a Technocore GET-write URL", "Blocked"],
  ["ACTIONLOCK-010", "Bounded built-in inspection", "Allowed with provenance"],
  ["ACTIONLOCK-020", "Remote shell, wallet, or social capability", "Blocked"],
  ["ACTIONLOCK-030", "Remote content reaches a configured downstream tool", "Exact approval required"],
  ["ACTIONLOCK-031", "Approval matches evidence, policy, tool, target, and arguments", "Allowed once"],
  ["ACTIONLOCK-040", "Sensitive local action has no approval", "Approval required"],
  ["ACTIONLOCK-050", "Local action is inside trusted policy", "Allowed"],
] as const;

export default function DocsPage(): React.ReactElement {
  return (
    <main className="guide-shell">
      <header className="guide-topbar">
        <a href="/" aria-label="Back to ActionLock console"><ArrowLeft aria-hidden="true" />Console</a>
        <div><ShieldCheck aria-hidden="true" /><strong>ActionLock documentation</strong></div>
        <a href="https://github.com/Vegeta451/technocore-actionlock" target="_blank" rel="noreferrer">GitHub <ExternalLink aria-hidden="true" /></a>
      </header>

      <section className="guide-intro" id="overview">
        <span>Documentation</span>
        <h1>Evidence before authority.</h1>
        <p>ActionLock is a local-first MCP capability gateway for agents that consume untrusted Technocore messages. It keeps authorship, content risk, approval, and permission to act as separate decisions.</p>
      </section>

      <nav className="docs-nav" aria-label="Documentation sections">
        <a href="#overview">Overview</a><a href="#how-it-works">How it works</a><a href="#console">Public console</a><a href="#setup">Agent setup</a><a href="#rules">Policy rules</a><a href="#operations">Operations</a><a href="#limits">Limits</a>
      </nav>

      <section className="guide-section" id="how-it-works">
        <div className="guide-section-title"><Fingerprint aria-hidden="true" /><div><span>Overview</span><h2>What ActionLock changes</h2></div></div>
        <p>A valid signature proves that a key signed a message. It does not make the text safe or authorize an agent tool. ActionLock binds the message to evidence, derives capabilities only from trusted local policy, and requires a one-time approval for eligible downstream effects.</p>
      </section>

      <section className="boundary-diagram" aria-label="ActionLock connection boundary">
        <div><span>1</span><strong>Agent</strong><small>Sees ActionLock tools only</small></div><b>→</b>
        <div><span>2</span><strong>ActionLock MCP</strong><small>Evidence, policy, approval, audit</small></div><b>→</b>
        <div><span>3</span><strong>Trusted MCP server</strong><small>Exact allow-listed tools only</small></div>
      </section>

      <section className="console-guide" id="console" aria-label="Using the hosted console">
        <div className="guide-section-title"><CheckCircle2 aria-hidden="true" /><div><span>Public console</span><h2>Inspect without installing anything</h2></div></div>
        <ol className="verification-list">
          <li><strong>Choose a room</strong><span>Enter a Technocore room, choose a 25–200 message depth, then press <b>Scan</b>. Optional refresh runs every 30 or 60 seconds.</span></li>
          <li><strong>Find evidence</strong><span>Search the live window, or enter an exact sequence. Current-window matches resolve immediately; older records stream from the room export while retained. Export lookup is manual, uncached, and bounded to 12 MiB.</span></li>
          <li><strong>Select or paste</strong><span>Choose a room message, or open <b>Inspect pasted message</b> to review text from another source.</span></li>
          <li><strong>Test a boundary</strong><span>Select one capability or test all eight. The complete map shows hypothetical permission checks, not actions detected in the text.</span></li>
          <li><strong>Keep a receipt</strong><span>Pin evidence in this browser or download its JSON report. Browser pins never become a server-side ActionLock archive.</span></li>
        </ol>
      </section>

      <section className="guide-section" id="setup">
        <div className="guide-section-title"><TerminalSquare aria-hidden="true" /><div><span>Agent setup · 1</span><h2>Install and verify</h2></div></div>
        <div className="command-list"><code>git clone https://github.com/Vegeta451/technocore-actionlock.git</code><code>cd technocore-actionlock</code><code>npm install</code><code>npm run check</code><code>npm run check:mcp</code></div>
        <p>Use Node.js 20 or newer. The MCP check starts an isolated local server, connects with a real client, verifies all five tools, and confirms fail-closed startup.</p>
      </section>

      <section className="guide-section">
        <div className="guide-section-title"><LockKeyhole aria-hidden="true" /><div><span>Agent setup · 2</span><h2>Define the downstream boundary</h2></div></div>
        <p>Copy <code>actionlock.config.example.json</code> to the ignored local file <code>actionlock.config.json</code>. Every exposed tool needs a fixed capability, operation, target, and argument-size limit.</p>
        <pre><code>{policyConfig}</code></pre>
        <div className="guide-warning"><strong>Keep the boundary narrow.</strong><span>Use absolute executable paths. Leave <code>inheritEnv</code> empty unless the downstream server needs a named variable. Never store secrets in this file.</span></div>
      </section>

      <section className="guide-section">
        <div className="guide-section-title"><ShieldCheck aria-hidden="true" /><div><span>Agent setup · 3</span><h2>Create the local secret</h2></div></div>
        <p>Generate the secret on the builder’s machine. Keep it out of Git, screenshots, chat, and the hosted console.</p>
        <div className="command-list"><code>node -e &quot;console.log(require('node:crypto').randomBytes(48).toString('base64url'))&quot;</code></div>
        <div className="guide-warning"><strong>This secret controls local approvals.</strong><span>Use a different value for every installation. Exposing it weakens the local evidence, approval, and audit boundary.</span></div>
      </section>

      <section className="guide-section">
        <div className="guide-section-title"><ShieldCheck aria-hidden="true" /><div><span>Agent setup · 4</span><h2>Connect the MCP client</h2></div></div>
        <p>Add one local stdio server to the agent’s MCP configuration. Replace paths and the secret locally. Do not expose the same downstream server directly to the agent.</p>
        <pre><code>{clientConfig}</code></pre>
        <p>Restart the client. It should discover five ActionLock tools and no direct downstream tools. If it cannot find <code>npm</code>, use the absolute executable path.</p>
      </section>

      <section className="guide-section" id="rules">
        <div className="guide-section-title"><LockKeyhole aria-hidden="true" /><div><span>Policy</span><h2>Decision rules</h2></div></div>
        <div className="policy-table" role="table" aria-label="ActionLock policy rules">
          <div role="row" className="policy-head"><span role="columnheader">Rule</span><span role="columnheader">Condition</span><span role="columnheader">Result</span></div>
          {policyRules.map(([rule, condition, result]) => <div role="row" key={rule}><code role="cell">{rule}</code><span role="cell">{condition}</span><strong role="cell">{result}</strong></div>)}
        </div>
      </section>

      <section className="guide-section" id="operations">
        <div className="guide-section-title"><CheckCircle2 aria-hidden="true" /><div><span>Operations</span><h2>Review and execute once</h2></div></div>
        <ol className="verification-list">
          <li><strong>Read evidence</strong><span>Call <code>actionlock_read_room</code> and retain the short-lived evidence token.</span></li>
          <li><strong>Inspect policy</strong><span>Call <code>actionlock_list_policies</code>. An empty list means downstream execution is disabled.</span></li>
          <li><strong>Preview exact arguments</strong><span>Call <code>actionlock_preview</code>. Review the evidence, tool, target, arguments, and action hash without executing.</span></li>
          <li><strong>Approve outside the agent</strong><span>Run <code>npm run approve -- &lt;action-hash&gt;</code>. The one-time token expires after 120 seconds.</span></li>
          <li><strong>Execute once</strong><span>Call <code>actionlock_execute</code> without changing evidence, server, tool, arguments, or approval token.</span></li>
          <li><strong>Verify the audit</strong><span>Call <code>actionlock_verify_audit</code>. Replayed or modified approvals are rejected.</span></li>
        </ol>
      </section>

      <section className="guide-section">
        <div className="guide-section-title"><TerminalSquare aria-hidden="true" /><div><span>Troubleshooting</span><h2>Fail-closed states are signals</h2></div></div>
        <ol className="verification-list">
          <li><strong>No policies listed</strong><span>The config is missing, unreadable, or intentionally empty. No downstream execution is available.</span></li>
          <li><strong>Approval required</strong><span>The action is eligible but no exact, valid one-time approval matches its current hash.</span></li>
          <li><strong>Blocked</strong><span>The requested boundary is prohibited. Remote shell, wallet, and social capabilities cannot be approved.</span></li>
          <li><strong>Technocore unavailable</strong><span>The hosted console remains online but cannot fetch the upstream retained window. Retry after the upstream service returns.</span></li>
          <li><strong>Not retained</strong><span>The requested sequence is older than the first record in the current export. ActionLock reports the boundary and does not fabricate missing evidence.</span></li>
        </ol>
      </section>

      <section className="guide-limits" id="limits">
        <h2>Security limits</h2>
        <p>ActionLock protects only calls routed through it. Remove direct shell, wallet, social, and downstream MCP access from the agent. The hosted Vercel console has no execution secret and cannot approve or run tools. Local audit checkpoints cannot detect coordinated rollback unless the head hash is exported to an external append-only system.</p>
        <a href="https://github.com/Vegeta451/technocore-actionlock/blob/main/SECURITY.md" target="_blank" rel="noreferrer">Read SECURITY.md <ExternalLink aria-hidden="true" /></a>
      </section>
    </main>
  );
}
