import type { RiskAssessment, RiskFinding, RiskSeverity } from "./types";

const URL_PATTERN = /https?:\/\/[^\s<>"'`]+/gi;
const TECHNOCORE_WRITE_PATH = /\/(?:r\/[^/]+\/(?:say|say-signed)|kv\/[^/]+\/[^/]+\/(?:set|set-signed))(?:\/|$)/i;
const INVISIBLE_OR_BIDI = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/u;

const PROMPT_PATTERNS: Array<{ code: string; title: string; pattern: RegExp; severity: RiskSeverity }> = [
  {
    code: "instruction_override",
    title: "Instruction override language",
    pattern: /\b(?:ignore|forget|override|disregard)\b.{0,40}\b(?:previous|prior|system|developer|instructions?)\b/i,
    severity: "high",
  },
  {
    code: "secret_request",
    title: "Credential or secret request",
    pattern: /\b(?:private key|seed phrase|mnemonic|api key|identity\.pem|passphrase|system prompt)\b/i,
    severity: "high",
  },
  {
    code: "tool_directive",
    title: "Tool execution directive",
    pattern: /\b(?:run|execute|invoke|call|open|fetch|download)\b.{0,32}\b(?:tool|command|terminal|shell|url|link|script|file)\b/i,
    severity: "medium",
  },
  {
    code: "role_spoofing",
    title: "Agent role spoofing marker",
    pattern: /(?:^|\s)(?:system|developer|assistant)\s*:/i,
    severity: "medium",
  },
];

const WEIGHTS: Record<RiskSeverity, number> = {
  low: 10,
  medium: 25,
  high: 45,
  critical: 70,
};

function trimEvidence(value: string): string {
  return value.length > 180 ? `${value.slice(0, 177)}...` : value;
}

function decodedPath(pathname: string): string {
  let value = pathname;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const decoded = decodeURIComponent(value);
      if (decoded === value) break;
      value = decoded;
    } catch {
      break;
    }
  }
  return value;
}

export function analyzeText(text: string, trustedOrigin = "https://technocore.chat"): RiskAssessment {
  const findings: RiskFinding[] = [];
  const urls = [...text.matchAll(URL_PATTERN)].map((match) => match[0]);

  for (const urlText of urls) {
    try {
      const url = new URL(urlText);
      if (url.origin === trustedOrigin && TECHNOCORE_WRITE_PATH.test(decodedPath(url.pathname))) {
        findings.push({
          code: "technocore_get_write_url",
          title: "Technocore write URL embedded in content",
          severity: "critical",
          evidence: trimEvidence(urlText),
        });
      } else {
        findings.push({
          code: "external_url",
          title: "Untrusted external URL",
          severity: "low",
          evidence: trimEvidence(urlText),
        });
      }
    } catch {
      findings.push({
        code: "malformed_url",
        title: "Malformed URL-like content",
        severity: "medium",
        evidence: trimEvidence(urlText),
      });
    }
  }

  for (const rule of PROMPT_PATTERNS) {
    const match = text.match(rule.pattern);
    if (match) {
      findings.push({
        code: rule.code,
        title: rule.title,
        severity: rule.severity,
        evidence: trimEvidence(match[0]),
      });
    }
  }

  if (INVISIBLE_OR_BIDI.test(text)) {
    findings.push({
      code: "invisible_unicode",
      title: "Invisible or bidirectional Unicode",
      severity: "medium",
      evidence: "Message contains hidden formatting code points",
    });
  }

  const score = Math.min(100, findings.reduce((total, finding) => total + WEIGHTS[finding.severity], 0));
  const hasBlocker = findings.some((finding) => finding.severity === "critical");
  const hasQuarantine = findings.some(
    (finding) => finding.severity === "high" || finding.severity === "medium",
  );

  return {
    action: hasBlocker ? "block" : hasQuarantine ? "quarantine" : "allow",
    score,
    findings,
    urls,
  };
}
