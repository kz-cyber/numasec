/**
 * Deterministic next-action suggestions for findings.
 *
 * Maps vulnerability types (inferred from CWE or title) to concrete
 * next steps the agent should take. These are NOT stored in DB —
 * computed on read for freshness and zero-migration overhead.
 */

interface ActionSet {
  keywords: string[]
  cwePrefix?: string[]
  actions: string[]
}

const ACTION_MAP: ActionSet[] = [
  {
    keywords: ["sql injection", "sqli", "sql error"],
    cwePrefix: ["CWE-89"],
    actions: [
      "Use sqlmap via shell for deep exploitation: sqlmap -u '<URL>' --batch --dump",
      "Test related endpoints with similar parameter patterns",
      "Extract credentials — chain with auth_test for privilege escalation",
      "Enumerate database tables and check for PII / secrets",
    ],
  },
  {
    keywords: ["xss", "cross-site scripting", "script injection"],
    cwePrefix: ["CWE-79"],
    actions: [
      "Test for stored XSS — submit payload, check if it persists across sessions",
      "Attempt cookie theft: document.cookie exfiltration via XSS",
      "Check if CSP headers block script execution",
      "Chain with CSRF for authenticated action forgery",
    ],
  },
  {
    keywords: ["jwt", "json web token", "token", "weak secret"],
    cwePrefix: ["CWE-347", "CWE-345"],
    actions: [
      "Forge admin token with cracked/weak secret",
      "Test protected endpoints with forged token — prove privilege escalation",
      "Check for algorithm confusion (RS256 → HS256)",
      "Test token expiration enforcement",
    ],
  },
  {
    keywords: ["idor", "insecure direct object", "authorization bypass", "access control"],
    cwePrefix: ["CWE-639", "CWE-284"],
    actions: [
      "Enumerate sequential IDs to measure data exposure scope",
      "Test with different auth levels (admin vs user vs anonymous)",
      "Quantify impact: how many records are accessible?",
      "Chain with credential findings for authenticated IDOR",
    ],
  },
  {
    keywords: ["ssrf", "server-side request forgery"],
    cwePrefix: ["CWE-918"],
    actions: [
      "Probe internal services: 127.0.0.1, 169.254.169.254 (cloud metadata)",
      "Attempt cloud credential extraction via metadata endpoint",
      "Scan internal network ports through SSRF",
      "Chain with discovered internal services for deeper compromise",
    ],
  },
  {
    keywords: ["file upload", "upload bypass", "unrestricted upload"],
    cwePrefix: ["CWE-434"],
    actions: [
      "Upload a web shell and verify execution",
      "Test path traversal in upload filename",
      "Chain with directory listing to locate uploaded files",
      "Verify file type validation bypass with polyglot files",
    ],
  },
  {
    keywords: ["command injection", "os command", "cmdi", "rce", "remote code"],
    cwePrefix: ["CWE-78", "CWE-77"],
    actions: [
      "Establish reverse shell for persistent access proof",
      "Read sensitive files: /etc/passwd, environment variables",
      "Enumerate internal network from compromised host",
      "Demonstrate data exfiltration capability",
    ],
  },
  {
    keywords: ["csrf", "cross-site request forgery"],
    cwePrefix: ["CWE-352"],
    actions: [
      "Craft PoC HTML that triggers state-changing action",
      "Test against authenticated endpoints (password change, email change)",
      "Chain with XSS for same-origin CSRF bypass",
    ],
  },
  {
    keywords: ["cors", "cross-origin"],
    cwePrefix: ["CWE-942"],
    actions: [
      "Test if credentials are included in cross-origin responses",
      "Craft PoC JavaScript that exfiltrates data cross-origin",
      "Check if wildcard origin reflects arbitrary domains",
    ],
  },
  {
    keywords: ["ssti", "template injection", "server-side template"],
    cwePrefix: ["CWE-1336"],
    actions: [
      "Identify template engine (Jinja2, Twig, Freemarker, etc.)",
      "Escalate from SSTI to RCE with engine-specific payload",
      "Read server-side files through template engine",
    ],
  },
  {
    keywords: ["nosql", "mongodb", "operator injection"],
    cwePrefix: ["CWE-943"],
    actions: [
      "Attempt authentication bypass with $ne / $gt operators",
      "Extract data using $regex-based blind enumeration",
      "Test $where clause for JavaScript injection",
    ],
  },
  {
    keywords: ["graphql", "introspection"],
    cwePrefix: ["CWE-200"],
    actions: [
      "Use introspection schema to discover hidden queries/mutations",
      "Test mutations for authorization bypass",
      "Attempt batch queries for rate limit bypass / DoS",
    ],
  },
  {
    keywords: ["race condition", "toctou", "concurrent"],
    cwePrefix: ["CWE-362"],
    actions: [
      "Test financial operations: double-spend, duplicate coupons",
      "Test privilege escalation via concurrent role changes",
      "Quantify business impact of race window",
    ],
  },
  {
    keywords: ["path traversal", "lfi", "local file inclusion", "directory traversal"],
    cwePrefix: ["CWE-22"],
    actions: [
      "Read /etc/passwd, /etc/shadow, application config files",
      "Attempt log poisoning → LFI to RCE chain",
      "Test for remote file inclusion (RFI)",
    ],
  },
  {
    keywords: ["open redirect"],
    cwePrefix: ["CWE-601"],
    actions: [
      "Chain with OAuth flows for token theft",
      "Use in phishing campaigns targeting the domain's trust",
      "Test for SSRF via redirect chains",
    ],
  },
  {
    keywords: ["information disclosure", "exposed", "sensitive data", "data leak", "verbose error"],
    cwePrefix: ["CWE-200", "CWE-209"],
    actions: [
      "Enumerate all exposed endpoints for sensitive data",
      "Check if disclosed information aids other attacks (credentials, internal IPs)",
      "Verify whether error messages reveal technology stack details",
    ],
  },
  {
    keywords: ["missing header", "security header", "hsts", "csp", "x-frame"],
    cwePrefix: ["CWE-693", "CWE-1021"],
    actions: [
      "Verify if missing headers enable clickjacking or XSS",
      "Test Content-Security-Policy bypass if present but weak",
      "Check all endpoints for header consistency",
    ],
  },
]

/** Get deterministic next-action suggestions for a finding. */
export function getNextActions(cweId: string, title: string): string[] {
  const titleLower = title.toLowerCase()

  // First pass: match by CWE prefix
  if (cweId) {
    for (const set of ACTION_MAP) {
      if (set.cwePrefix?.some((p) => cweId.startsWith(p))) {
        return set.actions
      }
    }
  }

  // Second pass: match by title keywords
  for (const set of ACTION_MAP) {
    if (set.keywords.some((k) => titleLower.includes(k))) {
      return set.actions
    }
  }

  // Generic fallback
  return [
    "Verify the finding is exploitable — not just detected",
    "Check related endpoints for the same vulnerability pattern",
    "Assess business impact and document evidence",
  ]
}
