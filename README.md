# numasec

AI-driven penetration testing, as a terminal and as an MCP server.

Runs structured assessments following the PTES 5-phase methodology — recon, crawling, injection, authentication, access control, through to a full report with CWE, CVSS, OWASP, and ATT&CK mappings. Use it as a standalone terminal (like Claude Code, but for pentesting) or wire it into any MCP-compatible AI assistant.

---

## Two ways to use it

### Terminal

An interactive pentesting session in your terminal. The AI follows PTES phases, keeps a live findings panel with OWASP coverage, and generates a report when done.

```bash
curl -fsSL https://raw.githubusercontent.com/anomalyco/numasec/main/install.sh | bash
numasec
```

Run `numasec` in any directory. The agent asks for a target, runs recon, then walks through exploitation phases. Everything is scoped — it won't test URLs outside the target you define.

### MCP server

21 security tools exposed to any MCP host. Your AI assistant can call `recon`, `injection_test`, `xss_test`, `auth_test`, etc. directly, with session state and report generation built in.

```bash
pip install "numasec[mcp]"
playwright install chromium
```

**VS Code / GitHub Copilot** — `.vscode/mcp.json`:

```json
{
  "servers": {
    "numasec": {
      "command": "numasec"
    }
  }
}
```

**Claude Desktop** — `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "numasec": {
      "command": "numasec"
    }
  }
}
```

**Cursor** — use HTTP transport:

```json
{
  "mcpServers": {
    "numasec": {
      "command": "numasec",
      "args": ["--mcp-http"]
    }
  }
}
```

---

## What it tests

| Category | Details |
|---|---|
| Injection | SQLi (blind, time-based, union, error-based), NoSQL, SSTI, command injection, XXE |
| Client-side | Reflected XSS, DOM XSS with canary injection, CSRF, open redirect |
| Authentication | JWT attacks, OAuth testing, credential spray, default credentials |
| Access control | IDOR, CORS misconfiguration, path traversal, LFI |
| Server-side | SSRF with cloud metadata detection, host header injection, XXE |
| Recon | Port scanning, tech fingerprinting, SSL/TLS analysis, CVE enrichment via NVD |
| Discovery | Directory and file enumeration, OpenAPI/Swagger import, JS source analysis |
| Manual | Raw HTTP requests, Playwright browser sessions, out-of-band callbacks |

## Tools (21)

| Tool | What it does |
|---|---|
| `recon` | Port scan, tech fingerprint, service probing, CVE enrichment |
| `crawl` | HTTP + SPA crawling, OpenAPI/Swagger import |
| `injection_test` | SQLi, NoSQL, SSTI, command injection, GraphQL injection |
| `xss_test` | Reflected + DOM XSS with canary injection |
| `auth_test` | JWT attacks, OAuth testing, credential spray |
| `access_control_test` | IDOR, CSRF, CORS misconfiguration |
| `ssrf_test` | SSRF with cloud metadata detection |
| `path_test` | LFI, XXE, open redirect, host header injection |
| `dir_fuzz` | Directory and file enumeration |
| `js_analyze` | Secrets in source, exposed endpoints, DOM sinks |
| `browser` | Playwright-based browser interaction |
| `http_request` | Raw HTTP requests |
| `oob` | Out-of-band detection (DNS/HTTP callbacks) |
| `run_scanner_batch` | Parallel multi-scanner execution |
| `kb_search` | Search 34 KB templates: techniques, CWEs, payloads |
| `plan` | Scan planning, OWASP coverage tracking, next-step suggestions |
| `create_session` | Start an assessment session |
| `save_finding` | Store a finding — auto-enriched with CWE, CVSS, OWASP, ATT&CK |
| `get_findings` | Retrieve and filter findings by severity |
| `generate_report` | Export as SARIF 2.1.0, Markdown, HTML, or JSON |
| `relay_credentials` | Pass discovered credentials into authenticated testing |

## Knowledge base

34 YAML templates indexed for BM25 search, covering:

- Detection patterns (SQLi, XSS, SSRF, auth, WAF bypass, API security, business logic)
- Exploitation by target: DBMS-specific SQL injection, SSTI per engine, XXE, cloud metadata  
- Post-exploitation: Linux/Windows privilege escalation, Docker escape, token impersonation
- Payloads: SQL injection, XSS, SSTI/command injection, reverse shells, web shells
- Remediation guides for every vulnerability class

## Findings enrichment

Every finding saved via `save_finding` is automatically enriched:

1. CWE ID inferred from the finding title/type
2. CVSS 3.1 base score and vector computed from the CWE
3. OWASP Top 10 category mapped from the CWE
4. MITRE ATT&CK technique mapped from the CWE

SARIF 2.1.0 output is directly compatible with GitHub Code Scanning.

## Benchmark

96% recall on OWASP Juice Shop v17 — 25 of 26 ground truth vulnerabilities found, all 10 OWASP categories covered, 68 total findings.

---

## Requirements

- Python 3.11+
- Playwright (for browser-based testing)
- Optional: `nmap`, `naabu` for faster port scanning
- Optional: `asyncssh`, `smbprotocol` for SSH/SMB protocol testing

```bash
pip install -e ".[protocols]"   # SSH + SMB support
pip install -e ".[all]"         # Everything including dev tools
```

## Configuration

Pass environment variables through your MCP client's `env` block. numasec does not read `.env` files.

| Variable | Description | Default |
|---|---|---|
| `NUMASEC_ALLOW_INTERNAL` | Allow scanning localhost/private IPs (labs) | `0` |
| `NUMASEC_NVD_API_KEY` | NVD API key for CVE enrichment | — |
| `NUMASEC_RATE_PER_MINUTE` | Per-session call limit | `9999` |
| `NUMASEC_RATE_CONCURRENT` | Per-session concurrency | `100` |
| `NUMASEC_RATE_GLOBAL_PER_MINUTE` | Global call limit | `9999` |
| `NUMASEC_RATE_GLOBAL_CONCURRENT` | Global concurrency | `200` |
| `MCP_TRANSPORT` | Transport: `stdio` or `http` | `stdio` |

## Development

```bash
pip install -e ".[all]"
pytest tests/ -v -m "not slow and not benchmark"
ruff check numasec/
mypy numasec/
```

## License

MIT
