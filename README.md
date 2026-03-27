# numasec

AI-powered penetration testing through the Model Context Protocol.

numasec exposes 21 composite security tools to any MCP-compatible AI assistant (GitHub Copilot, Claude Desktop, Cursor, numasec agent, etc.), enabling automated vulnerability discovery following the PTES 5-phase methodology.

## Features

- **21 security tools** — recon, crawling, injection testing, XSS, SSRF, auth testing, access control, path traversal, directory fuzzing, JS analysis, and more
- **PTES methodology** — deterministic 5-phase planner guides the assessment from reconnaissance through exploitation and reporting
- **Multi-client** — works with any MCP-compatible host via stdio or HTTP transport
- **Auto-enrichment** — findings are automatically enriched with CWE, CVSS 3.1, OWASP Top 10, and MITRE ATT&CK mappings
- **Knowledge base** — 34 YAML templates covering detection, exploitation, post-exploitation, payloads, attack chains, and remediation
- **Report generation** — SARIF 2.1.0, Markdown, HTML, and JSON output formats
- **Zero external dependencies for scanning** — pure Python scanners with optional binary acceleration (nmap, naabu)

## Quick Start

```bash
pip install -e ".[mcp]"
playwright install chromium
```

Verify installation:

```bash
numasec --version
```

## MCP Configuration

### VS Code / GitHub Copilot

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "numasec": {
      "command": "numasec",
      "args": ["--mcp"]
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "numasec": {
      "command": "numasec",
      "args": ["--mcp"]
    }
  }
}
```

### Cursor

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

### numasec agent

Add to `numasec.json`:

```json
{
  "mcp": {
    "numasec": {
      "type": "local",
      "command": ["numasec", "--mcp"],
      "enabled": true
    }
  }
}
```

> If `numasec` is not in your PATH, use the full path: `["/usr/bin/python", "-m", "numasec", "--mcp"]`

## Tools

### Security Testing (13)

| Tool | Description |
|------|-------------|
| `recon` | Port scan, tech fingerprint, service probing, CVE enrichment |
| `crawl` | HTTP + SPA crawling, OpenAPI/Swagger import |
| `injection_test` | SQLi, NoSQL, SSTI, command injection, GraphQL |
| `xss_test` | Reflected + DOM XSS with canary injection |
| `auth_test` | JWT attacks, OAuth testing, credential spray |
| `access_control_test` | IDOR, CSRF, CORS misconfiguration |
| `ssrf_test` | SSRF with cloud metadata detection |
| `path_test` | LFI, XXE, open redirect, host header injection |
| `dir_fuzz` | Directory and file enumeration |
| `js_analyze` | JavaScript source analysis for secrets, endpoints, DOM XSS |
| `browser` | Playwright-based browser interaction |
| `http_request` | Raw HTTP requests for manual testing |
| `run_scanner_batch` | Run multiple scanners in parallel |

### Intelligence (2)

| Tool | Description |
|------|-------------|
| `kb_search` | Search the knowledge base for techniques, CWEs, attack patterns |
| `plan` | Generate scan plans, track coverage, suggest next steps |

### State Management (6)

| Tool | Description |
|------|-------------|
| `create_session` | Start a new assessment session |
| `save_finding` | Store a finding with auto-enrichment (CWE → CVSS → OWASP → ATT&CK) |
| `get_findings` | Retrieve findings, filter by severity |
| `generate_report` | Export as SARIF, Markdown, HTML, or JSON |
| `relay_credentials` | Store discovered credentials for authenticated testing |
| `run_scanner_batch` | Parallel scanner execution |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NUMASEC_ALLOW_INTERNAL` | Allow scanning localhost/private IPs | `0` |
| `NUMASEC_NVD_API_KEY` | NVD API key for CVE enrichment | — |
| `NUMASEC_RATE_PER_MINUTE` | Per-session rate limit | `9999` |
| `NUMASEC_RATE_CONCURRENT` | Per-session concurrency | `100` |
| `NUMASEC_RATE_GLOBAL_PER_MINUTE` | Global rate limit | `9999` |
| `NUMASEC_RATE_GLOBAL_CONCURRENT` | Global concurrency | `200` |
| `MCP_TRANSPORT` | Transport protocol (`stdio` or `http`) | `stdio` |

Pass environment variables through your MCP client's config, not `.env` files.

## Optional Dependencies

```bash
pip install -e ".[protocols]"  # SSH/SMB protocol probing (asyncssh, smbprotocol)
pip install -e ".[all]"        # Everything including dev tools
```

## Development

```bash
pip install -e ".[all]"
pytest tests/ -v
ruff check numasec/
mypy numasec/
```

## License

MIT
