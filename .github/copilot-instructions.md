# numasec — Copilot Instructions

## What this project is

**numasec** is an AI-powered penetration testing platform delivered as an MCP (Model Context Protocol) server. It exposes 21+ Python security scanners as MCP tools that a host LLM (Claude, GPT-4, etc.) calls to run real pentests. The TypeScript TUI in `agent/` is a separate frontend (forked from OpenCode, MIT) that communicates with the Python MCP server via JSON-RPC over stdin/stdout.

**Two components**: Python backend (~33K LOC, 38 scanners) + TypeScript TUI (~63K LOC, Bun/SolidJS monorepo).

## Build, test, lint

```bash
# Install everything (includes dev deps)
pip install -e ".[all]"

# Run full test suite (1251 tests)
pytest tests/ -v

# Run a single test file
pytest tests/test_scanners.py -v

# Run a single test by name
pytest tests/test_scanners.py::TestPortInfo::test_defaults -v

# Skip slow/benchmark/integration
pytest tests/ -m "not slow and not benchmark and not integration"

# Lint
ruff check numasec/

# Type check (Python)
mypy numasec/

# Type check (TUI) — MUST run from agent/, not root
cd agent && bun typecheck
```

Tests use `asyncio_mode = "auto"` — all test functions can be `async def` without extra decorators.

Benchmark tests (Juice Shop, DVWA, WebGoat) are marked `benchmark`. Integration tests are marked `integration`.

## Architecture

```
numasec/                    # Python MCP server
  mcp/                      # MCP server, tool bridge, session store, rate limiting, SSRF protection
    server.py               # FastMCP server factory, SessionRateLimiter, SSRF protection
    tool_bridge.py          # bridge_tools_to_mcp() — auto-exposes ToolRegistry as MCP tools
    mcp_session_store.py    # Session CRUD, build_chains() algorithm, finding persistence
  scanners/                 # 38 individual scanners — pure async functions
    sqli.py, xss.py, ssrf.py, auth.py, idor.py, csrf.py, cors.py,
    smuggling.py, race.py, upload.py, ssti.py, cmdi.py, lfi.py, xxe.py,
    graphql.py, crlf.py, nosql.py, open_redirect.py, host_header.py,
    python_connect.py, naabu.py, nmap.py, subdomain_scanner.py,
    crawler.py, browser_crawler.py, cve_enricher.py, service_prober.py,
    shodan.py, openapi_parser.py, js_analyzer.py, dir_fuzzer.py,
    _base.py, _encoder.py, _envelope.py, _plugin.py, waf_evasion.py,
    poc_validator.py, oob_handler.py
  tools/                    # ToolRegistry + 21 composite tools
    __init__.py             # All tool registrations happen here
  core/
    planner.py              # DeterministicPlanner (PTES 5-phase, no LLM)
    coverage.py             # OWASP Top 10 coverage tracking + OWASP_TOOL_MAP
  models/
    finding.py              # Finding model (auto-ID, auto-enrichment)
    target.py               # TargetProfile, Port, Endpoint, Technology, Credential, Token
    plan.py                 # AttackPlan, AttackPhase, AttackStep (living document)
    sarif.py                # SARIF 2.1.0 dataclasses
    enums.py                # Severity, PhaseStatus, PTESPhase
  knowledge/                # KB: 34 bundled YAML templates + BM25 retriever
    templates/              # detection, exploitation, post-exploitation, remediation, payloads, etc.
    retriever.py            # BM25Okapi + optional semantic reranking (60/40 weight)
    loader.py               # YAML template loader
  storage/                  # CheckpointStore (SQLite via aiosqlite, WAL mode)
  reporting/                # SARIF, HTML, Markdown, JSON report generators
    __init__.py             # calculate_risk_score(), build_executive_summary()
    sarif.py, markdown.py, html.py
  security/                 # Input validation, SSRF protection helpers
  standards/                # OWASP Top 10 / CWE mappings
  worker.py                 # JSON-RPC subprocess bridge for TUI (CRITICAL FILE)
  cli/ci_mode.py            # Non-interactive CI pipeline (6-tool sequence)
agent/                      # TypeScript TUI (Bun/SolidJS monorepo, forked from OpenCode)
  packages/numasec/         # Main TUI package
    src/agent/agent.ts      # 5 primary + 4 sub + 3 utility agents defined here
    src/agent/prompt/*.txt  # System prompt files per agent
    src/bridge/python.ts    # PythonBridge — JSON-RPC over stdio to worker.py
    src/tool/               # 41 TUI-side tool definitions
    src/provider/           # 16+ LLM provider integrations (Anthropic, OpenAI, etc.)
    src/command/            # Slash commands (/target, /findings, /report, etc.)
    src/cli/cmd/tui/        # TUI rendering
      app.tsx               # Root component, 13 context providers
      routes/home.tsx       # Session list
      routes/session/       # Main chat interface
        index.tsx           # Message display (2,430 lines)
        sidebar.tsx         # Findings panel, attack chains, OWASP matrix, todos
        header.tsx          # OWASP heatmap, cost, model info
        footer.tsx          # Status bar
        question.tsx        # Interactive prompts
        permission.tsx      # Permission request UI with code diffs
      context/              # SolidJS contexts (sync, sdk, theme, keybind, route, etc.)
      component/            # Dialogs, evidence browser, prompts, tips
  packages/sdk/js/          # TypeScript SDK (types, client, server)
  packages/ui/              # Shared UI components
tests/                      # 1251 pytest tests across 55 files
community-templates/        # 6 community scanner templates (CORS, headers, cookies, etc.)
```

### Data flow

**MCP path** (standalone server):
1. Host LLM calls an MCP tool (e.g. `recon`, `injection_test`)
2. `tool_bridge.py` routes through `ToolRegistry.call()`
3. Composite tools in `numasec/tools/` orchestrate individual scanners
4. Scanners in `numasec/scanners/` make HTTP requests and return structured dicts
5. Findings saved via `McpSessionStore` → `CheckpointStore` (SQLite)
6. `generate_report` produces SARIF / Markdown / HTML / JSON output

**TUI path** (interactive terminal):
1. TUI spawns `python -m numasec.worker` as subprocess
2. `python.ts` (PythonBridge) sends JSON-RPC requests over stdin
3. `worker.py` dispatches: SPECIAL_METHODS → custom handlers, others → `ToolRegistry.call()`
4. Responses stream back over stdout as newline-delimited JSON
5. TUI parses responses, updates SolidJS reactive state, renders terminal UI

### worker.py — the critical bridge file

`worker.py` is the most important integration point. It handles:

- **SPECIAL_METHODS**: `create_session`, `save_finding`, `get_findings`, `generate_report`, `build_chains`, `plan`, `relay_credentials`, `coverage_gaps`, `mandatory_tests`, `chain`, `post_auth` — these bypass ToolRegistry and have custom handler functions
- **Auto-save**: `_auto_save_findings()` extracts findings from any tool response and persists them
- **Parameter normalization**: Maps TUI parameter names to Python tool expectations
- **Concurrent dispatch**: Semaphore-limited (default 5) parallel tool execution
- **Vulnerability type mapping**: `_VULN_TYPE_MAP` maps scanner names to human-readable types

⚠️ **GOTCHA**: Worker serializes findings manually (dict construction, NOT `model_dump()`). When adding new fields to the Finding model, you MUST also add them to the worker's serialization code in `_handle_get_findings()`, `_handle_build_chains()`, and `_handle_generate_report()`.

### Tool registration pattern

Every tool is registered with `ToolRegistry` (OpenAI-compatible JSON schema):

```python
registry.register("tool_name", async_func, schema={"description": "...", "parameters": {...}})
```

`bridge_tools_to_mcp(mcp, registry)` then auto-exposes all registered tools as MCP tools. New tools must be registered in `numasec/tools/__init__.py` before the server starts.

### Scanner extensibility

Two mechanisms for adding scanners without touching core code:

- **Python plugins**: drop a `.py` file with a `register(registry)` function into `~/.numasec/plugins/`
- **YAML scanner templates**: drop a `.yaml` file into `~/.numasec/plugins/` using the template format defined in `numasec/scanners/_plugin.py`

`ScanEngineFactory` auto-selects the best port scanner backend: naabu → nmap → pure Python.

### Session lifecycle

```
create_session(target) → save_finding() × N → build_chains() → generate_report()
```

- SQLite with WAL mode, 4 tables: `sessions`, `findings`, `events`, `tool_cache`
- Rate limiting per-session via `SessionRateLimiter` (env: `NUMASEC_RATE_PER_MINUTE`, `NUMASEC_RATE_CONCURRENT`)
- Auto-enrichment on `save_finding()`: CWE → CVSS 3.1 → OWASP category → MITRE ATT&CK

### Finding model

- **ID**: `SSEC-{SHA256(method:url:parameter:title)[:12].upper()}` — deterministic, dedup-friendly
- **Severity**: Enum with auto-normalization (`crit`→`critical`, `med`→`medium`)
- **Auto-generated fields** (don't set manually): `id`, `cvss_score`, `cvss_vector`, `owasp_category`, `timestamp`
- **Chain fields**: `chain_id` (set by `build_chains()`), `related_finding_ids`
- **Confidence**: float 0-1, default 0.5

### Attack chains

`build_chains()` in `mcp_session_store.py` groups findings by URL base path, then merges via `related_finding_ids`. Only chains with 2+ findings are shown. The sidebar displays chain headers as `⛓ SQL Injection → IDOR` with per-finding severity dots (● red/yellow/green).

Chain data flows to the TUI from 3 sources:
1. `save_finding` responses (Source 1 — individual findings with chain_id)
2. `build_chains` / `generate_report` responses (Source 2 — `findings` array with title/severity/url/chain_id)
3. `get_findings` responses (Source 3 — all findings with chain_id field)

### Planner (DeterministicPlanner)

PTES 5-phase methodology, NO internal LLM calls (based on CHECKMATE paper):
1. **Recon**: port scan, tech fingerprint, optional dir fuzz
2. **Service Mapping**: map services, endpoints
3. **Vulnerability Testing**: selected by `_select_vuln_tests()` based on detected technologies
4. **Exploitation Validation**: only in standard/deep scope
5. **Reporting**: generate assessment report

**Replan signals**: `waf_detected`, `escalation_found`, `auth_obtained`, `rate_limited`, `technology_identified`, `large_surface`, `api_app_detected`, `spa_detected`

**Scope timeouts**: quick=3min, standard=10min, deep=30min

### Reporting

4 formats: **SARIF** 2.1.0 (CI/CD), **HTML** (self-contained), **Markdown**, **JSON**

Risk score: `min(100, sum(severity_weight × confidence))` where weights are critical=25, high=15, medium=8, low=3, info=1.

Executive summary includes OWASP Top 10 coverage percentage.

### Knowledge base

34 bundled YAML templates in 8 categories: detection, exploitation, post-exploitation, remediation, reference, attack_chains, payloads, protocols. BM25 retriever with optional semantic reranking (60% BM25, 40% cosine similarity). 6 community templates auto-loaded as MCP tools.

## Key conventions (Python)

- `from __future__ import annotations` at the top of every module
- Pydantic v2 `BaseModel` for all data models; use `field_validator` / `model_validator`
- Line length: 120 chars (ruff, `E501` ignored)
- `Finding` model auto-generates ID, CVSS score, and OWASP category on creation — don't set these manually
- Tests prefer real implementations over mocks; avoid `unittest.mock` unless testing external I/O
- All scanner functions are `async def`; use `httpx.AsyncClient` for HTTP (not `requests`)
- `verify=False, follow_redirects=True` is the standard `AsyncClient` config for scanners
- SSRF protection is enforced in `mcp/server.py` — internal IPs/localhost are blocked unless `NUMASEC_ALLOW_INTERNAL=1`

## TypeScript TUI (agent/)

The `agent/` directory is a separate Bun/TypeScript monorepo. Its conventions (in `agent/AGENTS.md`) differ from the Python package:

- Default branch: `dev`; use `dev` or `origin/dev` for diffs
- Prefer single-word variable names; avoid destructuring; no `else` statements
- Run tests from package directories (e.g. `packages/numasec`), not the repo root
- `bun typecheck` for type checking, not `tsc` directly
- Effect-TS for service composition (Effect.gen, Effect.fn, Schema.Class)
- SolidJS for reactive UI rendering (@opentui/core + @opentui/solid)

### TUI agents

**5 primary** (user-selectable): `pentest` (default, full PTES), `recon` (no exploitation), `hunt` (aggressive OWASP Top 10), `review` (source code only), `report` (documentation/validation)

**4 subagents**: `scanner` (raw scan delegation), `analyst` (false positive validation, chain correlation), `reporter` (SARIF/MD/HTML generation), `explore` (CVE research, read-only)

**3 utility** (hidden): `compaction`, `title`, `summary`

Each agent has: system prompt (`src/agent/prompt/*.txt`), permission model, temperature, color, tool restrictions.

### TUI bridge

`PythonBridge` (`src/bridge/python.ts`):
- Spawns `python -m numasec.worker` with `PYTHONUNBUFFERED=1`
- Waits for `{ ready: true }` (30s timeout)
- Health check: every 30s via `ping` method
- Call timeout: 5 minutes (300s)
- Auto-restart: max 3 in 60s window, then degraded mode

### Slash commands

`/target` (set pentest target), `/findings` (list findings), `/report` (generate report), `/coverage` (OWASP matrix), `/creds` (discovered credentials), `/evidence` (finding evidence), `/init` (initialize workspace), `/review` (code review)

## Common pitfalls

1. **Worker serialization**: Adding a field to Finding but forgetting to serialize it in worker.py's manual dict construction
2. **Sidebar data sources**: Attack chain data arrives from 3 different response types — changes must handle all 3
3. **Test from correct dir**: TUI tests fail from repo root; must `cd agent/packages/numasec`
4. **SSRF protection**: Scanners targeting localhost/internal IPs need `NUMASEC_ALLOW_INTERNAL=1`
5. **ScanEngineFactory**: Port scanner backend varies by environment — tests should mock or use the pure Python fallback
