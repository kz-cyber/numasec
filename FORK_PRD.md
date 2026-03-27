# numasec: The numasec-upstream Fork for Pentesting

## Product Requirements Document & Engineering Blueprint

**Version**: 1.0
**Date**: 2026-03-27
**Author**: Engineering deep-think analysis

---

## 1. Executive Summary

**What**: Fork numasec-upstream (MIT, TypeScript/Bun, 131k stars) and replace its "coding assistant" domain with numasec's pentesting domain, producing a standalone agentic pentesting terminal called **numasec**.

**Why**: numasec-upstream is the best open-source implementation of the Claude Code UX pattern — interactive, multi-turn, human-in-the-loop agentic sessions with context management, subagents, checkpoints, and undo/redo. Building this from scratch would take 6+ months. Forking gives us the entire agentic infrastructure in exchange for learning the codebase.

**Product vision**: `numasec` is what you get when a senior pentester has an AI co-pilot that can scan, exploit, document, and report — interactively, in real-time, in a terminal.

---

## 2. numasec-upstream Architecture Audit

### 2.1 Monorepo Structure

```
numasec/
├── packages/
│   ├── numasec/          # ★ CORE: Engine, server, CLI, TUI, tools, sessions
│   │   ├── src/
│   │   │   ├── agent/     # Agent definitions, prompts, generation
│   │   │   ├── session/   # Session management, LLM calls, compaction, revert
│   │   │   ├── tool/      # Built-in tools (bash, read, write, edit, grep, glob...)
│   │   │   ├── provider/  # LLM provider abstraction (AI SDK wrappers)
│   │   │   ├── mcp/       # MCP client (for connecting to external MCP servers)
│   │   │   ├── plugin/    # Plugin loader and hook system
│   │   │   ├── skill/     # On-demand skill loading from SKILL.md files
│   │   │   ├── permission/# Permission system (ask/allow/deny per tool)
│   │   │   ├── server/    # Hono HTTP API server
│   │   │   ├── cli/       # CLI parsing, TUI entry (SolidJS + opentui)
│   │   │   ├── config/    # Configuration loading and merging
│   │   │   ├── storage/   # SQLite + Drizzle ORM
│   │   │   ├── snapshot/  # File checkpointing for undo/redo
│   │   │   ├── file/      # File operations 
│   │   │   ├── lsp/       # Language Server Protocol client
│   │   │   ├── shell/     # Shell/PTY management
│   │   │   ├── pty/       # Pseudo-terminal support
│   │   │   └── ...
│   │   ├── migration/     # Drizzle DB migrations
│   │   ├── test/          # Core tests
│   │   └── bin/           # Binary entry point
│   ├── app/               # Web UI (SolidJS components)
│   ├── desktop/           # Native desktop (Tauri)
│   ├── desktop-electron/  # Electron alternative 
│   ├── sdk/               # JS/TS SDK (@numasec-ai/sdk)
│   ├── plugin/            # Plugin toolkit (@numasec-ai/plugin)
│   ├── ui/                # Shared UI components
│   ├── web/               # Documentation site
│   ├── console/           # Console UI
│   └── ...
├── sdks/vscode/           # VS Code extension
├── infra/                 # Infrastructure
└── turbo.json             # Turborepo config
```

### 2.2 Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Runtime | **Bun 1.3+** | JS runtime, bundler, package manager, shell API |
| Type System | **TypeScript** + tsgo | Type checking |
| Effect System | **Effect-TS** | Service composition, error handling, concurrency, DI |
| LLM Integration | **Vercel AI SDK** (`ai` + `@ai-sdk/*`) | 16+ provider adapters under unified interface |
| Terminal UI | **SolidJS** + **@opentui/core** + **@opentui/solid** | Reactive terminal rendering |
| Web UI | **SolidJS** + **Vite** | Shared browser/desktop components |
| Desktop | **Tauri** | Native app wrapping web UI |
| HTTP Server | **Hono** | API server for client/server architecture |
| Database | **Drizzle ORM** + **SQLite** | Session/message/finding persistence |
| MCP | **@modelcontextprotocol/sdk** 1.27.1 | MCP client for external tool servers |
| File Watch | **@parcel/watcher** | File system monitoring |
| PTY | **bun-pty** | Terminal emulation |
| Build | **Turborepo** | Monorepo build orchestration |

### 2.3 Key Design Patterns

1. **Effect-TS throughout** — Every service is an Effect, composed via `Effect.gen`. Services use `InstanceState` for per-directory isolation and `makeRuntime` for shared singletons.
2. **Tool = .ts + .txt** — Each tool has a TypeScript implementation and a `.txt` system prompt description. The LLM sees the `.txt`; the engine executes the `.ts`.
3. **Client/Server split** — Headless server (Hono) exposes full API. TUI, Web, Desktop, SDK are all clients connecting to the same server. This is architectural gold for us.
4. **Pluggable everything** — Agents (markdown), skills (SKILL.md), plugins (JS/TS hooks), custom tools (JS/TS), MCP servers — all extensible without touching core.

### 2.4 LOC Estimate

Based on structure analysis and active development velocity (741 releases, 828 contributors):

| Package | Estimated LOC | Relevance to Fork |
|---------|--------------|-------------------|
| `packages/numasec/src/` | ~40-50k | HIGH — this is the engine |
| `packages/app/` | ~15-20k | MEDIUM — UI customization |
| `packages/sdk/` | ~5k | KEEP — client library |
| `packages/plugin/` | ~2k | KEEP — plugin system |
| `packages/desktop/` | ~3k | LOW priority — later |
| Everything else | ~20k | REMOVE/IGNORE |

---

## 3. Fork Strategy

### 3.1 Philosophy: Domain Swap, Not Rewrite

numasec-upstream is a **domain-agnostic agentic harness** dressed in coding clothes. The agentic loop, session management, context compaction, tool dispatch, provider abstraction, permission system, checkpoint/revert, subagent orchestration — none of this is coding-specific.

What makes it a "coding agent" is:
1. **18 coding-specific tools** (read, write, edit, multiedit, apply_patch, glob, grep, ls, lsp, bash, codesearch, websearch, webfetch, batch, task, todo, skill, question, plan)
2. **System prompts** that say "you are a coding assistant"
3. **LSP integration** for code intelligence
4. **File editing** as the primary output modality

For pentesting:
1. Tools become security scanners, HTTP clients, and analysis tools
2. System prompts say "you are a penetration tester following PTES"
3. LSP integration is replaced by target intelligence
4. Findings/reports are the primary output modality

### 3.2 What We Keep (Unchanged)

These are the foundation — we do not touch them:

| Component | Path | Rationale |
|-----------|------|-----------|
| Session engine | `src/session/` | Message handling, LLM calls, compaction, retry, revert |
| Provider layer | `src/provider/` | All 16+ LLM providers via AI SDK |
| Agent framework | `src/agent/` | Agent definitions, subagent dispatch |
| Permission system | `src/permission/` | Ask/allow/deny per tool per agent |
| Plugin system | `src/plugin/` | Hook system for extensibility |
| Skill system | `src/skill/` | On-demand knowledge loading |
| MCP client | `src/mcp/` | Can connect to OTHER MCP servers |
| Config system | `src/config/` | Config loading, merging, precedence |
| Storage layer | `src/storage/` | SQLite + Drizzle |
| Server | `src/server/` | Hono API server |
| CLI framework | `src/cli/` | Command parsing, TUI entry |
| Authentication | `src/auth/` | Provider auth flows |
| Effect runtime | `src/effect/` | Effect-TS infrastructure |
| Snapshot/revert | `src/snapshot/` | Checkpoint system |
| Shell/PTY | `src/shell/`, `src/pty/` | For running commands |
| Question tool | `src/tool/question.ts` | Human-in-the-loop prompts |
| Batch tool | `src/tool/batch.ts` | Parallel operations |
| Task/Todo | `src/tool/task.ts`, `todo.ts` | Progress tracking |
| SDK | `packages/sdk/` | Programmatic access |
| Plugin toolkit | `packages/plugin/` | Plugin development |
| UI library | `packages/ui/` | Shared components |

### 3.3 What We Remove

| Component | Path | Rationale |
|-----------|------|-----------|
| Write tool | `src/tool/write.ts` | No file creation in pentest mode |
| Edit tool | `src/tool/edit.ts` | No code editing |
| MultiEdit tool | `src/tool/multiedit.ts` | No code editing |
| ApplyPatch tool | `src/tool/apply_patch.ts` | No patching |
| LSP integration | `src/lsp/` | No language servers needed |
| Code search | `src/tool/codesearch.ts` | Not applicable |
| Plan enter/exit | `src/tool/plan.ts`, `plan-enter.txt`, `plan-exit.txt` | Replaced by pentest plan tool |
| IDE integration | `src/ide/` | We build our own or skip |
| Formatters | (config) | Not applicable |
| VS Code extension | `sdks/vscode/` | Phase 2 |
| i18n translations | `packages/app/src/i18n/` | Reduce to EN only initially |
| Unnecessary provider deps | Various `@ai-sdk/*` | Keep top 5, remove edge cases |

### 3.4 What We Modify

| Component | Change | Effort |
|-----------|--------|--------|
| System prompts | Rewrite all prompts in `src/session/prompt/` and `src/agent/prompt/` | MEDIUM |
| Default agents | `build`→`pentest`, `plan`→`reconnaissance`, new subagents | SMALL |
| TUI layout | Add findings panel, OWASP coverage, target info bar | MEDIUM |
| Web UI layout | Security dashboard instead of code editor | MEDIUM |
| CLI commands | `/target`, `/findings`, `/report`, `/creds`, `/coverage` | MEDIUM |
| Branding | numasec→numasec everywhere | SMALL (sed) |
| Config schema | Add security-specific config (target scope, auth, proxy) | SMALL |
| Tool registry | Register numasec tools instead of coding tools | MEDIUM |

### 3.5 What We Add

| Component | Description | Effort |
|-----------|-------------|--------|
| Python bridge | TypeScript→Python IPC for numasec scanners | HIGH |
| 21 native security tools | TypeScript wrappers calling Python scanners | HIGH |
| Finding model | Drizzle schema for findings with auto-enrichment | MEDIUM |
| Target model | Persistent target profile accumulating recon data | MEDIUM |
| OWASP coverage tracker | Real-time coverage visualization | SMALL |
| Report generator | SARIF/HTML/Markdown within the tool framework | MEDIUM |
| Knowledge base integration | BM25 retrieval from 34 YAML templates via bridge | MEDIUM |
| Security-specific skills | SKILL.md files for PTES phases | SMALL |
| Attack chain visualization | TUI representation of vulnerability chains | MEDIUM |

---

## 4. Python Bridge Architecture

This is the most critical engineering decision. numasec has ~30 Python scanners, 34 YAML knowledge templates, and extensive Python-specific dependencies (httpx, playwright, beautifulsoup4, cryptography, etc.). Rewriting in TypeScript is neither feasible nor desirable.

### 4.1 Bridge Design: JSON-RPC over stdio

```
┌─────────────────────────┐     stdin/stdout      ┌──────────────────────┐
│    numasec (Bun/TS)     │ ◄──── JSON-RPC ────► │  numasec-worker (Py) │
│                         │                        │                      │
│  Tool: recon.ts         │ → {"method":"recon",   │  Dispatcher          │
│  Tool: injection.ts     │    "params":{...}}     │   ├─ ScanEngine      │
│  Tool: xss.ts           │                        │   ├─ Crawlers        │
│  ...                    │ ← {"result":{...}}     │   ├─ Testers         │
│                         │                        │   └─ KB Retriever    │
└─────────────────────────┘                        └──────────────────────┘
```

**Why JSON-RPC over stdio (not HTTP, not MCP)**:
- **Not HTTP**: Adds unnecessary network stack. We're same-machine.
- **Not MCP**: MCP is designed for the LLM-to-tool interface, not internal IPC. We don't need MCP's discovery/negotiation overhead for our own tools.
- **stdio**: Zero configuration, zero ports, process lifecycle tied to parent. Bun's `Bun.spawn` with `stdin: "pipe"` and `stdout: "pipe"` makes this trivial.

### 4.2 Python Worker Process

```python
# numasec/worker.py — long-lived subprocess
import json, sys, asyncio
from numasec.scanners import SCANNER_REGISTRY
from numasec.knowledge import retriever
from numasec.models import Finding, TargetProfile

async def dispatch(method: str, params: dict) -> dict:
    """Route JSON-RPC calls to scanner implementations."""
    scanner = SCANNER_REGISTRY[method]
    result = await scanner.execute(**params)
    return result.to_dict()

async def main():
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    
    while True:
        line = await reader.readline()
        if not line:
            break
        request = json.loads(line)
        try:
            result = await dispatch(request["method"], request.get("params", {}))
            response = {"id": request["id"], "result": result}
        except Exception as e:
            response = {"id": request["id"], "error": {"message": str(e)}}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

asyncio.run(main())
```

### 4.3 TypeScript Tool Wrapper Pattern

```typescript
// src/tool/recon.ts
import { z } from "zod"
import { PythonBridge } from "../bridge/python"

const ReconInput = z.object({
  target: z.string().describe("Target host or URL to scan"),
  ports: z.string().optional().describe("Port range (e.g., '1-1000', 'top100')"),
  service_detection: z.boolean().default(true),
})

export const recon = {
  name: "recon",
  description: /* loaded from recon.txt */,
  parameters: ReconInput,
  async execute(args: z.infer<typeof ReconInput>) {
    const bridge = PythonBridge.instance()
    const result = await bridge.call("recon", args)
    return formatReconResult(result)
  }
}
```

Each of the 21 numasec tools follows this pattern: Zod schema + `bridge.call()` + result formatting.

### 4.4 Bridge Lifecycle

```typescript
// src/bridge/python.ts
export class PythonBridge {
  private process: Subprocess
  private pending: Map<string, { resolve, reject }>
  
  async start() {
    this.process = Bun.spawn(["python", "-m", "numasec.worker"], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    })
    this.readLoop()
  }

  async call(method: string, params: object): Promise<any> {
    const id = ulid()
    const promise = new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
    })
    this.process.stdin.write(JSON.stringify({ id, method, params }) + "\n")
    return promise
  }
  
  private async readLoop() {
    const reader = this.process.stdout.getReader()
    // ... readline, parse JSON, resolve pending promises
  }
}
```

**Lifecycle**:
- Bridge starts with the server (lazy — first tool call triggers spawn)
- Stays alive for the session duration
- Restarts automatically on crash
- Graceful shutdown on server exit

---

## 5. Tool Mapping

### 5.1 Kept Tools (from numasec-upstream)

| numasec-upstream Tool | numasec Use |
|--------------|-------------|
| `bash` | Running security commands (nmap, curl, etc.) |
| `read` | Reading target configs, server files (post-exploit) |
| `grep` | Searching through crawl results, response bodies |
| `glob` | Finding files in downloaded/enumerated content |
| `ls` | Listing directories for recon data |
| `webfetch` | Fetching web pages for analysis |
| `websearch` | Researching CVEs, exploits, documentation |
| `question` | Human-in-the-loop: "Should I test this endpoint?" |
| `batch` | Parallel scanning operations |
| `task` / `todo` | Tracking pentest progress |
| `skill` | Loading security knowledge on demand |

### 5.2 New Security Tools (via Python Bridge)

| Tool | Bridge Method | Description |
|------|--------------|-------------|
| `recon` | `recon` | Port scan + tech detect + service probe + CVE enrichment |
| `crawl` | `crawl` | HTTP crawl + SPA crawl + OpenAPI import |
| `injection_test` | `injection_test` | SQLi + NoSQL + CMDi + SSTI + XXE testing |
| `xss_test` | `xss_test` | Reflected + stored + DOM XSS |
| `ssrf_test` | `ssrf_test` | Server-side request forgery |
| `auth_test` | `auth_test` | JWT + OAuth + credential spray |
| `access_control_test` | `access_control_test` | IDOR + privilege escalation |
| `path_test` | `path_test` | LFI + path traversal |
| `dir_fuzz` | `dir_fuzz` | Directory and file brute-forcing |
| `js_analyze` | `js_analyze` | JavaScript static analysis (secrets, endpoints) |
| `browser` | `browser` | Playwright-based browser automation |
| `oob` | `oob` | Out-of-band interaction testing |
| `http_request` | `http_request` | Raw HTTP request construction |
| `save_finding` | `save_finding` | Persist finding with auto-enrichment |
| `get_findings` | `get_findings` | Query findings by severity/category |
| `generate_report` | `generate_report` | SARIF/HTML/Markdown output |
| `kb_search` | `kb_search` | BM25 search over 34 knowledge templates |
| `plan` | `plan` | PTES planning + coverage tracking |
| `create_session` | `create_session` | Initialize pentest session |
| `relay_credentials` | `relay_credentials` | Store and relay discovered credentials |
| `run_scanner_batch` | `run_scanner_batch` | Execute multiple scanners in sequence |

### 5.3 New Native Tools (TypeScript, no bridge)

| Tool | Description |
|------|-------------|
| `target` | Set/get current target (stored in session state) |
| `coverage` | Display OWASP Top 10 coverage matrix |
| `evidence` | Capture and store evidence (screenshots, responses) |

---

## 6. Agent Architecture

### 6.1 Primary Agents (Tab-switchable)

```markdown
# pentest (default primary)
---
mode: primary
model: anthropic/claude-sonnet-4-20250514
description: AI penetration tester following PTES methodology
permission:
  bash:
    "*": ask
    "curl *": allow
    "nmap *": allow  
    "nikto *": allow
    "sqlmap *": ask
    "nuclei *": allow
  edit: deny
  skill:
    "*": allow
---

You are numasec, an AI penetration testing assistant. You follow the 
Penetration Testing Execution Standard (PTES) 5-phase methodology:

1. RECONNAISSANCE — Port scanning, service detection, technology fingerprinting
2. DISCOVERY — Endpoint crawling, directory fuzzing, JavaScript analysis  
3. VULNERABILITY ASSESSMENT — Automated and manual vulnerability testing
4. EXPLOITATION — Controlled exploitation to confirm vulnerabilities
5. REPORTING — Documentation with evidence, severity, and remediation

You ALWAYS:
- Ask before testing destructive payloads
- Track OWASP Top 10 coverage
- Save findings with evidence
- Follow scope restrictions strictly
- Report false positives when you detect them
```

```markdown
# recon (primary, read-only)
---
mode: primary
model: anthropic/claude-sonnet-4-20250514
description: Reconnaissance-only mode — scanning and analysis without exploitation
permission:
  bash:
    "*": deny
    "nmap *": allow
    "dig *": allow
    "whois *": allow
    "curl -I *": allow
  edit: deny
---

You are in RECONNAISSANCE MODE. You can scan, enumerate, and analyze but 
CANNOT send exploitation payloads. Use this for initial target assessment 
and scope validation.
```

### 6.2 Subagents

| Agent | Mode | Purpose | Key Tools |
|-------|------|---------|-----------|
| `scanner` | subagent | Runs automated vulnerability scans on specific endpoints | injection_test, xss_test, ssrf_test, auth_test |
| `analyst` | subagent | Reviews scan results, eliminates false positives, correlates findings | get_findings, kb_search, read, grep |
| `reporter` | subagent | Generates structured reports from findings | get_findings, generate_report, evidence |
| `researcher` | subagent | Deep-dives into specific vulnerabilities, searches for exploits | kb_search, websearch, webfetch |

### 6.3 How They Orchestrate

Typical pentest session:

```
User: "Test https://target.com for OWASP Top 10"

[pentest agent]:
  1. Loads skill "ptes-methodology"
  2. Calls create_session, sets target
  3. Delegates @scanner for recon phase → recon tool
  4. Reviews results, asks user: "Found 47 endpoints, 3 services. Proceed?"
  5. User: "Yes, focus on the API endpoints"
  6. Delegates @scanner for injection testing on API endpoints
  7. Delegates @scanner for XSS testing on form endpoints  (parallel)
  8. Results come back → delegates @analyst to review
  9. @analyst eliminates false positives, correlates attack chains
  10. Reports to user: "Confirmed 5 vulnerabilities. Want to see details?"
  11. User: "Generate the report"
  12. Delegates @reporter → generate_report
```

The human can **interrupt at any step**, steer the agent, add context, expand/narrow scope. This is the Claude Code experience applied to pentesting.

---

## 7. TUI Customization

### 7.1 Layout Changes

numasec-upstream's TUI has a chat-centric layout:
```
┌──────────────────────────────────────┐
│  Session Title          Agent: Build │
├──────────────────────────────────────┤
│                                      │
│  [Message history]                   │
│                                      │
│                                      │
│                                      │
├──────────────────────────────────────┤
│  > Input prompt                      │
└──────────────────────────────────────┘
```

numasec's TUI adds a **status bar** and **findings feed**:
```
┌──────────────────────────────────────────────────────────┐
│ ☠ numasec    Target: https://juice-shop:3000   pentest  │
│ Coverage: ████████░░ 80% OWASP   Findings: 7 (2C 3H 2M) │
├─────────────────────────────────────┬────────────────────┤
│                                     │ FINDINGS           │
│  [Message history / tool output]    │ ┌─ CRITICAL ─────┐ │
│                                     │ │ SQLi /api/login │ │
│  ⚡ Running injection_test on       │ │ XSS /search     │ │
│    POST /api/users/login ...        │ ├─ HIGH ─────────┤ │
│                                     │ │ SSRF /fetch     │ │
│  ✓ Found: SQL Injection (CRITICAL)  │ │ Auth bypass     │ │
│    Evidence: ' OR 1=1-- in email    │ │ JWT none alg    │ │
│                                     │ ├─ MEDIUM ───────┤ │
│                                     │ │ CORS misconfig  │ │
│                                     │ │ Info disclosure │ │
│                                     │ └────────────────┘ │
├─────────────────────────────────────┴────────────────────┤
│  > Test the password reset flow for auth bypass          │
└──────────────────────────────────────────────────────────┘
```

### 7.2 Custom Commands

| Command | Action |
|---------|--------|
| `/target <url>` | Set pentest target (validates scope) |
| `/findings` | Full findings table (sortable by severity) |
| `/coverage` | OWASP Top 10 coverage matrix |
| `/report [format]` | Generate report (sarif\|html\|md) |
| `/creds` | List discovered credentials |
| `/evidence <finding_id>` | Show evidence for a finding |
| `/scope` | Show/edit permitted target scope |
| Tab | Switch between `pentest` ↔ `recon` modes |

---

## 8. Implementation Plan

### Phase 0: Fork & Setup (Week 1)

```bash
# Fork
git clone https://github.com/anomalyco/numasec numasec-agent
cd numasec-agent
git remote rename origin upstream
git remote add origin git@github.com:your-org/numasec-agent.git

# Global rename
find . -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.json" -o -name "*.md" \) \
  -exec sed -i 's/numasec/numasec/g' {} +
# (careful: needs case-sensitive passes and manual review)

# Verify it builds
bun install
bun dev
```

Deliverable: numasec branded fork that builds and runs as-is (still coding mode).

### Phase 1: Strip Coding, Add Security Shell (Week 2-3)

1. **Remove coding tools**: Delete `write.ts`, `edit.ts`, `multiedit.ts`, `apply_patch.ts`, `codesearch.ts`, `lsp.ts` and their `.txt` files
2. **Remove LSP subsystem**: Delete `src/lsp/`
3. **Rewrite system prompts**: All files in `src/session/prompt/` and `src/agent/prompt/`
4. **Replace default agents**: `build`→`pentest`, `plan`→`recon`
5. **Add Python bridge**: `src/bridge/python.ts` with lifecycle management
6. **Add Python worker**: `python/numasec/worker.py` (JSON-RPC dispatcher)
7. **Register first 5 security tools**: `recon`, `crawl`, `injection_test`, `xss_test`, `http_request`

Deliverable: numasec that can do basic recon + injection testing via interactive conversation.

### Phase 2: Full Tool Integration (Week 4-5)

1. **Register remaining 16 security tools** via Python bridge
2. **Add subagents**: `scanner`, `analyst`, `reporter`, `researcher`
3. **Add security skills**: PTES methodology, OWASP checklist, per-vuln-class testing guides
4. **Add finding persistence**: Drizzle schema for findings + target profiles
5. **Custom commands**: `/target`, `/findings`, `/report`, `/coverage`

Deliverable: Full 21-tool pentest agent with persistent findings and reporting.

### Phase 3: TUI Enhancement (Week 6-7)

1. **Findings sidebar panel** (SolidJS component in `packages/app`)
2. **Coverage status bar** (OWASP Top 10 progress)
3. **Target info header bar**
4. **Evidence viewer** (request/response display)
5. **Theming** (security-focused dark themes)

Deliverable: Professional pentesting TUI experience.

### Phase 4: Polish & Ship (Week 8)

1. **Install script**: `curl -fsSL https://numasec.dev/install | bash`
2. **Python dependency management**: Bundled virtualenv or auto-install
3. **Documentation site** (repurpose `packages/web/`)
4. **GitHub Actions CI**: Build + test + release pipeline
5. **End-to-end tests against DVWA/Juice Shop/WebGoat**

Deliverable: Shippable v0.1.0.

---

## 9. Critical Technical Decisions

### 9.1 Python Dependency Distribution

**Problem**: numasec needs Python 3.11+ with httpx, playwright, beautifulsoup4, etc.

**Options**:
| Option | Pros | Cons |
|--------|------|------|
| Require user has Python | Simple | Bad UX, version conflicts |
| Bundle via PyInstaller | No Python needed | Huge binary, packaging complexity |
| Embedded venv | Controlled deps, user has Python | Needs Python installed |
| uv auto-install | Modern, fast, handles Python itself | uv dependency |

**Decision**: **uv auto-install**. On first run, numasec checks for `uv`, installs it if missing, then `uv sync` creates a managed venv. This is the modern Python packaging standard and handles Python version management too.

```typescript
// src/bridge/setup.ts
async function ensurePythonEnv() {
  // 1. Check for uv
  const hasUv = await which("uv")
  if (!hasUv) {
    await $`curl -LsSf https://astral.sh/uv/install.sh | sh`
  }
  // 2. Create/sync venv with numasec Python package
  await $`uv sync --project ${NUMASEC_PYTHON_DIR}`
  // 3. Return python path
  return `${NUMASEC_PYTHON_DIR}/.venv/bin/python`
}
```

### 9.2 What About the MCP Server?

numasec currently IS an MCP server. After the fork, the relationship changes:

- **numasec-agent** (the fork) = the agentic terminal (replaces the numasec-upstream binary)
- **numasec** (original Python package) = the scanner engine (used as a library by the worker process, NOT as MCP server)

The MCP server capability is preserved but becomes optional — you can still run `numasec --mcp` to expose tools to Claude Code or VS Code Copilot. But the primary product is the standalone agent.

### 9.3 Upstream Sync Strategy

**Policy: Selective cherry-pick, not merge.**

After forking, we track upstream `anomalyco/numasec` tags. When they release, we:
1. Read the changelog
2. Cherry-pick bug fixes and infrastructure improvements
3. Ignore coding-specific features
4. Never merge dev branch wholesale

Over time, the codebases diverge. That's fine — we're building a different product.

Key areas to monitor upstream:
- Provider layer updates (new LLM providers, AI SDK upgrades)
- Session/compaction improvements
- TUI framework upgrades (opentui)
- Security patches
- Performance improvements

### 9.4 Scope Enforcement

Pentesting tools should NEVER:
- Scan targets outside defined scope
- Store credentials in plaintext
- Execute exploits without user confirmation
- Make destructive changes to target systems

Implementation:
- `src/security/scope.ts` — validates all target URLs against allowed scope
- Permission system hooks — `auth_test` and `injection_test` always require `ask` confirmation
- Session-level scope stored in DB, checked before every tool call

---

## 10. Competitive Landscape & Moat

| Product | What It Does | How numasec Differs |
|---------|-------------|-------------------|
| Burp Suite | Manual/semi-auto web scanner | AI-driven conversation, not button-clicking |
| OWASP ZAP | Open-source web scanner | Interactive agent, not fire-and-forget |
| Nuclei | Template-based vuln scanner | AI selects and chains templates dynamically |
| PentestGPT | GPT wrapper for pentest guidance | Actually executes scans, not just suggests |
| Claude Code + MCP | Coding agent using numasec tools | Purpose-built UX, deeper integration |

**Moat**: The combination of (1) Claude Code-quality agentic UX with (2) professional-grade scanning engine with (3) 34-template knowledge base with (4) PTES methodology baked into the agent — this doesn't exist anywhere.

---

## 11. Naming & Branding

The product is **numasec**.

```
 ░▒▓███████▓▒░ 
 ░▒▓█  numasec █▓▒░
 ░▒▓███████▓▒░

 AI Penetration Testing Agent
```

- Binary: `numasec`
- Config: `numasec.json` (or `.numasec/`)
- Rules file: `AGENTS.md` (keep numasec-upstream convention)
- npm package: `numasec` (TBD if public)
- Python package: `numasec` (scanner engine, already on PyPI path)

---

## 12. Risk Matrix

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Effect-TS learning curve | HIGH | HIGH | Dedicate time to study; follow existing patterns |
| Bun runtime quirks | MEDIUM | MEDIUM | Pin to stable Bun release; test extensively |
| Python bridge latency | MEDIUM | LOW | JSON-RPC is fast; batch calls when possible |
| opentui/SolidJS terminal rendering bugs | MEDIUM | MEDIUM | Start with minimal TUI changes |
| Upstream breaking changes | LOW | MEDIUM | Cherry-pick policy; never blind merge |
| Scope creep | HIGH | HIGH | Strict phased delivery; ship Phase 1 that works |

---

## 13. Success Criteria

### Phase 1 MVP (ship in 3 weeks)
- [ ] `numasec` binary starts, connects to LLM
- [ ] User can type "scan https://juice-shop:3000" and get results
- [ ] Interactive conversation with course-correction works
- [ ] Findings are persisted and queryable
- [ ] Report generation works (at least Markdown)
- [ ] Undo/redo (inherited from numasec-upstream) works
- [ ] Session resume works

### Phase 2 Full Product (ship in 5 weeks)
- [ ] All 21 security tools operational
- [ ] Subagent delegation (scanner, analyst, reporter) works
- [ ] OWASP Top 10 coverage tracking
- [ ] TUI with findings panel
- [ ] Skills loaded on-demand
- [ ] 96%+ recall on Juice Shop benchmark (matching current MCP mode)

### Phase 3 Market Ready (ship in 8 weeks)
- [ ] Install script (single curl command)
- [ ] Documentation site
- [ ] Desktop app (Tauri)
- [ ] 3+ LLM providers tested (Claude, GPT, Gemini)
- [ ] End-to-end test suite

---

## Appendix A: File-Level Change Map

```
packages/numasec/src/
├── agent/
│   ├── agent.ts                    # MODIFY: add pentest/recon agent defs
│   ├── prompt/                     # REWRITE: all security-focused prompts
│   └── generate.txt                # REWRITE: security generation prompt
├── bridge/                         # NEW: Python IPC bridge
│   ├── python.ts                   # JSON-RPC client
│   ├── setup.ts                    # uv/venv setup
│   └── schema.ts                   # Shared tool schemas
├── session/
│   ├── prompt/                     # REWRITE: pentest system prompts
│   ├── system.ts                   # MODIFY: security system message
│   └── (rest)                      # KEEP
├── tool/
│   ├── bash.ts/txt                 # KEEP
│   ├── read.ts/txt                 # KEEP
│   ├── grep.ts/txt                 # KEEP
│   ├── glob.ts/txt                 # KEEP
│   ├── ls.ts/txt                   # KEEP
│   ├── webfetch.ts/txt             # KEEP
│   ├── websearch.ts/txt            # KEEP
│   ├── question.ts/txt             # KEEP
│   ├── batch.ts/txt                # KEEP
│   ├── task.ts/txt                 # KEEP
│   ├── todo.ts/txt                 # KEEP (progress tracking)
│   ├── skill.ts/txt                # KEEP
│   ├── write.ts/txt                # DELETE
│   ├── edit.ts/txt                 # DELETE
│   ├── multiedit.ts/txt            # DELETE
│   ├── apply_patch.ts/txt          # DELETE
│   ├── codesearch.ts/txt           # DELETE
│   ├── lsp.ts/txt                  # DELETE
│   ├── plan.ts                     # REWRITE → pentest plan
│   ├── recon.ts/txt                # NEW
│   ├── crawl.ts/txt                # NEW
│   ├── injection_test.ts/txt       # NEW
│   ├── xss_test.ts/txt             # NEW
│   ├── ssrf_test.ts/txt            # NEW
│   ├── auth_test.ts/txt            # NEW
│   ├── access_control.ts/txt       # NEW
│   ├── path_test.ts/txt            # NEW
│   ├── dir_fuzz.ts/txt             # NEW
│   ├── js_analyze.ts/txt           # NEW
│   ├── browser_tool.ts/txt         # NEW
│   ├── oob.ts/txt                  # NEW
│   ├── http_request.ts/txt         # NEW
│   ├── save_finding.ts/txt         # NEW
│   ├── get_findings.ts/txt         # NEW
│   ├── generate_report.ts/txt      # NEW
│   ├── kb_search.ts/txt            # NEW
│   ├── create_session.ts/txt       # NEW
│   ├── relay_credentials.ts/txt    # NEW
│   ├── run_batch.ts/txt            # NEW
│   ├── target.ts/txt               # NEW (native TS)
│   ├── coverage.ts/txt             # NEW (native TS)
│   └── registry.ts                 # MODIFY: register new tools
├── security/                       # NEW
│   ├── scope.ts                    # Target scope enforcement
│   └── sanitize.ts                 # Input/output sanitization
├── lsp/                            # DELETE entirely
├── (everything else)               # KEEP as-is
```

## Appendix B: Python Package Structure (Scanner Engine)

The existing numasec Python package remains the scanner engine, refactored slightly to support the worker mode:

```
numasec/
├── worker.py              # NEW: JSON-RPC worker entry point
├── scanners/              # KEEP: all existing scanners
├── knowledge/             # KEEP: 34 YAML templates + BM25 retriever
├── models/                # KEEP: Finding, TargetProfile, etc.
├── standards/             # KEEP: CWE/CVSS/OWASP/ATT&CK mappings
├── reporting/             # KEEP: SARIF/HTML/Markdown generation
├── tools/                 # KEEP: composite tool wrappers
├── core/                  # KEEP: planner, coverage tracker
├── security/              # KEEP: sandbox, rate limiting
├── storage/               # KEEP: SQLite session persistence
└── mcp/                   # KEEP (optional): MCP server mode still works
```

The only addition is `worker.py`. The rest of the Python codebase works exactly as-is. The existing test suite (732 tests) continues to validate the scanner engine independently.
