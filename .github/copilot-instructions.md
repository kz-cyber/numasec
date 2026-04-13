# numasec — Copilot Instructions

## What this project is

**numasec** is an AI-powered penetration testing platform. It is a single TypeScript binary — no Python, no runtime dependencies. The LLM agent calls 21 native TypeScript security tools to run real pentests against targets.

All code lives in `agent/` (Bun/TypeScript monorepo).

## Build, test, lint

```bash
# Install deps (run from agent/)
cd agent && bun install

# Build binary
cd agent/packages/numasec && bun run build

# Type check (run from agent/ — uses turbo across all packages)
cd agent && bun typecheck

# Run full test suite — MUST run from packages/numasec, not root
cd agent/packages/numasec && bun test --timeout 30000

# Run a single test file
cd agent/packages/numasec && bun test --timeout 30000 test/storage/storage.test.ts

# Run tests matching a pattern
cd agent/packages/numasec && bun test --timeout 30000 --test-name-pattern "finding"
```

⚠️ `bun test` at the repo root or `agent/` root exits with code 1 by design.

## Architecture

The main package is `agent/packages/numasec`. Key subdirectories under `src/`:

```
src/
  security/           # All 21 security tools + supporting modules
    tool/             # One file per tool (e.g. recon.ts, injection-test.ts)
    enrichment/       # Finding enrichment: CWE → CVSS → OWASP → MITRE ATT&CK
    planner/          # DeterministicPlanner (PTES 5-phase, no LLM)
    kb/               # BM25 knowledge base retriever + 35 YAML attack templates
    chain-builder.ts  # Groups findings into attack chains by URL clustering
    report/           # SARIF 2.1.0, HTML, Markdown report generators
  agent/
    agent.ts          # All agent definitions (primary, sub, utility)
    prompt/*.txt      # System prompts per agent
  tool/               # Framework-level tool definitions (Tool.define())
  provider/           # 16+ LLM provider integrations (Anthropic, OpenAI, etc.)
  command/            # Slash commands (/scope set, /finding list, /report generate + legacy aliases)
  storage/            # SQLite via Drizzle ORM, WAL mode
  session/            # Session lifecycle
  cli/cmd/tui/        # Terminal UI (SolidJS + @opentui)
    app.tsx           # Root component
    routes/session/   # Main chat interface
      index.tsx       # Message display
      sidebar.tsx     # Findings panel, attack chains, OWASP matrix
```

### Data flow

The agent calls security tools → tools run HTTP/shell operations → evidence/finding graph is updated in SQLite → `derive_attack_paths` groups findings into chains → `generate_report` produces output.

Session lifecycle (v2): `create_session` → `observe_surface`/`record_evidence`/`upsert_finding` × N → `derive_attack_paths` → `generate_report` (legacy `save_finding`/`build_chains` still supported)

### Tool registration pattern

Every security tool is defined with `Tool.define()` and registered in `src/tool/`:

```typescript
export const MyTool = Tool.define({
  name: "my_tool",
  description: "...",
  parameters: z.object({ ... }),
  execute: async (params) => { ... }
})
```

New tools must be exported from `src/security/index.ts`.

### Finding model

- **ID**: `SSEC-{SHA256(method:url:parameter:title)[:12].upper()}` — deterministic, dedup-friendly
- **Auto-generated fields** (never set manually): `id`, `cvss_score`, `cvss_vector`, `owasp_category`, `timestamp`
- **Enrichment pipeline**: CWE → CVSS 3.1 base score → OWASP Top 10 category → MITRE ATT&CK tactic
- **Chain fields**: `chain_id` (set by `build_chains`), `related_finding_ids`

### Planner

PTES 5-phase deterministic methodology — no internal LLM calls:
1. Recon → 2. Service Mapping → 3. Vulnerability Testing → 4. Exploitation Validation → 5. Reporting

Replan signals: `waf_detected`, `auth_obtained`, `escalation_found`, `spa_detected`, `api_app_detected`
Scope timeouts: quick=3min, standard=10min, deep=30min

### Agent modes

**5 primary** (user-selectable): `pentest` (default, full PTES), `recon` (no exploitation), `hunt` (OWASP Top 10 sweep), `review` (source code only), `report` (deliverables)

**4 subagents**: `scanner`, `analyst`, `reporter`, `explore`

**3 utility** (hidden): `compaction`, `title`, `summary`

Each agent has: system prompt in `src/agent/prompt/*.txt`, permission model, temperature, tool restrictions.

### Database

Drizzle ORM with SQLite (WAL mode). Schema files are `src/**/*.sql.ts`. Columns use `snake_case`.

Generate migrations:
```bash
cd agent/packages/numasec && bun run db generate --name <slug>
# outputs: migration/<timestamp>_<slug>/migration.sql
```

## Key conventions

### TypeScript style (enforced in AGENTS.md)

- **Single-word variable names** by default. Multi-word only when a single word would be ambiguous. This is mandatory.
- **No `else` statements** — use early returns instead
- **No destructuring** — use dot notation (`obj.a` not `const { a } = obj`)
- **`const` over `let`** — use ternaries or early returns to avoid reassignment
- **Inline single-use values** — don't introduce a variable if it's only used once
- **Avoid `try`/`catch`** where possible
- **Bun APIs** — use `Bun.file()`, `Bun.write()` etc. instead of Node fs equivalents

### Effect-TS patterns

- `Effect.gen(function* () { ... })` for composition
- `Effect.fn("Domain.method")` for named/traced effects; `Effect.fnUntraced` for internal helpers
- `Schema.Class` for multi-field data; `Schema.brand` for single-value types
- `Schema.TaggedErrorClass` for typed errors
- `makeRuntime` (from `src/effect/run-service.ts`) for all services — uses shared `memoMap`
- `InstanceState` (from `src/effect/instance-state.ts`) for per-directory state needing cleanup
- Prefer Effect services: `FileSystem.FileSystem` over raw fs, `HttpClient.HttpClient` over fetch
- `Effect.cached` when multiple concurrent callers should share one in-flight computation

### SolidJS UI

- Prefer `createStore` over multiple `createSignal` calls

### Drizzle schema

Use `snake_case` for field names so column names don't need to be redefined as strings:

```typescript
// Good
const table = sqliteTable("session", { project_id: text().notNull() })
// Bad
const table = sqliteTable("session", { projectID: text("project_id").notNull() })
```

### Testing

- Use `tmpdir` fixture (`test/fixture/fixture.ts`) for tests that need temp directories — supports `await using` for automatic cleanup
- Avoid mocks; test actual implementations
- Tests cannot run from repo root or `agent/` — always `cd agent/packages/numasec` first

## Common pitfalls

1. **Test directory**: Running `bun test` from repo root or `agent/` root intentionally fails. Always `cd agent/packages/numasec`.
2. **Typecheck from `agent/`**: Run `bun typecheck` from `agent/`, not a package subdirectory.
3. **DB migrations**: Always generate via `bun run db generate` — never write migration SQL manually.
4. **Finding auto-fields**: Don't set `id`, `cvss_score`, `owasp_category` on a Finding — they're auto-generated by the enrichment pipeline.
5. **New tools**: Must be exported from `src/security/index.ts` to be registered.
