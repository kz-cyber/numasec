import { describeRoute, resolver, validator } from "hono-openapi"
import { Hono } from "hono"
import z from "zod"
import { Flag } from "../../flag/flag"
import { and, Database, eq } from "../../storage/db"
import { TargetTable, FindingTable, CoverageTable } from "../../security/security.sql"
import { EvidenceNodeTable, EvidenceEdgeTable } from "../../security/evidence.sql"
import { SessionID } from "../../session/schema"
import { lazy } from "../../util/lazy"

type TargetRow = (typeof TargetTable)["$inferSelect"]
type FindingRow = (typeof FindingTable)["$inferSelect"]
type CoverageRow = (typeof CoverageTable)["$inferSelect"]
type EvidenceNodeRow = (typeof EvidenceNodeTable)["$inferSelect"]
type EvidenceEdgeRow = (typeof EvidenceEdgeTable)["$inferSelect"]

type SyncCursor = {
  id: string
  time_updated: number
}

type SyncRow = {
  id: string
  time_updated: number
}

type SyncQueryValue = {
  limit?: number
  cursor?: string
  since?: number
}

type ChainSyncRow = {
  id: string
  chain_id: string
  severity: string
  finding_count: number
  finding_ids: string[]
  urls: string[]
  time_created: number
  time_updated: number
}

const DEFAULT_SYNC_LIMIT = 100

function parseCursor(value: string): SyncCursor | undefined {
  const split = value.indexOf(":")
  if (split < 1) return
  const left = value.slice(0, split)
  const right = value.slice(split + 1)
  if (!right) return
  const time = Number(left)
  if (!Number.isInteger(time)) return
  return {
    id: right,
    time_updated: time,
  }
}

function encodeCursor(value: SyncCursor) {
  return `${value.time_updated}:${value.id}`
}

function cursorAfter(item: SyncRow, cursor: SyncCursor) {
  if (item.time_updated > cursor.time_updated) return true
  if (item.time_updated < cursor.time_updated) return false
  return item.id > cursor.id
}

function emptySync(query: SyncQueryValue) {
  return {
    limit: query.limit ?? DEFAULT_SYNC_LIMIT,
    cursor: query.cursor ?? null,
    since: query.since ?? null,
    next_cursor: null,
    has_more: false,
  }
}

function syncPage<T extends SyncRow>(rows: T[], query: SyncQueryValue) {
  const limit = query.limit ?? DEFAULT_SYNC_LIMIT
  const sorted = rows.toSorted((a, b) => {
    if (a.time_updated === b.time_updated) return a.id.localeCompare(b.id)
    return a.time_updated - b.time_updated
  })
  const cursor = query.cursor ? parseCursor(query.cursor) : undefined
  const filtered: T[] = []
  for (const item of sorted) {
    if (query.since !== undefined && item.time_updated < query.since) continue
    if (cursor && !cursorAfter(item, cursor)) continue
    filtered.push(item)
  }
  const hasMore = filtered.length > limit
  const items = hasMore ? filtered.slice(0, limit) : filtered
  let next: string | null = null
  if (items.length > 0) {
    const item = items[items.length - 1]
    next = encodeCursor({
      id: item.id,
      time_updated: item.time_updated,
    })
  }
  return {
    items,
    sync: {
      limit,
      cursor: query.cursor ?? null,
      since: query.since ?? null,
      next_cursor: next,
      has_more: hasMore,
    },
  }
}

function setNextCursor(c: { header: (name: string, value: string) => unknown }, value: string | null) {
  if (!value) return
  c.header("Access-Control-Expose-Headers", "X-Next-Cursor")
  c.header("X-Next-Cursor", value)
}

function chainSeverity(rows: FindingRow[]) {
  const rank: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  }
  let value = "info"
  for (const item of rows) {
    const current = rank[value] ?? 100
    const next = rank[item.severity] ?? 100
    if (next < current) value = item.severity
  }
  return value
}

function chainGroups(rows: FindingRow[]) {
  const value = new Map<string, FindingRow[]>()
  for (const item of rows) {
    if (!item.chain_id) continue
    const list = value.get(item.chain_id)
    if (list) {
      list.push(item)
      continue
    }
    value.set(item.chain_id, [item])
  }
  return value
}

function buildChains(rows: FindingRow[]) {
  const groups = chainGroups(rows)
  const value: Array<{
    chain_id: string
    severity: string
    finding_count: number
    finding_ids: string[]
    urls: string[]
  }> = []
  for (const entry of groups.entries()) {
    const chainID = entry[0]
    const list = entry[1]
    const urls = new Set<string>()
    const ids: string[] = []
    for (const item of list) {
      ids.push(item.id)
      if (item.url) urls.add(item.url)
    }
    value.push({
      chain_id: chainID,
      severity: chainSeverity(list),
      finding_count: list.length,
      finding_ids: ids,
      urls: Array.from(urls),
    })
  }
  return value
}

function buildChainSyncRows(rows: FindingRow[]) {
  const groups = chainGroups(rows)
  const value: ChainSyncRow[] = []
  for (const entry of groups.entries()) {
    const chainID = entry[0]
    const list = entry[1]
    const urls = new Set<string>()
    const ids: string[] = []
    let created = 0
    let updated = 0
    let first = true
    for (const item of list) {
      ids.push(item.id)
      if (item.url) urls.add(item.url)
      if (first) {
        created = item.time_created
        updated = item.time_updated
        first = false
        continue
      }
      if (item.time_created < created) created = item.time_created
      if (item.time_updated > updated) updated = item.time_updated
    }
    value.push({
      id: chainID,
      chain_id: chainID,
      severity: chainSeverity(list),
      finding_count: list.length,
      finding_ids: ids,
      urls: Array.from(urls),
      time_created: created,
      time_updated: updated,
    })
  }
  return value.toSorted((a, b) => {
    if (a.time_updated === b.time_updated) return a.id.localeCompare(b.id)
    return a.time_updated - b.time_updated
  })
}

function readScope(rows: TargetRow[]) {
  const value = new Set<string>()
  for (const item of rows) {
    if (item.url) value.add(item.url)
    if (!item.scope) continue
    for (const part of item.scope) {
      if (!part) continue
      value.add(part)
    }
  }
  return Array.from(value)
}

function latestUpdated<T extends { time_updated: number }>(rows: T[]) {
  if (rows.length === 0) return null
  let value = rows[0].time_updated
  for (const item of rows) {
    if (item.time_updated > value) value = item.time_updated
  }
  return value
}

function changed(latest: number | null, since: number | undefined) {
  if (since === undefined) return false
  if (latest === null) return false
  return latest >= since
}

function readState(sessionID: z.infer<typeof SessionID.zod>, graphEnabled: boolean) {
  const targets = Database.use((db) =>
    db
      .select()
      .from(TargetTable)
      .where(eq(TargetTable.session_id, sessionID))
      .all(),
  )
  const findings = Database.use((db) =>
    db
      .select()
      .from(FindingTable)
      .where(eq(FindingTable.session_id, sessionID))
      .all(),
  )
  const coverage = Database.use((db) =>
    db
      .select()
      .from(CoverageTable)
      .where(eq(CoverageTable.session_id, sessionID))
      .all(),
  )
  const nodes = graphEnabled
    ? Database.use((db) =>
        db
          .select()
          .from(EvidenceNodeTable)
          .where(eq(EvidenceNodeTable.session_id, sessionID))
          .all(),
      )
    : []
  const edges = graphEnabled
    ? Database.use((db) =>
        db
          .select()
          .from(EvidenceEdgeTable)
          .where(eq(EvidenceEdgeTable.session_id, sessionID))
          .all(),
      )
    : []
  const hypotheses = graphEnabled ? nodes.filter((item) => item.type === "hypothesis") : []
  const scope = readScope(targets)
  const chains = buildChains(findings)
  const chainRows = buildChainSyncRows(findings)
  return {
    targets,
    findings,
    coverage,
    nodes,
    edges,
    hypotheses,
    scope,
    chains,
    chainRows,
  }
}

const SyncMetaSchema = z.object({
  limit: z.number(),
  cursor: z.string().nullable(),
  since: z.number().nullable(),
  next_cursor: z.string().nullable(),
  has_more: z.boolean(),
})

const SyncItemSchema = z
  .object({
    id: z.string(),
    time_updated: z.number(),
  })
  .passthrough()

const SyncQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
  since: z.coerce.number().int().min(0).optional(),
  cursor: z
    .string()
    .optional()
    .refine(
      (value) => {
        if (!value) return true
        return parseCursor(value) !== undefined
      },
      { message: "Invalid cursor" },
    ),
})

const FindingsSyncQuerySchema = SyncQuerySchema.extend({
  severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
})

const ChainSyncSchema = z.object({
  chain_id: z.string(),
  severity: z.string(),
  finding_count: z.number(),
  finding_ids: z.string().array(),
  urls: z.string().array(),
  time_created: z.number(),
  time_updated: z.number(),
})

const SummaryCounterSchema = z.object({
  count: z.number(),
  latest_time_updated: z.number().nullable(),
  changed: z.boolean(),
})

const SummaryEvidenceSchema = SummaryCounterSchema.extend({
  enabled: z.boolean(),
})

const ReadSummarySchema = z.object({
  session_id: SessionID.zod,
  graph_enabled: z.boolean(),
  generated_at: z.number(),
  summary: z.object({
    scope_count: z.number(),
    hypothesis_count: z.number(),
    evidence_node_count: z.number(),
    evidence_edge_count: z.number(),
    finding_count: z.number(),
    chain_count: z.number(),
    coverage_count: z.number(),
  }),
  checkpoints: z.object({
    scope: SummaryCounterSchema,
    hypotheses: SummaryCounterSchema,
    findings: SummaryCounterSchema,
    chains: SummaryCounterSchema,
    coverage: SummaryCounterSchema,
    evidence_nodes: SummaryEvidenceSchema,
    evidence_edges: SummaryEvidenceSchema,
  }),
  sync: z.object({
    since: z.number().nullable(),
  }),
})

export const SecurityRoutes = lazy(() =>
  new Hono()
    .get(
      "/:sessionID/read",
      describeRoute({
        summary: "Read canonical security state",
        description:
          "Returns canonical security read model with scope, hypotheses, evidence, findings, chains, and coverage.",
        operationId: "security.read",
        responses: {
          200: {
            description: "Canonical security state",
            content: {
              "application/json": {
                schema: resolver(z.any()),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const graphEnabled = Flag.NUMASEC_SECURITY_GRAPH_READ
        const state = readState(sessionID, graphEnabled)

        return c.json({
          session_id: sessionID,
          graph_enabled: graphEnabled,
          scope: state.scope,
          hypotheses: state.hypotheses,
          evidence: {
            nodes: state.nodes,
            edges: state.edges,
          },
          findings: state.findings,
          chains: state.chains,
          coverage: state.coverage,
          summary: {
            scope_count: state.scope.length,
            hypothesis_count: state.hypotheses.length,
            evidence_node_count: state.nodes.length,
            evidence_edge_count: state.edges.length,
            finding_count: state.findings.length,
            chain_count: state.chains.length,
            coverage_count: state.coverage.length,
          },
        })
      },
    )
    .get(
      "/:sessionID/read/summary",
      describeRoute({
        summary: "Read security sync summary",
        description:
          "Returns canonical security summary with projection checkpoints for polling and incremental sync loops.",
        operationId: "security.read.summary",
        responses: {
          200: {
            description: "Security sync summary",
            content: {
              "application/json": {
                schema: resolver(ReadSummarySchema),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      validator(
        "query",
        z.object({
          since: z.coerce.number().int().min(0).optional(),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const query = c.req.valid("query")
        const graphEnabled = Flag.NUMASEC_SECURITY_GRAPH_READ
        const state = readState(sessionID, graphEnabled)
        const scopeUpdated = latestUpdated(state.targets)
        const hypothesisUpdated = latestUpdated(state.hypotheses)
        const findingUpdated = latestUpdated(state.findings)
        const chainUpdated = latestUpdated(state.chainRows)
        const coverageUpdated = latestUpdated(state.coverage)
        const nodeUpdated = latestUpdated(state.nodes)
        const edgeUpdated = latestUpdated(state.edges)
        return c.json({
          session_id: sessionID,
          graph_enabled: graphEnabled,
          generated_at: Date.now(),
          summary: {
            scope_count: state.scope.length,
            hypothesis_count: state.hypotheses.length,
            evidence_node_count: state.nodes.length,
            evidence_edge_count: state.edges.length,
            finding_count: state.findings.length,
            chain_count: state.chains.length,
            coverage_count: state.coverage.length,
          },
          checkpoints: {
            scope: {
              count: state.scope.length,
              latest_time_updated: scopeUpdated,
              changed: changed(scopeUpdated, query.since),
            },
            hypotheses: {
              count: state.hypotheses.length,
              latest_time_updated: hypothesisUpdated,
              changed: changed(hypothesisUpdated, query.since),
            },
            findings: {
              count: state.findings.length,
              latest_time_updated: findingUpdated,
              changed: changed(findingUpdated, query.since),
            },
            chains: {
              count: state.chains.length,
              latest_time_updated: chainUpdated,
              changed: changed(chainUpdated, query.since),
            },
            coverage: {
              count: state.coverage.length,
              latest_time_updated: coverageUpdated,
              changed: changed(coverageUpdated, query.since),
            },
            evidence_nodes: {
              enabled: graphEnabled,
              count: state.nodes.length,
              latest_time_updated: nodeUpdated,
              changed: changed(nodeUpdated, query.since),
            },
            evidence_edges: {
              enabled: graphEnabled,
              count: state.edges.length,
              latest_time_updated: edgeUpdated,
              changed: changed(edgeUpdated, query.since),
            },
          },
          sync: {
            since: query.since ?? null,
          },
        })
      },
    )
    .get(
      "/:sessionID/findings",
      describeRoute({
        summary: "Read findings projection",
        description: "Returns findings projection for a session.",
        operationId: "security.findings",
        responses: {
          200: {
            description: "Findings projection",
            content: {
              "application/json": {
                schema: resolver(z.any()),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      validator(
        "query",
        z.object({
          severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
          limit: z.coerce.number().min(1).max(500).optional(),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const query = c.req.valid("query")
        const conditions = [eq(FindingTable.session_id, sessionID)]
        if (query.severity) conditions.push(eq(FindingTable.severity, query.severity))
        const rows = Database.use((db) => {
          const where = conditions.length === 1 ? conditions[0] : and(...conditions)
          const list = db
            .select()
            .from(FindingTable)
            .where(where)
            .orderBy(FindingTable.time_created)
          if (query.limit) return list.limit(query.limit).all()
          return list.all()
        })
        return c.json(rows)
      },
    )
    .get(
      "/:sessionID/findings/sync",
      describeRoute({
        summary: "Read findings sync projection",
        description: "Returns findings with cursor and since support for incremental synchronization.",
        operationId: "security.findings.sync",
        responses: {
          200: {
            description: "Findings sync projection",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    items: SyncItemSchema.array(),
                    sync: SyncMetaSchema,
                  }),
                ),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      validator("query", FindingsSyncQuerySchema),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const query = c.req.valid("query")
        const conditions = [eq(FindingTable.session_id, sessionID)]
        if (query.severity) conditions.push(eq(FindingTable.severity, query.severity))
        const rows = Database.use((db) => {
          const where = conditions.length === 1 ? conditions[0] : and(...conditions)
          return db
            .select()
            .from(FindingTable)
            .where(where)
            .all()
        })
        const page = syncPage(rows, query)
        setNextCursor(c, page.sync.next_cursor)
        return c.json(page)
      },
    )
    .get(
      "/:sessionID/chains",
      describeRoute({
        summary: "Read attack chain projection",
        description: "Returns attack chain projection derived from findings.",
        operationId: "security.chains",
        responses: {
          200: {
            description: "Attack chain projection",
            content: {
              "application/json": {
                schema: resolver(z.any()),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const findings = Database.use((db) =>
          db
            .select()
            .from(FindingTable)
            .where(eq(FindingTable.session_id, sessionID))
            .all(),
        )
        return c.json(buildChains(findings))
      },
    )
    .get(
      "/:sessionID/chains/sync",
      describeRoute({
        summary: "Read attack chain sync projection",
        description: "Returns derived chains with cursor and since support for incremental synchronization.",
        operationId: "security.chains.sync",
        responses: {
          200: {
            description: "Attack chain sync projection",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    items: ChainSyncSchema.array(),
                    sync: SyncMetaSchema,
                  }),
                ),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      validator("query", SyncQuerySchema),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const query = c.req.valid("query")
        const findings = Database.use((db) =>
          db
            .select()
            .from(FindingTable)
            .where(eq(FindingTable.session_id, sessionID))
            .all(),
        )
        const rows = buildChainSyncRows(findings)
        const page = syncPage(rows, query)
        const items: Array<{
          chain_id: string
          severity: string
          finding_count: number
          finding_ids: string[]
          urls: string[]
          time_created: number
          time_updated: number
        }> = []
        for (const item of page.items) {
          items.push({
            chain_id: item.chain_id,
            severity: item.severity,
            finding_count: item.finding_count,
            finding_ids: item.finding_ids,
            urls: item.urls,
            time_created: item.time_created,
            time_updated: item.time_updated,
          })
        }
        setNextCursor(c, page.sync.next_cursor)
        return c.json({
          items,
          sync: page.sync,
        })
      },
    )
    .get(
      "/:sessionID/evidence/nodes",
      describeRoute({
        summary: "Read evidence nodes",
        description: "Returns evidence graph nodes for a session when graph read is enabled.",
        operationId: "security.evidence.nodes",
        responses: {
          200: {
            description: "Evidence nodes",
            content: {
              "application/json": {
                schema: resolver(z.any()),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        if (!Flag.NUMASEC_SECURITY_GRAPH_READ) {
          return c.json({
            enabled: false,
            items: [],
          })
        }
        const rows = Database.use((db) =>
          db
            .select()
            .from(EvidenceNodeTable)
            .where(eq(EvidenceNodeTable.session_id, sessionID))
            .all(),
        )
        return c.json({
          enabled: true,
          items: rows,
        })
      },
    )
    .get(
      "/:sessionID/evidence/nodes/sync",
      describeRoute({
        summary: "Read evidence node sync projection",
        description: "Returns evidence nodes with cursor and since support for incremental synchronization.",
        operationId: "security.evidence.nodes.sync",
        responses: {
          200: {
            description: "Evidence node sync projection",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    enabled: z.boolean(),
                    items: SyncItemSchema.array(),
                    sync: SyncMetaSchema,
                  }),
                ),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      validator("query", SyncQuerySchema),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const query = c.req.valid("query")
        if (!Flag.NUMASEC_SECURITY_GRAPH_READ) {
          return c.json({
            enabled: false,
            items: [],
            sync: emptySync(query),
          })
        }
        const rows = Database.use((db) =>
          db
            .select()
            .from(EvidenceNodeTable)
            .where(eq(EvidenceNodeTable.session_id, sessionID))
            .all(),
        )
        const page = syncPage(rows, query)
        setNextCursor(c, page.sync.next_cursor)
        return c.json({
          enabled: true,
          items: page.items,
          sync: page.sync,
        })
      },
    )
    .get(
      "/:sessionID/evidence/edges",
      describeRoute({
        summary: "Read evidence edges",
        description: "Returns evidence graph edges for a session when graph read is enabled.",
        operationId: "security.evidence.edges",
        responses: {
          200: {
            description: "Evidence edges",
            content: {
              "application/json": {
                schema: resolver(z.any()),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        if (!Flag.NUMASEC_SECURITY_GRAPH_READ) {
          return c.json({
            enabled: false,
            items: [],
          })
        }
        const rows = Database.use((db) =>
          db
            .select()
            .from(EvidenceEdgeTable)
            .where(eq(EvidenceEdgeTable.session_id, sessionID))
            .all(),
        )
        return c.json({
          enabled: true,
          items: rows,
        })
      },
    )
    .get(
      "/:sessionID/evidence/edges/sync",
      describeRoute({
        summary: "Read evidence edge sync projection",
        description: "Returns evidence edges with cursor and since support for incremental synchronization.",
        operationId: "security.evidence.edges.sync",
        responses: {
          200: {
            description: "Evidence edge sync projection",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    enabled: z.boolean(),
                    items: SyncItemSchema.array(),
                    sync: SyncMetaSchema,
                  }),
                ),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionID.zod,
        }),
      ),
      validator("query", SyncQuerySchema),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const query = c.req.valid("query")
        if (!Flag.NUMASEC_SECURITY_GRAPH_READ) {
          return c.json({
            enabled: false,
            items: [],
            sync: emptySync(query),
          })
        }
        const rows = Database.use((db) =>
          db
            .select()
            .from(EvidenceEdgeTable)
            .where(eq(EvidenceEdgeTable.session_id, sessionID))
            .all(),
        )
        const page = syncPage(rows, query)
        setNextCursor(c, page.sync.next_cursor)
        return c.json({
          enabled: true,
          items: page.items,
          sync: page.sync,
        })
      },
    ),
)
