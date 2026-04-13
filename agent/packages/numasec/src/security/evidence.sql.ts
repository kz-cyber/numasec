import { sqliteTable, text, real, integer, index, uniqueIndex } from "drizzle-orm/sqlite-core"
import { SessionTable } from "../session/session.sql"
import type { SessionID } from "../session/schema"
import { Timestamps } from "../storage/schema.sql"

export type EvidenceNodeID = string & { __brand: "EvidenceNodeID" }
export type EvidenceEdgeID = string & { __brand: "EvidenceEdgeID" }
export type EvidenceRunID = string & { __brand: "EvidenceRunID" }

export const EvidenceNodeTable = sqliteTable(
  "evidence_node",
  {
    id: text().$type<EvidenceNodeID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    type: text().notNull(),
    fingerprint: text().notNull(),
    status: text().notNull().default("active"),
    confidence: real().notNull().default(0.5),
    payload: text({ mode: "json" }).$type<Record<string, any>>().notNull().default({}),
    source_tool: text().notNull().default(""),
    invalidated_at: integer(),
    invalidation_reason: text().notNull().default(""),
    ...Timestamps,
  },
  (table) => [
    index("evidence_node_session_idx").on(table.session_id),
    index("evidence_node_type_idx").on(table.type),
    uniqueIndex("evidence_node_session_type_fp_uidx").on(table.session_id, table.type, table.fingerprint),
  ],
)

export const EvidenceEdgeTable = sqliteTable(
  "evidence_edge",
  {
    id: text().$type<EvidenceEdgeID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    from_node_id: text()
      .$type<EvidenceNodeID>()
      .notNull()
      .references(() => EvidenceNodeTable.id, { onDelete: "cascade" }),
    to_node_id: text()
      .$type<EvidenceNodeID>()
      .notNull()
      .references(() => EvidenceNodeTable.id, { onDelete: "cascade" }),
    relation: text().notNull(),
    weight: real().notNull().default(1),
    metadata: text({ mode: "json" }).$type<Record<string, any>>().notNull().default({}),
    ...Timestamps,
  },
  (table) => [
    index("evidence_edge_session_idx").on(table.session_id),
    index("evidence_edge_from_idx").on(table.from_node_id),
    index("evidence_edge_to_idx").on(table.to_node_id),
    uniqueIndex("evidence_edge_unique_uidx").on(table.session_id, table.from_node_id, table.to_node_id, table.relation),
  ],
)

export const EvidenceRunTable = sqliteTable(
  "evidence_run",
  {
    id: text().$type<EvidenceRunID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    planner_state: text().notNull().default(""),
    hypothesis_id: text().notNull().default(""),
    status: text().notNull().default(""),
    attempts: integer().notNull().default(0),
    notes: text({ mode: "json" }).$type<Record<string, any>>().notNull().default({}),
    ...Timestamps,
  },
  (table) => [index("evidence_run_session_idx").on(table.session_id)],
)

