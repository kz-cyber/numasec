import { expect } from "bun:test"
import { Effect, Layer } from "effect"
import type { SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../../src/security/evidence.sql"
import { EvidenceGraphStore, createEvidenceFingerprint } from "../../src/security/evidence-store"
import { SessionTable } from "../../src/session/session.sql"
import { and, Database, eq } from "../../src/storage/db"
import { testEffect } from "../lib/effect"

const truncate = Layer.effectDiscard(
  Effect.sync(() => {
    const db = Database.Client()
    db.run(/*sql*/ `DELETE FROM evidence_edge`)
    db.run(/*sql*/ `DELETE FROM evidence_node`)
    db.run(/*sql*/ `DELETE FROM evidence_run`)
  }),
)

const it = testEffect(Layer.merge(EvidenceGraphStore.layer, truncate))

function seedSession(sessionID: SessionID) {
  const projectID = ProjectID.make("project-evidence")
  Database.use((db) =>
    db
      .insert(ProjectTable)
      .values({
        id: projectID,
        worktree: "/tmp",
        sandboxes: [],
      })
      .onConflictDoNothing()
      .run(),
  )
  Database.use((db) =>
    db
      .insert(SessionTable)
      .values({
        id: sessionID,
        project_id: projectID,
        slug: "evidence",
        directory: "/tmp",
        title: "evidence-test",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

it.effect("createEvidenceFingerprint is stable across key ordering", () =>
  Effect.sync(() => {
    const first = createEvidenceFingerprint({
      b: 2,
      a: 1,
      list: [{ z: 10, y: 20 }],
    })
    const second = createEvidenceFingerprint({
      a: 1,
      b: 2,
      list: [{ y: 20, z: 10 }],
    })
    expect(first).toBe(second)
  }),
)

it.effect("upsertNode deduplicates by session/type/fingerprint", () =>
  Effect.gen(function* () {
    const sessionID = "sess-evidence-upsert" as SessionID
    seedSession(sessionID)
    const first = yield* EvidenceGraphStore.use((item) =>
      item.upsertNode({
        sessionID,
        type: "observation",
        payload: { method: "GET", url: "https://example.com/a", status: 200 },
        confidence: 0.3,
      }),
    )
    const second = yield* EvidenceGraphStore.use((item) =>
      item.upsertNode({
        sessionID,
        type: "observation",
        payload: { method: "GET", url: "https://example.com/a", status: 200 },
        confidence: 0.9,
      }),
    )

    expect(first.id).toBe(second.id)

    const rows = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.session_id, sessionID))
        .all(),
    )
    expect(rows.length).toBe(1)
    expect(rows[0].confidence).toBe(0.9)
  }),
)

it.effect("upsertEdge deduplicates by session/from/to/relation", () =>
  Effect.gen(function* () {
    const sessionID = "sess-evidence-edge" as SessionID
    seedSession(sessionID)
    const from = yield* EvidenceGraphStore.use((item) =>
      item.upsertNode({
        sessionID,
        type: "hypothesis",
        payload: { id: "h1" },
      }),
    )
    const to = yield* EvidenceGraphStore.use((item) =>
      item.upsertNode({
        sessionID,
        type: "evidence",
        payload: { id: "e1" },
      }),
    )

    const first = yield* EvidenceGraphStore.use((item) =>
      item.upsertEdge({
        sessionID,
        fromNodeID: from.id,
        toNodeID: to.id,
        relation: "supports",
        weight: 1,
        metadata: { source: "pass-1" },
      }),
    )
    const second = yield* EvidenceGraphStore.use((item) =>
      item.upsertEdge({
        sessionID,
        fromNodeID: from.id,
        toNodeID: to.id,
        relation: "supports",
        weight: 2,
        metadata: { source: "pass-2" },
      }),
    )

    expect(first.id).toBe(second.id)

    const rows = Database.use((db) =>
      db
        .select()
        .from(EvidenceEdgeTable)
        .where(eq(EvidenceEdgeTable.session_id, sessionID))
        .all(),
    )
    expect(rows.length).toBe(1)
    expect(rows[0].weight).toBe(2)
  }),
)

it.effect("supersedeNode creates supersedes edge and marks prior node superseded", () =>
  Effect.gen(function* () {
    const sessionID = "sess-evidence-supersede" as SessionID
    seedSession(sessionID)
    const oldNode = yield* EvidenceGraphStore.use((item) =>
      item.upsertNode({
        sessionID,
        type: "finding",
        payload: { id: "finding-old" },
      }),
    )
    const newNode = yield* EvidenceGraphStore.use((item) =>
      item.upsertNode({
        sessionID,
        type: "finding",
        payload: { id: "finding-new" },
      }),
    )

    const edge = yield* EvidenceGraphStore.use((item) =>
      item.supersedeNode({
        sessionID,
        supersededNodeID: oldNode.id,
        supersedingNodeID: newNode.id,
        reason: "new evidence invalidates prior assertion",
      }),
    )

    expect(edge.relation).toBe("supersedes")

    const oldRow = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(and(eq(EvidenceNodeTable.session_id, sessionID), eq(EvidenceNodeTable.id, oldNode.id)))
        .get(),
    )
    expect(oldRow).toBeDefined()
    expect(oldRow?.status).toBe("superseded")
    expect(oldRow?.invalidation_reason).toBe("new evidence invalidates prior assertion")

    const edgeRow = Database.use((db) =>
      db
        .select()
        .from(EvidenceEdgeTable)
        .where(
          and(
            eq(EvidenceEdgeTable.session_id, sessionID),
            eq(EvidenceEdgeTable.from_node_id, newNode.id),
            eq(EvidenceEdgeTable.to_node_id, oldNode.id),
            eq(EvidenceEdgeTable.relation, "supersedes"),
          ),
        )
        .get(),
    )
    expect(edgeRow).toBeDefined()
  }),
)
