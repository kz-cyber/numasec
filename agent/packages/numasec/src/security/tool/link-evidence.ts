import z from "zod"
import { Effect } from "effect"
import { Tool } from "../../tool/tool"
import { EvidenceGraphStore } from "../evidence-store"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Link two evidence nodes with a typed relation.
This primitive is used to encode support/refute/derived-from/supersedes graph edges.`

export const LinkEvidenceTool = Tool.define("link_evidence", {
  description: DESCRIPTION,
  parameters: z.object({
    from_node_id: z.string().describe("Source evidence node id"),
    to_node_id: z.string().describe("Destination evidence node id"),
    relation: z.string().describe("Edge relation (supports, refutes, derives, supersedes, etc.)"),
    weight: z.number().optional().describe("Relation weight, default 1"),
    metadata: z.record(z.string(), z.any()).optional().describe("Optional edge metadata"),
  }),
  async execute(params, ctx) {
    const row = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertEdge({
          sessionID: ctx.sessionID,
          fromNodeID: params.from_node_id,
          toNodeID: params.to_node_id,
          relation: params.relation,
          weight: params.weight,
          metadata: params.metadata,
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    return {
      title: `Evidence link: ${row.relation}`,
      metadata: {
        id: row.id,
        from: row.from_node_id,
        to: row.to_node_id,
        relation: row.relation,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
          {
            type: "evidence_edge",
            edge_id: row.id,
            relation: row.relation,
            from_node_id: row.from_node_id,
            to_node_id: row.to_node_id,
          },
        ],
      }),
      output: [
        `Edge ID: ${row.id}`,
        `From: ${row.from_node_id}`,
        `To: ${row.to_node_id}`,
        `Relation: ${row.relation}`,
        `Weight: ${row.weight}`,
      ].join("\n"),
    }
  },
})
