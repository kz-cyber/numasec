import z from "zod"
import { desc, eq } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../evidence.sql"
import { UpsertFindingTool } from "./upsert-finding"

function readPayload(input: unknown): Record<string, unknown> {
  if (typeof input === "object" && input !== null && !Array.isArray(input)) {
    return input as Record<string, unknown>
  }
  return {}
}

function verificationPassed(row: (typeof EvidenceNodeTable)["$inferSelect"]): boolean {
  const payload = readPayload(row.payload)
  if (typeof payload.passed === "boolean") return payload.passed
  return row.status === "confirmed"
}

function verificationControl(row: (typeof EvidenceNodeTable)["$inferSelect"]): string {
  const payload = readPayload(row.payload)
  if (typeof payload.control === "string") return payload.control
  return "neutral"
}

const DESCRIPTION = `Confirm a finding in one shot from recent evidence.
Auto-selects verification/control/impact evidence when not explicitly provided, then delegates to upsert_finding.`

export const ConfirmFindingTool = Tool.define("confirm_finding", {
  description: DESCRIPTION,
  parameters: z.object({
    hypothesis_id: z.string().describe("Hypothesis node id"),
    title: z.string().describe("Finding title"),
    severity: z.string().describe("Finding severity"),
    impact: z.string().describe("Business or technical impact"),
    evidence_refs: z.array(z.string()).optional().describe("Optional evidence refs; auto-suggested when omitted"),
    negative_control_refs: z.array(z.string()).optional().describe("Optional negative control refs; auto-suggested when omitted"),
    impact_refs: z.array(z.string()).optional().describe("Optional impact refs; auto-suggested when omitted"),
    lookback_limit: z.number().int().min(20).max(500).optional().describe("Recent evidence window for auto-suggestions"),
    confidence: z.number().min(0).max(1).optional(),
    status: z.string().optional(),
    strict_assertion: z.boolean().optional(),
    url: z.string().optional(),
    method: z.string().optional(),
    parameter: z.string().optional(),
    payload: z.string().optional(),
    tool_used: z.string().optional(),
    remediation: z.string().optional(),
    taxonomy_tags: z.array(z.string()).optional(),
  }),
  async execute(params, ctx) {
    const rows = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.session_id, ctx.sessionID))
        .orderBy(desc(EvidenceNodeTable.time_updated))
        .all(),
    )
    const edges = Database.use((db) =>
      db
        .select()
        .from(EvidenceEdgeTable)
        .where(eq(EvidenceEdgeTable.session_id, ctx.sessionID))
        .all(),
    )

    const known = new Set<string>([params.hypothesis_id])
    const queue: Array<{ id: string; depth: number }> = [{ id: params.hypothesis_id, depth: 0 }]
    while (queue.length > 0) {
      const item = queue.shift()
      if (!item) continue
      if (item.depth >= 2) continue
      for (const edge of edges) {
        if (edge.from_node_id !== item.id && edge.to_node_id !== item.id) continue
        const next = edge.from_node_id === item.id ? edge.to_node_id : edge.from_node_id
        if (known.has(next)) continue
        known.add(next)
        queue.push({
          id: next,
          depth: item.depth + 1,
        })
      }
    }
    const recent = rows.filter((row) => row.status === "confirmed").slice(0, params.lookback_limit ?? 200)
    const scoped = recent.filter((row) => known.has(row.id))

    const evidence = Array.from(new Set(params.evidence_refs ?? []))
    const negative = Array.from(new Set(params.negative_control_refs ?? []))
    const impact = Array.from(new Set(params.impact_refs ?? []))

    if (evidence.length === 0) {
      const candidates = scoped.filter((item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) !== "negative")
      if (candidates.length === 1) evidence.push(candidates[0]!.id)
      if (candidates.length > 1) {
        throw new Error(`confirm_finding found multiple positive verification candidates in hypothesis scope: ${candidates.map((item) => item.id).join(", ")}. Pass evidence_refs explicitly.`)
      }
      if (candidates.length === 0) {
        const fallback = recent.filter((item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) !== "negative")
        if (fallback.length === 1) evidence.push(fallback[0]!.id)
        if (fallback.length > 1) {
          throw new Error(`confirm_finding found multiple positive verification candidates in session scope: ${fallback.map((item) => item.id).join(", ")}. Pass evidence_refs explicitly.`)
        }
      }
    }
    if (negative.length === 0) {
      const candidates = scoped.filter((item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) === "negative")
      if (candidates.length === 1) negative.push(candidates[0]!.id)
      if (candidates.length > 1) {
        throw new Error(`confirm_finding found multiple negative control candidates in hypothesis scope: ${candidates.map((item) => item.id).join(", ")}. Pass negative_control_refs explicitly.`)
      }
      if (candidates.length === 0) {
        const fallback = recent.filter((item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) === "negative")
        if (fallback.length === 1) negative.push(fallback[0]!.id)
        if (fallback.length > 1) {
          throw new Error(`confirm_finding found multiple negative control candidates in session scope: ${fallback.map((item) => item.id).join(", ")}. Pass negative_control_refs explicitly.`)
        }
      }
    }
    if (impact.length === 0) {
      const candidates = scoped.filter((item) => item.type === "artifact" || item.type === "observation")
      if (candidates.length === 1) impact.push(candidates[0]!.id)
      if (candidates.length === 0) {
        const fallback = recent.filter((item) => item.type === "artifact" || item.type === "observation")
        if (fallback.length === 1) impact.push(fallback[0]!.id)
      }
    }

    if (evidence.length === 0) {
      throw new Error("confirm_finding could not auto-select positive verification evidence in hypothesis scope. Run verify_assertion with hypothesis_id/persist=true or pass evidence_refs explicitly.")
    }

    const impl = await UpsertFindingTool.init()
    const out = await impl.execute(
      {
        hypothesis_id: params.hypothesis_id,
        title: params.title,
        severity: params.severity,
        impact: params.impact,
        evidence_refs: evidence,
        negative_control_refs: negative,
        impact_refs: impact,
        taxonomy_tags: params.taxonomy_tags,
        confidence: params.confidence,
        status: params.status,
        strict_assertion: params.strict_assertion,
        url: params.url,
        method: params.method,
        parameter: params.parameter,
        payload: params.payload,
        tool_used: params.tool_used ?? "confirm_finding",
        remediation: params.remediation,
      } as never,
      ctx,
    )

    return {
      title: out.title,
      metadata: {
        ...(out.metadata as any),
        auto_selected: {
          evidence_refs: evidence,
          negative_control_refs: negative,
          impact_refs: impact,
        },
      } as any,
      envelope: out.envelope,
      output: out.output,
    }
  },
})
