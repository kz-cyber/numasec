import type { EvidenceEdgeRow, EvidenceNodeRow } from "../evidence-store"
import type { SessionID } from "../../session/schema"
import { FindingTable } from "../security.sql"

export type FindingRow = (typeof FindingTable)["$inferSelect"]

export interface FindingEvaluatorInput {
  sessionID: SessionID
  nodes: EvidenceNodeRow[]
  edges: EvidenceEdgeRow[]
  findings: FindingRow[]
}

export interface FindingCandidate {
  family: string
  title: string
  description: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  state: "provisional" | "verified" | "refuted" | "suppressed"
  confidence: number
  url: string
  method: string
  parameter: string
  payload: string
  root_cause_key: string
  source_hypothesis_id: string
  evidence_refs: string[]
  negative_control_refs: string[]
  impact_refs: string[]
  remediation: string
  reportable: boolean
  suppression_reason: string
  node_ids: string[]
}

export interface FindingEvaluator {
  readonly family: string
  readonly evaluate: (input: FindingEvaluatorInput) => FindingCandidate[]
}

export function payload(row: EvidenceNodeRow): Record<string, any> {
  const value = row.payload
  if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, any>
  return {}
}

export function passed(row: EvidenceNodeRow) {
  const value = payload(row)
  if (typeof value.passed === "boolean") return value.passed
  return row.status === "confirmed"
}

export function familyNodes(input: FindingEvaluatorInput, family: string, type?: string) {
  return input.nodes.filter((row) => {
    if (type && row.type !== type) return false
    return payload(row).family === family
  })
}

export function incoming(edges: EvidenceEdgeRow[], nodeID: string, relation?: string) {
  return edges.filter((row) => row.to_node_id === nodeID && (!relation || row.relation === relation))
}

export function outgoing(edges: EvidenceEdgeRow[], nodeID: string, relation?: string) {
  return edges.filter((row) => row.from_node_id === nodeID && (!relation || row.relation === relation))
}

export function evidenceRefs(edges: EvidenceEdgeRow[], nodeID: string) {
  return incoming(edges, nodeID, "supports").map((row) => row.from_node_id)
}

export function hypothesisRef(input: FindingEvaluatorInput, nodeID: string) {
  const links = incoming(input.edges, nodeID)
  for (const edge of links) {
    const node = input.nodes.find((row) => row.id === edge.from_node_id)
    if (!node || node.type !== "hypothesis") continue
    return node.id
  }
  return ""
}

export function text(value: unknown) {
  if (typeof value === "string") return value
  if (typeof value === "number") return String(value)
  if (typeof value === "boolean") return value ? "true" : "false"
  return ""
}
