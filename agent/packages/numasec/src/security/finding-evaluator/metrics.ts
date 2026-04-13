import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const MetricsEvaluator: FindingEvaluator = {
  family: "metrics",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "metrics", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      out.push({
        family: "metrics",
        title: String(value.title ?? "Metrics endpoint exposed without authentication"),
        description: "An unauthenticated metrics endpoint exposed operational internals suitable for reconnaissance and attack planning.",
        severity: (value.technical_severity ?? "medium") as any,
        state: "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.85,
        url,
        method: String(value.method ?? "GET"),
        parameter: "",
        payload: "",
        root_cause_key: `metrics|${url}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation: "Restrict metrics endpoints to internal networks or require authentication.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
