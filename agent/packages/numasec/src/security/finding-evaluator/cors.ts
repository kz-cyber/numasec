import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const CorsEvaluator: FindingEvaluator = {
  family: "cors",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "cors")
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      const kind = String(value.kind ?? "")
      const item: FindingCandidate = {
        family: "cors",
        title: String(value.title ?? "CORS policy issue"),
        description: Array.isArray(value.details) ? value.details.join("; ") : String(value.evidence ?? "Cross-origin policy requires review."),
        severity: (value.technical_severity ?? "medium") as any,
        state: row.type === "verification" && passed(row) ? "verified" : "suppressed",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.75,
        url,
        method: String(value.method ?? "GET"),
        parameter: "",
        payload: "",
        root_cause_key: `cors|${url}|${kind}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation: "Restrict Access-Control-Allow-Origin to trusted origins and avoid credentialed cross-origin access on sensitive data endpoints.",
        reportable: row.type === "verification" && passed(row),
        suppression_reason: "",
        node_ids: [row.id],
      }
      if (!item.reportable) {
        item.suppression_reason = kind || "non_dangerous_cors_pattern"
      }
      out.push(item)
    }
    return out
  },
}
