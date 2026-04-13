import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const SqlInjectionEvaluator: FindingEvaluator = {
  family: "sql_injection",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "sql_injection", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      const method = String(value.method ?? "GET")
      const parameter = String(value.parameter ?? "")
      const title = String(value.title ?? "SQL injection indicated")
      const kind = String(value.kind ?? "signal")
      out.push({
        family: "sql_injection",
        title,
        description: String(value.evidence ?? "A crafted payload triggered a database-specific error signature consistent with SQL injection."),
        severity: (value.technical_severity ?? "high") as any,
        state: "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.8,
        url,
        method,
        parameter,
        payload: String(value.payload ?? ""),
        root_cause_key: `sqli|${url}|${method}|${parameter}|${kind}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation: "Use parameterized queries and avoid concatenating untrusted input into database queries.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
