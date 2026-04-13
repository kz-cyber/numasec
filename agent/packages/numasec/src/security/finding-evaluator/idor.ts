import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const IdorEvaluator: FindingEvaluator = {
  family: "idor",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "idor", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      const method = String(value.method ?? "GET")
      const parameter = String(value.parameter ?? "")
      out.push({
        family: "idor",
        title: String(value.title ?? "IDOR indicated"),
        description:
          String(value.evidence ?? "") ||
          "Authenticated enumeration returned multiple resource identifiers with accessible data. Treat as access-control vulnerability pending stronger ownership differential proof.",
        severity: (value.technical_severity ?? "high") as any,
        state: value.kind === "resource_enumeration" ? "provisional" : "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.7,
        url,
        method,
        parameter,
        payload: String(value.payload ?? ""),
        root_cause_key: `idor|${url}|${method}|${parameter}|${String(value.kind ?? "signal")}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation: "Enforce object-level authorization checks for every resource access and mutation.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
