import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const JwtEvaluator: FindingEvaluator = {
  family: "jwt",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "jwt", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      const method = String(value.method ?? "GET")
      const kind = String(value.kind ?? "jwt_issue")
      out.push({
        family: "jwt",
        title: String(value.title ?? "JWT weakness detected"),
        description: String(value.evidence ?? "JWT analysis detected a security weakness."),
        severity: (value.technical_severity ?? "medium") as any,
        state: "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.85,
        url,
        method,
        parameter: "",
        payload: "",
        root_cause_key: `jwt|${url}|${kind}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation:
          kind === "no_expiration"
            ? "Add a short-lived exp claim and rotate tokens frequently."
            : "Remove sensitive data and unnecessary privilege claims from JWT payloads.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
