import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const MassAssignmentEvaluator: FindingEvaluator = {
  family: "mass_assignment",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "mass_assignment", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      const method = String(value.method ?? "POST")
      const parameter = String(value.parameter ?? "")
      out.push({
        family: "mass_assignment",
        title: String(value.title ?? "Mass assignment indicated"),
        description: "Protected fields were accepted during object creation or update, enabling unauthorized privilege or attribute manipulation.",
        severity: (value.technical_severity ?? "high") as any,
        state: "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.85,
        url,
        method,
        parameter,
        payload: String(value.payload ?? ""),
        root_cause_key: `mass|${url}|${method}|${parameter}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation: "Whitelist writable fields server-side and reject privileged attributes from untrusted input.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
