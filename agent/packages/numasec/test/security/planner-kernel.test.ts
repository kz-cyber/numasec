import { describe, expect, test } from "bun:test"
import { applyPlannerEvent, createPlannerKernel, nextPlannerStep, plannerIsTerminal } from "../../src/security/planner/kernel"

describe("planner kernel", () => {
  test("starts in idle and asks for scope definition", () => {
    const kernel = createPlannerKernel()
    expect(kernel.state).toBe("idle")
    expect(nextPlannerStep(kernel).primitive).toBe("plan_next")
  })

  test("follows positive closure flow", () => {
    let kernel = createPlannerKernel()
    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "standard" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-1", summary: "IDOR in profile" })
    kernel = applyPlannerEvent(kernel, { type: "evidence_recorded", node_id: "node-1", relation: "supports" })
    kernel = applyPlannerEvent(kernel, { type: "verification_recorded", node_id: "node-2", passed: true })
    kernel = applyPlannerEvent(kernel, { type: "decision_made", verdict: "confirmed", finding_id: "SSEC-001" })

    expect(kernel.state).toBe("closed_positive")
    expect(kernel.finding_id).toBe("SSEC-001")
    expect(plannerIsTerminal(kernel)).toBe(true)
    expect(kernel.evidence_nodes.length).toBe(2)
  })

  test("supports negative closure and invalidation", () => {
    let kernel = createPlannerKernel()
    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "quick" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-2", summary: "weak auth" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_invalidated", reason: "control sample disproves hypothesis" })

    expect(kernel.state).toBe("closed_negative")
    expect(plannerIsTerminal(kernel)).toBe(true)
    expect(kernel.notes).toContain("control sample disproves hypothesis")
  })

  test("reset clears kernel runtime state", () => {
    let kernel = createPlannerKernel()
    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "deep" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-3", summary: "graphql auth bypass" })
    kernel = applyPlannerEvent(kernel, { type: "reset" })

    expect(kernel.state).toBe("idle")
    expect(kernel.target).toBe("")
    expect(kernel.hypothesis_id).toBe("")
    expect(kernel.history.length).toBe(1)
    expect(kernel.history[0].type).toBe("reset")
  })
})
