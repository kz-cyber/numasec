import { describe, expect, test } from "bun:test"
import { applyPlannerEvent, createPlannerKernel, nextPlannerStep } from "../../src/security/planner/kernel"
import { selectPlannerPrimitives } from "../../src/security/planner/policy"

describe("planner policy", () => {
  test("keeps kernel transition primitive as policy primary", () => {
    let kernel = createPlannerKernel()
    let policy = selectPlannerPrimitives(kernel)
    expect(policy.primary.primitive).toBe(nextPlannerStep(kernel).primitive)

    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "standard" })
    policy = selectPlannerPrimitives(kernel)
    expect(policy.primary.primitive).toBe(nextPlannerStep(kernel).primitive)

    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-1", summary: "IDOR flow" })
    policy = selectPlannerPrimitives(kernel)
    expect(policy.primary.primitive).toBe(nextPlannerStep(kernel).primitive)

    kernel = applyPlannerEvent(kernel, { type: "evidence_recorded", node_id: "node-1", relation: "supports" })
    policy = selectPlannerPrimitives(kernel)
    expect(policy.primary.primitive).toBe(nextPlannerStep(kernel).primitive)

    kernel = applyPlannerEvent(kernel, { type: "verification_recorded", node_id: "node-2", passed: true })
    policy = selectPlannerPrimitives(kernel)
    expect(policy.primary.primitive).toBe(nextPlannerStep(kernel).primitive)
  })

  test("uses evidence signals from kernel transitions", () => {
    let kernel = createPlannerKernel()
    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "standard" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-2", summary: "auth bypass" })
    kernel = applyPlannerEvent(kernel, { type: "evidence_recorded", node_id: "node-3", relation: "supports" })
    kernel = applyPlannerEvent(kernel, { type: "verification_recorded", node_id: "node-4", passed: false })

    const policy = selectPlannerPrimitives(kernel, {
      budget: {
        primitive_budget: 3,
      },
    })

    expect(kernel.state).toBe("decision_pending")
    expect(policy.primary.primitive).toBe("upsert_finding")
    expect(policy.steps.some((item) => item.primitive === "upsert_hypothesis")).toBe(true)
    expect(policy.evidence.supports).toBe(1)
    expect(policy.evidence.refutes).toBe(0)
    expect(policy.evidence.verification_passed).toBe(false)
  })

  test("applies quick scope budget cap", () => {
    let kernel = createPlannerKernel()
    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "quick" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-3", summary: "api auth gap" })

    const policy = selectPlannerPrimitives(kernel, {
      signals: ["api_app_detected", "waf_detected", "spa_detected"],
      budget: {
        primitive_budget: 4,
        remaining_seconds: 170,
      },
    })

    expect(policy.primary.primitive).toBe("observe_surface")
    expect(policy.steps.length).toBe(1)
    expect(policy.budget.primitive_budget).toBe(1)
  })

  test("adds progressive primitives in deep scope when budget allows", () => {
    let kernel = createPlannerKernel()
    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "deep" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-4", summary: "api input handling" })

    const policy = selectPlannerPrimitives(kernel, {
      signals: ["api_app_detected", "waf_detected", "spa_detected"],
      budget: {
        primitive_budget: 4,
        remaining_seconds: 1200,
      },
    })

    expect(policy.primary.primitive).toBe("observe_surface")
    expect(policy.steps.length).toBeGreaterThan(1)
    expect(policy.steps.some((item) => item.primitive === "mutate_input")).toBe(true)
  })

  test("prioritizes authenticated authz coverage after auth is obtained", () => {
    let kernel = createPlannerKernel()
    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "deep" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-6", summary: "authenticated user workflow" })

    const policy = selectPlannerPrimitives(kernel, {
      signals: ["auth_obtained", "spa_detected"],
      budget: {
        primitive_budget: 4,
        remaining_seconds: 1200,
      },
    })

    expect(policy.primary.primitive).toBe("observe_surface")
    expect(policy.steps.some((item) => item.primitive === "access_control_test")).toBe(true)
    expect(policy.steps.some((item) => item.primitive === "browser")).toBe(true)
  })

  test("reduces primitive queue when time budget is low", () => {
    let kernel = createPlannerKernel()
    kernel = applyPlannerEvent(kernel, { type: "scope_set", target: "https://example.com", scope: "deep" })
    kernel = applyPlannerEvent(kernel, { type: "hypothesis_upserted", hypothesis_id: "hyp-5", summary: "waf bypass" })

    const policy = selectPlannerPrimitives(kernel, {
      signals: ["waf_detected"],
      budget: {
        primitive_budget: 4,
        remaining_seconds: 60,
      },
    })

    expect(policy.steps.length).toBe(1)
    expect(policy.budget.primitive_budget).toBe(1)
  })
})
