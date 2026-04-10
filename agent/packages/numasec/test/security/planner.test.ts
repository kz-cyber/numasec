import { describe, expect, test } from "bun:test"
import { generatePlan, applyReplanSignal, formatPlan } from "../../src/security/planner/planner"

describe("generatePlan", () => {
  test("quick scope: minimal recon, no exploitation phase", () => {
    const plan = generatePlan({ url: "http://target.com" }, "quick")

    expect(plan.scope).toBe("quick")
    expect(plan.timeout).toBe(180)
    expect(plan.phases.some((p) => p.phase === "recon")).toBe(true)
    expect(plan.phases.some((p) => p.phase === "vuln_testing")).toBe(true)
    expect(plan.phases.some((p) => p.phase === "reporting")).toBe(true)
    expect(plan.phases.some((p) => p.phase === "exploitation")).toBe(false)
  })

  test("standard scope: includes exploitation phase", () => {
    const plan = generatePlan({ url: "http://target.com" }, "standard")

    expect(plan.timeout).toBe(600)
    expect(plan.phases.some((p) => p.phase === "exploitation")).toBe(true)
  })

  test("deep scope: longest timeout", () => {
    const plan = generatePlan({ url: "http://target.com" }, "deep")
    expect(plan.timeout).toBe(1800)
  })

  test("always includes injection_test and xss_test", () => {
    const plan = generatePlan({ url: "http://target.com" }, "quick")
    const vulnSteps = plan.phases.find((p) => p.phase === "vuln_testing")!.steps

    expect(vulnSteps.some((s) => s.tool === "injection_test")).toBe(true)
    expect(vulnSteps.some((s) => s.tool === "xss_test")).toBe(true)
  })

  test("includes graphql_test when hasGraphql=true", () => {
    const plan = generatePlan({ url: "http://target.com", hasGraphql: true })
    const vulnSteps = plan.phases.find((p) => p.phase === "vuln_testing")!.steps
    expect(vulnSteps.some((s) => s.tool === "graphql_test")).toBe(true)
  })

  test("includes upload_test when hasUpload=true", () => {
    const plan = generatePlan({ url: "http://target.com", hasUpload: true })
    const vulnSteps = plan.phases.find((p) => p.phase === "vuln_testing")!.steps
    expect(vulnSteps.some((s) => s.tool === "upload_test")).toBe(true)
  })

  test("technology-specific notes: Flask → SSTI", () => {
    const plan = generatePlan({ url: "http://target.com", technologies: ["Flask 2.3"] })
    expect(plan.notes.some((n) => n.includes("SSTI"))).toBe(true)
  })

  test("technology-specific notes: Node.js → prototype pollution or NoSQL", () => {
    const plan = generatePlan({ url: "http://target.com", technologies: ["Express 4.18", "Node.js"] })
    expect(plan.notes.some((n) => n.includes("prototype pollution") || n.includes("NoSQL"))).toBe(true)
  })

  test("technology-specific notes: Java → deserialization or Log4Shell", () => {
    const plan = generatePlan({ url: "http://target.com", technologies: ["Spring Boot 3.0"] })
    expect(plan.notes.some((n) => n.includes("deserialization") || n.includes("Log4Shell"))).toBe(true)
  })

  test("technology-specific notes: PHP → LFI", () => {
    const plan = generatePlan({ url: "http://target.com", technologies: ["PHP 8.2"] })
    expect(plan.notes.some((n) => n.includes("LFI"))).toBe(true)
  })

  test("reporting phase is always last", () => {
    const plan = generatePlan({ url: "http://target.com" })
    const lastPhase = plan.phases[plan.phases.length - 1]
    expect(lastPhase.phase).toBe("reporting")
  })

  test("all steps have required fields", () => {
    const plan = generatePlan({ url: "http://target.com", hasGraphql: true, hasUpload: true }, "deep")
    for (const phase of plan.phases) {
      for (const step of phase.steps) {
        expect(step.tool).toBeTruthy()
        expect(step.description).toBeTruthy()
        expect(step.parameters).toBeDefined()
        expect([1, 2, 3]).toContain(step.priority)
      }
    }
  })
})

describe("applyReplanSignal", () => {
  test("waf_detected adds note", () => {
    const plan = generatePlan({ url: "http://target.com" })
    const updated = applyReplanSignal(plan, { type: "waf_detected" })
    expect(updated.notes.some((n) => n.includes("WAF"))).toBe(true)
  })

  test("graphql_detected adds graphql_test step", () => {
    const plan = generatePlan({ url: "http://target.com" })
    const vulnPhase = plan.phases.find((p) => p.phase === "vuln_testing")!
    expect(vulnPhase.steps.some((s) => s.tool === "graphql_test")).toBe(false)

    const updated = applyReplanSignal(plan, { type: "graphql_detected", data: { url: "http://target.com/graphql" } })
    const updatedVulnPhase = updated.phases.find((p) => p.phase === "vuln_testing")!
    expect(updatedVulnPhase.steps.some((s) => s.tool === "graphql_test")).toBe(true)
  })

  test("does not duplicate graphql_test if already present", () => {
    const plan = generatePlan({ url: "http://target.com", hasGraphql: true })
    const updated = applyReplanSignal(plan, { type: "graphql_detected" })
    const vulnPhase = updated.phases.find((p) => p.phase === "vuln_testing")!
    const graphqlSteps = vulnPhase.steps.filter((s) => s.tool === "graphql_test")
    expect(graphqlSteps.length).toBe(1)
  })

  test("returns a plan with the signal applied", () => {
    const plan = generatePlan({ url: "http://target.com" })
    const updated = applyReplanSignal(plan, { type: "waf_detected" })
    expect(updated.notes.length).toBeGreaterThan(plan.notes.length - 1)
    expect(updated.notes.some((n) => n.includes("WAF"))).toBe(true)
  })

  test("auth_obtained adds re-test note", () => {
    const plan = generatePlan({ url: "http://target.com" })
    const updated = applyReplanSignal(plan, { type: "auth_obtained" })
    expect(updated.notes.some((n) => n.toLowerCase().includes("auth") || n.toLowerCase().includes("credential"))).toBe(true)
  })

  test("rate_limited adds delay note", () => {
    const plan = generatePlan({ url: "http://target.com" })
    const updated = applyReplanSignal(plan, { type: "rate_limited" })
    expect(updated.notes.some((n) => n.toLowerCase().includes("delay") || n.toLowerCase().includes("concurren") || n.toLowerCase().includes("rate"))).toBe(true)
  })
})

describe("formatPlan", () => {
  test("includes target and scope", () => {
    const plan = generatePlan({ url: "http://target.com" }, "standard")
    const formatted = formatPlan(plan)

    expect(formatted).toContain("http://target.com")
    expect(formatted).toContain("standard")
  })

  test("includes phase names", () => {
    const plan = generatePlan({ url: "http://target.com" }, "standard")
    const formatted = formatPlan(plan)

    expect(formatted.toUpperCase()).toContain("RECON")
    expect(formatted.toUpperCase()).toContain("VULN_TESTING")
  })

  test("includes technology notes", () => {
    const plan = generatePlan({ url: "http://target.com", technologies: ["Flask"] })
    const formatted = formatPlan(plan)
    expect(formatted).toContain("SSTI")
  })
})
