import { describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { SessionID, MessageID } from "../../src/session/schema"
import { PlanNextTool } from "../../src/security/tool/plan-next"

function toolContext(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-test",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runPlanNext(args: Record<string, unknown>) {
  const sessionID = "sess-plan-next-policy" as SessionID
  const impl = await PlanNextTool.init()
  return impl.execute(args as never, toolContext(sessionID))
}

describe("plan_next tool policy integration", () => {
  test("returns policy primitive sequence with deep scope signals", async () => {
    const out = await runPlanNext({
      state: "hypothesis_open",
      target: "https://example.com",
      scope: "deep",
      hypothesis_id: "hyp-1",
      policy_signals: ["api_app_detected", "waf_detected", "spa_detected"],
      primitive_budget: 4,
      remaining_seconds: 1200,
    })

    expect((out.metadata as any).primitive).toBe("observe_surface")
    expect((out.metadata as any).policyPrimitives).toContain("mutate_input")
    expect(out.output).toContain("Policy sequence:")
  })

  test("caps policy queue in quick scope", async () => {
    const out = await runPlanNext({
      state: "hypothesis_open",
      target: "https://example.com",
      scope: "quick",
      hypothesis_id: "hyp-2",
      policy_signals: ["api_app_detected", "waf_detected"],
      primitive_budget: 4,
      remaining_seconds: 180,
    })

    expect((out.metadata as any).primitive).toBe("observe_surface")
    expect(((out.metadata as any).policyPrimitives as string[]).length).toBe(1)
    expect(out.output).toContain("Budget:")
  })

  test("surfaces authenticated authz coverage primitives after auth signal", async () => {
    const out = await runPlanNext({
      state: "hypothesis_open",
      target: "https://example.com",
      scope: "deep",
      hypothesis_id: "hyp-auth-1",
      policy_signals: ["auth_obtained", "spa_detected"],
      primitive_budget: 4,
      remaining_seconds: 1200,
    })

    expect((out.metadata as any).primitive).toBe("observe_surface")
    expect((out.metadata as any).policyPrimitives).toContain("access_control_test")
    expect((out.metadata as any).policyPrimitives).toContain("browser")
  })

  test("normalizes alias event names and uses top-level fallback fields", async () => {
    const out = await runPlanNext({
      state: "scope_defined",
      target: "https://example.com",
      scope: "standard",
      hypothesis_id: "hyp-9",
      event: "hypothesis",
      event_payload: {
        statement: "IDOR hypothesis",
      },
    })

    expect((out.metadata as any).eventRaw).toBe("hypothesis")
    expect((out.metadata as any).eventCanonical).toBe("hypothesis_upserted")
    expect(out.output).toContain("Event: hypothesis -> hypothesis_upserted")
  })

  test("accepts hypothesis_open alias used by interactive runs", async () => {
    const out = await runPlanNext({
      state: "scope_defined",
      target: "https://example.com",
      scope: "deep",
      hypothesis_id: "hyp-11",
      event_type: "hypothesis_open",
      event_payload: {
        statement: "Auth bypass hypothesis",
      },
    })

    expect((out.metadata as any).eventCanonical).toBe("hypothesis_upserted")
    expect(out.output).toContain("Event: hypothesis_open -> hypothesis_upserted")
  })

  test("accepts event_payload_json and decision aliases", async () => {
    const out = await runPlanNext({
      state: "decision_pending",
      target: "https://example.com",
      scope: "standard",
      finding_id: "SSEC-123",
      event_type: "verdict",
      event_payload_json: JSON.stringify({
        confirmed: true,
      }),
    })

    expect((out.metadata as any).eventCanonical).toBe("decision_made")
    expect(out.output).toContain("Event: verdict -> decision_made")
    expect((out.metadata as any).state).toBe("closed_positive")
  })
})
