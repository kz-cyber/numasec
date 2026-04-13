import { describe, expect, test } from "bun:test"
import { ToolResultEnvelope, makeToolResultEnvelope } from "../../src/security/tool/result-envelope"

describe("tool result envelope", () => {
  test("applies defaults for arrays and metrics", () => {
    const out = makeToolResultEnvelope({
      status: "ok",
    })

    expect(out.status).toBe("ok")
    expect(out.artifacts).toEqual([])
    expect(out.observations).toEqual([])
    expect(out.verifications).toEqual([])
    expect(out.links).toEqual([])
    expect(out.metrics).toEqual({})
  })

  test("supports structured observations and metrics", () => {
    const out = makeToolResultEnvelope({
      status: "ok",
      observations: [{ type: "finding_saved", finding_id: "SSEC-TEST" }],
      metrics: { finding_count: 1 },
    })

    expect(out.observations[0].type).toBe("finding_saved")
    expect(out.metrics.finding_count).toBe(1)
  })

  test("rejects invalid status", () => {
    const parsed = ToolResultEnvelope.safeParse({
      status: "not-valid",
    })

    expect(parsed.success).toBe(false)
  })
})

