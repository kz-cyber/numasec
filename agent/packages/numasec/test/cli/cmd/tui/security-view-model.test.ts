import { describe, expect, test } from "bun:test"
import type { Part } from "@numasec/sdk/v2"
import {
  fallbackChains,
  fallbackCoverage,
  fallbackFindings,
  fallbackTarget,
  selectChains,
  selectCoverage,
  selectFindings,
  selectTarget,
  type SecurityReadState,
} from "../../../../src/cli/cmd/tui/security-view-model"

function toolPart(input: {
  id: string
  tool: string
  output?: string
  state?: Record<string, unknown>
}) {
  return {
    id: input.id,
    sessionID: "ses_test",
    messageID: "msg_test",
    type: "tool",
    tool: input.tool,
    state: {
      status: "completed",
      input: input.state ?? {},
      output: input.output,
    },
  } as Part
}

describe("security view model", () => {
  test("prefers canonical read model when canonical state is available", () => {
    const messages = [{ id: "msg_test", role: "assistant" }]
    const parts: Record<string, Part[]> = {
      msg_test: [
        toolPart({
          id: "prt_target",
          tool: "security/create_session",
          state: { target: "https://legacy.example" },
        }),
        toolPart({
          id: "prt_findings",
          tool: "security/get_findings",
          output: JSON.stringify({
            findings: [
              {
                id: "LEGACY-1",
                title: "Legacy finding",
                severity: "low",
                chain_id: "LEGACY-CHAIN",
                owasp_category: "A01:2021",
                url: "https://legacy.example/login",
              },
            ],
          }),
        }),
      ],
    }

    const legacyFindings = fallbackFindings(messages, parts)
    const legacyChains = fallbackChains(messages, parts, legacyFindings)
    const legacyTarget = fallbackTarget(messages, parts)
    const legacyCoverage = fallbackCoverage(messages, parts)

    const canonical: SecurityReadState = {
      scope: ["https://canonical.example"],
      findings: [
        {
          id: "CAN-1",
          title: "Canonical SQLi",
          severity: "high",
          chain_id: "CAN-CHAIN",
          owasp_category: "A03:2021",
          url: "https://canonical.example/search",
        },
        {
          id: "CAN-2",
          title: "Canonical auth bypass",
          severity: "medium",
          chain_id: "CAN-CHAIN",
          owasp_category: "A07:2021",
          url: "https://canonical.example/admin",
        },
      ],
      chains: [
        {
          chain_id: "CAN-CHAIN",
          severity: "high",
          finding_ids: ["CAN-1", "CAN-2"],
          urls: ["https://canonical.example/search"],
        },
      ],
      coverage: [
        {
          category: "A05:2021",
          tested: true,
          finding_count: 0,
        },
      ],
    }

    const selectedFindings = selectFindings(canonical, legacyFindings)
    const selectedChains = selectChains(canonical, legacyChains, selectedFindings)
    const selectedTarget = selectTarget(canonical, legacyTarget)
    const selectedCoverage = selectCoverage(canonical, legacyCoverage, selectedFindings)

    expect(selectedFindings.map((item) => item.id)).toEqual(["CAN-1", "CAN-2"])
    expect(selectedChains.map((item) => item.chain_id)).toEqual(["CAN-CHAIN"])
    expect(selectedTarget).toBe("https://canonical.example")
    expect(selectedCoverage.tested.has("A05")).toBe(true)
    expect(selectedCoverage.vulnerable.has("A03")).toBe(true)
  })

  test("falls back to parsed tool output when canonical state is empty", () => {
    const messages = [{ id: "msg_test", role: "assistant" }]
    const parts: Record<string, Part[]> = {
      msg_test: [
        toolPart({
          id: "prt_target",
          tool: "security/recon",
          state: { target: "https://legacy.example" },
        }),
        toolPart({
          id: "prt_findings",
          tool: "security/get_findings",
          output: JSON.stringify({
            findings: [
              {
                id: "LEGACY-1",
                title: "Legacy finding",
                severity: "high",
                chain_id: "LEGACY-CHAIN",
                owasp_category: "A02:2021",
                url: "https://legacy.example/login",
              },
              {
                id: "LEGACY-2",
                title: "Legacy second finding",
                severity: "medium",
                chain_id: "LEGACY-CHAIN",
                owasp_category: "A03:2021",
                url: "https://legacy.example/admin",
              },
            ],
          }),
        }),
      ],
    }

    const legacyFindings = fallbackFindings(messages, parts)
    const legacyChains = fallbackChains(messages, parts, legacyFindings)
    const legacyTarget = fallbackTarget(messages, parts)
    const legacyCoverage = fallbackCoverage(messages, parts)

    const canonical: SecurityReadState = {
      scope: [],
      findings: [],
      chains: [],
      coverage: [],
    }

    const selectedFindings = selectFindings(canonical, legacyFindings)
    const selectedChains = selectChains(canonical, legacyChains, selectedFindings)
    const selectedTarget = selectTarget(canonical, legacyTarget)
    const selectedCoverage = selectCoverage(canonical, legacyCoverage, selectedFindings)

    expect(selectedFindings.map((item) => item.id)).toEqual(["LEGACY-1", "LEGACY-2"])
    expect(selectedChains.map((item) => item.chain_id)).toEqual(["LEGACY-CHAIN"])
    expect(selectedTarget).toBe("https://legacy.example")
    expect(selectedCoverage.vulnerable.has("A02")).toBe(true)
  })

  test("keeps build_chains parser fallback for legacy sessions without canonical findings", () => {
    const messages = [{ id: "msg_test", role: "assistant" }]
    const parts: Record<string, Part[]> = {
      msg_test: [
        toolPart({
          id: "prt_chain",
          tool: "security/build_chains",
          output: JSON.stringify({
            chains: {
              "LEGACY-CHAIN": ["SSEC-LEG-1", "SSEC-LEG-2"],
            },
          }),
        }),
      ],
    }

    const legacyFindings = fallbackFindings(messages, parts)
    const legacyChains = fallbackChains(messages, parts, legacyFindings)

    expect(legacyFindings.length).toBe(0)
    expect(legacyChains.length).toBe(1)
    expect(legacyChains[0].chain_id).toBe("LEGACY-CHAIN")
    expect(legacyChains[0].items.map((item) => item.title)).toEqual(["SSEC-LEG-1", "SSEC-LEG-2"])
  })
})
