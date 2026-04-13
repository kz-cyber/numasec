import { describe, expect, test } from "bun:test"
import { mergeChains, mergeFindings, mergeMessages, readNextCursor } from "../../../src/cli/cmd/tui/context/sync-pagination"

describe("tui sync pagination helpers", () => {
  test("reads next cursor from response headers", () => {
    const headers = new Headers()
    headers.set("x-next-cursor", "cursor-1")
    expect(readNextCursor(headers)).toBe("cursor-1")
    expect(readNextCursor(new Headers())).toBeNull()
  })

  test("merges message pages without duplicates", () => {
    const current = [{ id: "msg_002" }, { id: "msg_003" }] as any
    const next = [{ id: "msg_001" }, { id: "msg_002" }] as any
    const merged = mergeMessages(current, next)
    expect(merged.map((item) => item.id)).toEqual(["msg_001", "msg_002", "msg_003"])
  })

  test("upserts findings when incremental sync returns updates", () => {
    const current = [
      {
        id: "SSEC-1",
        title: "one",
        severity: "low",
        url: "",
        parameter: "",
        payload: "",
        evidence: "",
        cwe_id: "",
        owasp_category: "",
        confidence: 0.5,
        chain_id: "",
        tool_used: "",
        description: "",
        cvss_score: null,
        time_created: 1,
        time_updated: 1,
      },
      {
        id: "SSEC-2",
        title: "two",
        severity: "low",
        url: "",
        parameter: "",
        payload: "",
        evidence: "",
        cwe_id: "",
        owasp_category: "",
        confidence: 0.5,
        chain_id: "",
        tool_used: "",
        description: "",
        cvss_score: null,
        time_created: 2,
        time_updated: 2,
      },
    ]
    const next = [
      {
        id: "SSEC-2",
        title: "two",
        severity: "high",
        url: "",
        parameter: "",
        payload: "",
        evidence: "",
        cwe_id: "",
        owasp_category: "",
        confidence: 0.5,
        chain_id: "",
        tool_used: "",
        description: "",
        cvss_score: null,
        time_created: 2,
        time_updated: 3,
      },
      {
        id: "SSEC-3",
        title: "three",
        severity: "critical",
        url: "",
        parameter: "",
        payload: "",
        evidence: "",
        cwe_id: "",
        owasp_category: "",
        confidence: 0.5,
        chain_id: "",
        tool_used: "",
        description: "",
        cvss_score: null,
        time_created: 4,
        time_updated: 4,
      },
    ]
    const merged = mergeFindings(current, next)
    expect(merged.map((item) => item.id)).toEqual(["SSEC-1", "SSEC-2", "SSEC-3"])
    expect(merged.find((item) => item.id === "SSEC-2")?.severity).toBe("high")
  })

  test("upserts chains when incremental sync returns updates", () => {
    const current = [
      {
        chain_id: "CHAIN-1",
        severity: "medium",
        finding_count: 1,
        finding_ids: ["SSEC-1"],
        urls: ["https://a"],
        time_created: 1,
        time_updated: 1,
      },
    ]
    const next = [
      {
        chain_id: "CHAIN-1",
        severity: "critical",
        finding_count: 2,
        finding_ids: ["SSEC-1", "SSEC-2"],
        urls: ["https://a"],
        time_created: 1,
        time_updated: 2,
      },
      {
        chain_id: "CHAIN-2",
        severity: "low",
        finding_count: 1,
        finding_ids: ["SSEC-3"],
        urls: ["https://b"],
        time_created: 3,
        time_updated: 3,
      },
    ]
    const merged = mergeChains(current, next)
    expect(merged.map((item) => item.chain_id)).toEqual(["CHAIN-1", "CHAIN-2"])
    expect(merged.find((item) => item.chain_id === "CHAIN-1")?.finding_count).toBe(2)
    expect(merged.find((item) => item.chain_id === "CHAIN-1")?.severity).toBe("critical")
  })
})
