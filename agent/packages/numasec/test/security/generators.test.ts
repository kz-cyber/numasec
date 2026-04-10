import { describe, expect, test } from "bun:test"
import { generateSarif, generateMarkdown, generateHtml, calculateRiskScore } from "../../src/security/report/generators"
import type { FindingTable } from "../../src/security/security.sql"
import type { ChainGroup } from "../../src/security/chain-builder"

type Finding = typeof FindingTable.$inferSelect

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id ?? ("SSEC-TEST000001" as any),
    session_id: "test-session" as any,
    target_id: null,
    title: overrides.title ?? "Test SQL Injection",
    severity: overrides.severity ?? "critical",
    description: overrides.description ?? "SQL injection in login endpoint",
    evidence: overrides.evidence ?? "Error: SQLITE_ERROR near syntax",
    confirmed: overrides.confirmed ?? true,
    false_positive: false,
    url: overrides.url ?? "http://example.com/api/login",
    method: overrides.method ?? "POST",
    parameter: overrides.parameter ?? "email",
    payload: overrides.payload ?? "' OR 1=1 --",
    request_dump: overrides.request_dump ?? "",
    response_status: overrides.response_status ?? 500,
    cwe_id: overrides.cwe_id ?? "CWE-89",
    cvss_score: overrides.cvss_score ?? 9.1,
    cvss_vector: overrides.cvss_vector ?? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    owasp_category: overrides.owasp_category ?? "A03:2021 - Injection",
    attack_technique: overrides.attack_technique ?? "T1190",
    rule_id: overrides.rule_id ?? "",
    wstg_id: overrides.wstg_id ?? "",
    confidence: overrides.confidence ?? 0.9,
    chain_id: overrides.chain_id ?? "",
    related_finding_ids: overrides.related_finding_ids ?? null,
    tool_used: overrides.tool_used ?? "injection_test",
    remediation_summary: overrides.remediation_summary ?? "Use parameterized queries",
    created_at: overrides.created_at ?? Date.now(),
    updated_at: null,
  } as Finding
}

const TEST_FINDINGS: Finding[] = [
  makeFinding(),
  makeFinding({
    id: "SSEC-TEST000002" as any,
    title: "Cross-Site Scripting in search",
    severity: "high",
    url: "http://example.com/search",
    parameter: "q",
    cwe_id: "CWE-79",
    cvss_score: 6.1,
    owasp_category: "A03:2021 - Injection",
    confidence: 0.8,
    remediation_summary: "Encode output and implement CSP",
  }),
  makeFinding({
    id: "SSEC-TEST000003" as any,
    title: "Information Disclosure",
    severity: "low",
    url: "http://example.com/debug",
    cwe_id: "CWE-200",
    cvss_score: 3.1,
    owasp_category: "A01:2021 - Broken Access Control",
    confidence: 0.6,
    remediation_summary: "Disable debug mode in production",
  }),
]

// ── Risk Score ───────────────────────────────────────────────

describe("calculateRiskScore", () => {
  test("empty findings → 0", () => {
    expect(calculateRiskScore([])).toBe(0)
  })

  test("single critical finding", () => {
    const score = calculateRiskScore([makeFinding({ severity: "critical", confidence: 1.0 })])
    expect(score).toBe(25)
  })

  test("score is capped at 100", () => {
    const manyFindings = Array.from({ length: 10 }, () =>
      makeFinding({ severity: "critical", confidence: 1.0 }),
    )
    expect(calculateRiskScore(manyFindings)).toBe(100)
  })

  test("confidence affects score", () => {
    const highConf = calculateRiskScore([makeFinding({ severity: "critical", confidence: 1.0 })])
    const lowConf = calculateRiskScore([makeFinding({ severity: "critical", confidence: 0.5 })])
    expect(highConf).toBeGreaterThan(lowConf)
  })

  test("info findings have minimal weight", () => {
    const score = calculateRiskScore([makeFinding({ severity: "info", confidence: 1.0 })])
    expect(score).toBe(1)
  })
})

// ── SARIF Generator ──────────────────────────────────────────

describe("generateSarif", () => {
  test("produces valid JSON", () => {
    const sarif = generateSarif(TEST_FINDINGS, "http://example.com")
    expect(() => JSON.parse(sarif)).not.toThrow()
  })

  test("follows SARIF 2.1.0 schema", () => {
    const parsed = JSON.parse(generateSarif(TEST_FINDINGS, "http://example.com"))
    expect(parsed.$schema).toContain("sarif-schema-2.1.0")
    expect(parsed.version).toBe("2.1.0")
    expect(parsed.runs).toHaveLength(1)
    expect(parsed.runs[0].tool.driver.name).toBe("numasec")
  })

  test("maps findings to rules and results", () => {
    const parsed = JSON.parse(generateSarif(TEST_FINDINGS, "http://example.com"))
    const run = parsed.runs[0]

    expect(run.tool.driver.rules).toHaveLength(3)
    expect(run.results).toHaveLength(3)
  })

  test("critical/high → error, low → note", () => {
    const parsed = JSON.parse(generateSarif(TEST_FINDINGS, "http://example.com"))
    const results = parsed.runs[0].results

    const critical = results.find((r: any) => r.ruleId === "SSEC-TEST000001")
    const low = results.find((r: any) => r.ruleId === "SSEC-TEST000003")

    expect(critical.level).toBe("error")
    expect(low.level).toBe("note")
  })

  test("includes attack chains when provided", () => {
    const chains: ChainGroup[] = [
      {
        id: "CHAIN-001",
        title: "SQLi → XSS",
        severity: "critical",
        impact: "Full compromise",
        findings: TEST_FINDINGS.slice(0, 2),
      },
    ]

    const parsed = JSON.parse(generateSarif(TEST_FINDINGS, "http://example.com", chains))
    const props = parsed.runs[0].invocations[0].properties
    expect(props.attackChains).toHaveLength(1)
    expect(props.attackChains[0].title).toBe("SQLi → XSS")
  })
})

// ── Markdown Generator ───────────────────────────────────────

describe("generateMarkdown", () => {
  test("includes header with target", () => {
    const md = generateMarkdown(TEST_FINDINGS, "http://example.com")
    expect(md).toContain("# Security Assessment Report")
    expect(md).toContain("http://example.com")
  })

  test("includes executive summary with risk score", () => {
    const md = generateMarkdown(TEST_FINDINGS, "http://example.com")
    expect(md).toContain("Executive Summary")
    expect(md).toContain("Risk Score")
    expect(md).toContain("/100")
  })

  test("includes severity counts", () => {
    const md = generateMarkdown(TEST_FINDINGS, "http://example.com")
    expect(md).toContain("| Severity | Count |")
    expect(md).toContain("Critical")
  })

  test("findings are sorted by severity (critical first)", () => {
    const md = generateMarkdown(TEST_FINDINGS, "http://example.com")
    const sqlIdx = md.indexOf("Test SQL Injection")
    const infoIdx = md.indexOf("Information Disclosure")
    expect(sqlIdx).toBeLessThan(infoIdx)
  })

  test("includes OWASP coverage section", () => {
    const md = generateMarkdown(TEST_FINDINGS, "http://example.com")
    expect(md).toContain("OWASP")
    expect(md).toContain("A03:2021")
  })

  test("includes remediation roadmap", () => {
    const md = generateMarkdown(TEST_FINDINGS, "http://example.com")
    expect(md).toContain("Remediation")
    expect(md).toContain("parameterized queries")
  })

  test("includes attack paths when chains provided", () => {
    const chains: ChainGroup[] = [
      {
        id: "CHAIN-001",
        title: "SQLi → XSS",
        severity: "critical",
        impact: "Full compromise",
        findings: TEST_FINDINGS.slice(0, 2),
      },
    ]

    const md = generateMarkdown(TEST_FINDINGS, "http://example.com", chains)
    expect(md).toContain("Attack Path")
    expect(md).toContain("SQLi → XSS")
  })
})

// ── HTML Generator ───────────────────────────────────────────

describe("generateHtml", () => {
  test("produces valid HTML document", () => {
    const html = generateHtml(TEST_FINDINGS, "http://example.com")
    expect(html).toContain("<!DOCTYPE html>")
    expect(html).toContain("</html>")
    expect(html).toContain("<head>")
    expect(html).toContain("<body>")
  })

  test("self-contained: inline CSS, no external resources", () => {
    const html = generateHtml(TEST_FINDINGS, "http://example.com")
    expect(html).toContain("<style>")
    expect(html).not.toContain("cdn.jsdelivr.net")
    expect(html).not.toContain("cdnjs.cloudflare.com")
    expect(html).not.toContain("unpkg.com")
  })

  test("HTML escapes user-generated content", () => {
    const findings = [
      makeFinding({
        title: 'XSS <script>alert("pwned")</script>',
        description: "Description with <b>HTML</b>",
        payload: '"><img onerror=alert(1)>',
      }),
    ]

    const html = generateHtml(findings, "http://example.com")
    expect(html).toContain("&lt;script&gt;")
    expect(html).not.toContain('<script>alert("pwned")</script>')
  })

  test("includes severity badges", () => {
    const html = generateHtml(TEST_FINDINGS, "http://example.com")
    expect(html).toContain("CRITICAL")
    expect(html).toContain("#dc3545")
  })

  test("includes attack chains when provided", () => {
    const chains: ChainGroup[] = [
      {
        id: "CHAIN-001",
        title: "SQLi → XSS",
        severity: "critical",
        impact: "Full compromise",
        findings: TEST_FINDINGS.slice(0, 2),
      },
    ]

    const html = generateHtml(TEST_FINDINGS, "http://example.com", chains)
    expect(html).toContain("Attack Path")
    expect(html).toContain("CHAIN-001")
  })

  test("includes remediation section", () => {
    const html = generateHtml(TEST_FINDINGS, "http://example.com")
    expect(html).toContain("Remediation")
    expect(html).toContain("parameterized queries")
  })

  test("empty findings produce a valid report", () => {
    const html = generateHtml([], "http://example.com")
    expect(html).toContain("<!DOCTYPE html>")
    expect(html).toContain("0")
  })
})
