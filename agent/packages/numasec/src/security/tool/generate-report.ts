/**
 * Tool: generate_report
 *
 * Generate a security assessment report in SARIF, HTML, or Markdown format.
 */

import z from "zod"
import path from "path"
import { mkdir } from "fs/promises"
import { Tool } from "../../tool/tool"
import type { SessionID } from "../../session/schema"
import { and, Database, eq } from "../../storage/db"
import { EvidenceNodeTable } from "../evidence.sql"
import { FindingTable } from "../security.sql"
import { generateSarif, generateMarkdown, generateHtml, calculateRiskScore } from "../report/generators"
import type { ChainGroup } from "../chain-builder"
import * as ChainProjection from "../chain-projection"
import { projectFindings } from "../finding-projector"
import { makeToolResultEnvelope } from "./result-envelope"

type Finding = (typeof FindingTable)["$inferSelect"]

interface ReportProjection {
  all: Finding[]
  verified: Finding[]
  provisional: Finding[]
  suppressed: Finding[]
  chains: ChainGroup[]
  snapshot: ChainProjection.DeriveAttackPathResult
  canonical: {
    input_count: number
    canonical_count: number
    dropped_superseded_ids: string[]
    dropped_duplicate_ids: string[]
  }
  counts: {
    raw: number
    verified: number
    provisional: number
    suppressed: number
    refuted: number
    reportable: number
    promotion_gaps: number
  }
  promotion_gap_ids: string[]
}

interface ClosureStatus {
  hypothesis_open: number
  hypothesis_critical_open: number
  hypothesis_open_ids: string[]
}

function readReportProjection(sessionID: SessionID): ReportProjection {
  const projected = projectFindings(sessionID)
  const verified = ChainProjection.deriveAttackPathProjection({
    sessionID,
    includeFalsePositive: false,
    states: ["verified"],
  })
  const all = projected.rows
  return {
    all,
    verified: verified.findings,
    provisional: all.filter((item) => item.reportable && item.state === "provisional"),
    suppressed: all.filter((item) => item.state === "suppressed" || item.state === "refuted" || !item.reportable),
    chains: verified.chains,
    snapshot: verified,
    canonical: verified.canonical,
    counts: projected.counts,
    promotion_gap_ids: projected.promotion_gap_ids,
  }
}

function readClosureStatus(sessionID: SessionID): ClosureStatus {
  const rows = Database.use((db) =>
    db
      .select()
      .from(EvidenceNodeTable)
      .where(and(eq(EvidenceNodeTable.session_id, sessionID), eq(EvidenceNodeTable.type, "hypothesis")))
      .all(),
  )
  const openStatuses = new Set(["open", "probing", "active", "new"])
  const open: string[] = []
  let critical = 0
  for (const row of rows) {
    if (!openStatuses.has(row.status)) continue
    open.push(row.id)
    if (row.confidence >= 0.75) critical += 1
  }
  return {
    hypothesis_open: open.length,
    hypothesis_critical_open: critical,
    hypothesis_open_ids: open.slice(0, 20),
  }
}

function chooseTargetUrl(findings: Finding[]) {
  const counts = new Map<string, number>()
  for (const finding of findings) {
    const value = (finding.url ?? "").trim()
    if (!value) continue
    counts.set(value, (counts.get(value) ?? 0) + 1)
  }
  let best = ""
  let score = -1
  for (const entry of counts.entries()) {
    if (entry[1] <= score) continue
    best = entry[0]
    score = entry[1]
  }
  return best || "unknown"
}

const DESCRIPTION = `Generate a security assessment report from saved findings.
Formats: sarif (for CI/CD), markdown (for documentation), html (self-contained visual report).

The report includes:
- Executive summary with risk score
- All findings grouped by severity
- CWE/CVSS/OWASP enrichment data
- Evidence and remediation for each finding
- OWASP Top 10 coverage analysis

Call this at the END of an assessment after all findings have been saved.`

export const GenerateReportTool = Tool.define("generate_report", {
  description: DESCRIPTION,
  parameters: z.object({
    format: z.enum(["sarif", "markdown", "html"]).default("markdown").describe("Report format"),
    target_url: z.string().optional().describe("Target URL (auto-detected from findings if omitted)"),
    allow_incomplete: z.boolean().optional().describe("Allow report generation when closure checks fail"),
    incomplete_reason: z.string().optional().describe("Required when allow_incomplete=true and critical hypotheses are still open"),
    output_path: z.string().optional().describe("Optional file path to write the generated report"),
  }),
  async execute(params, ctx) {
    const projection = readReportProjection(ctx.sessionID)
    ChainProjection.persistAttackPathProjection(ctx.sessionID, projection.snapshot)
    const closure = readClosureStatus(ctx.sessionID)
    const truthReasons: string[] = []
    if (closure.hypothesis_critical_open > 0) {
      truthReasons.push(`${closure.hypothesis_critical_open} critical hypothesis/hypotheses still open`)
    }
    if (projection.counts.promotion_gaps > 0) {
      truthReasons.push(`${projection.counts.promotion_gaps} verification(s) not promoted into findings`)
    }
    if (projection.provisional.length > 0) {
      truthReasons.push(`${projection.provisional.length} provisional reportable finding(s) not counted as verified`)
    }
    const incomplete = truthReasons.length > 0
    if (incomplete && params.allow_incomplete !== true) {
      return {
        title: "Report blocked: closure incomplete",
        metadata: {
          closure,
          incomplete,
          truthReasons,
          projection: projection.counts,
        } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [
            {
              type: "report_closure",
              blocked: true,
              open_hypotheses: closure.hypothesis_open,
              open_critical_hypotheses: closure.hypothesis_critical_open,
            },
          ],
          metrics: {
            closure_open_hypotheses: closure.hypothesis_open,
            closure_open_critical_hypotheses: closure.hypothesis_critical_open,
            promotion_gaps: projection.counts.promotion_gaps,
            provisional_reportable_findings: projection.provisional.length,
          },
        }),
        output: [
          "Report generation blocked by closure policy.",
          `Open hypotheses: ${closure.hypothesis_open}`,
          `Open critical hypotheses: ${closure.hypothesis_critical_open}`,
          `Promotion gaps: ${projection.counts.promotion_gaps}`,
          `Provisional reportable findings: ${projection.provisional.length}`,
          ...truthReasons.map((item) => `- ${item}`),
          "Set allow_incomplete=true and provide incomplete_reason to override.",
        ].join("\n"),
      }
    }
    if (incomplete && params.allow_incomplete === true) {
      const reason = (params.incomplete_reason ?? "").trim()
      if (!reason) {
        throw new Error("generate_report requires incomplete_reason when overriding closure policy")
      }
    }

    const findings = projection.verified
    const chains = projection.chains
    const canonical = projection.canonical

    if (projection.all.length === 0) {
      return {
        title: "No findings to report",
        metadata: { count: 0 } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [{ type: "report", generated: false, finding_count: 0 }],
        }),
        output: "No findings saved for this session. Save findings first with save_finding.",
      }
    }

    const targetUrl = params.target_url ?? chooseTargetUrl(projection.all)
    const verifiedRiskScore = calculateRiskScore(findings)
    const upperBoundRiskScore = calculateRiskScore([...findings, ...projection.provisional])
    const reason = incomplete ? (params.incomplete_reason ?? "").trim() : ""

    let report: string
    switch (params.format) {
      case "sarif":
        report = generateSarif(findings, targetUrl, chains, {
          incomplete,
          incomplete_reason: reason || undefined,
          verified_risk_score: verifiedRiskScore,
          upper_bound_risk_score: upperBoundRiskScore,
          provisional: projection.provisional,
          suppressed: projection.suppressed,
          promotion_gaps: projection.counts.promotion_gaps,
        })
        break
      case "html":
        report = generateHtml(findings, targetUrl, chains, {
          incomplete,
          incomplete_reason: reason || undefined,
          verified_risk_score: verifiedRiskScore,
          upper_bound_risk_score: upperBoundRiskScore,
          provisional: projection.provisional,
          suppressed: projection.suppressed,
          promotion_gaps: projection.counts.promotion_gaps,
        })
        break
      case "markdown":
      default:
        report = generateMarkdown(findings, targetUrl, chains, {
          incomplete,
          incomplete_reason: reason || undefined,
          verified_risk_score: verifiedRiskScore,
          upper_bound_risk_score: upperBoundRiskScore,
          provisional: projection.provisional,
          suppressed: projection.suppressed,
          promotion_gaps: projection.counts.promotion_gaps,
        })
        break
    }

    const override = incomplete && params.allow_incomplete === true
    const outputPath = (params.output_path ?? "").trim()
    let savedPath = ""
    if (outputPath) {
      const resolved = path.resolve(outputPath)
      const dir = path.dirname(resolved)
      await mkdir(dir, { recursive: true })
      await Bun.write(Bun.file(resolved), report)
      savedPath = resolved
    }

    return {
      title: `${incomplete ? "[INCOMPLETE] " : ""}Report (${params.format}): ${findings.length} verified${projection.provisional.length > 0 ? ` + ${projection.provisional.length} provisional` : ""}, risk ${verifiedRiskScore}/100${upperBoundRiskScore !== verifiedRiskScore ? ` (upper bound ${upperBoundRiskScore}/100)` : ""}`,
      metadata: {
        format: params.format,
        findings: projection.all.length,
        verifiedFindings: findings.length,
        provisionalFindings: projection.provisional.length,
        suppressedFindings: projection.suppressed.length,
        riskScore: verifiedRiskScore,
        upperBoundRiskScore,
        canonical,
        outputPath: savedPath,
        closure,
        incomplete,
        override,
        overrideReason: reason,
        truthReasons,
        promotionGapIds: projection.promotion_gap_ids,
        projection: projection.counts,
      } as any,
      envelope: makeToolResultEnvelope({
        status: incomplete ? "inconclusive" : "ok",
        artifacts: [
          {
            type: "report",
            format: params.format,
            target_url: targetUrl,
            output_path: savedPath || undefined,
          },
        ],
        observations: [
          ...findings.map((item) => ({
            type: "finding",
            finding_id: item.id,
            severity: item.severity,
            chain_id: item.chain_id,
            state: item.state,
          })),
          ...projection.provisional.map((item) => ({
            type: "finding_provisional",
            finding_id: item.id,
            severity: item.severity,
            state: item.state,
          })),
          {
            type: "report_closure",
            blocked: false,
            incomplete,
            override,
            open_hypotheses: closure.hypothesis_open,
            open_critical_hypotheses: closure.hypothesis_critical_open,
            promotion_gaps: projection.counts.promotion_gaps,
            provisional_reportable_findings: projection.provisional.length,
          },
          ...(reason
            ? [
                {
                  type: "report_override",
                  reason,
                },
              ]
            : []),
        ],
        metrics: {
          finding_count: projection.all.length,
          verified_finding_count: findings.length,
          provisional_finding_count: projection.provisional.length,
          suppressed_finding_count: projection.suppressed.length,
          risk_score: verifiedRiskScore,
          upper_bound_risk_score: upperBoundRiskScore,
          chain_count: chains.length,
          canonical_input_count: canonical.input_count,
          canonical_count: canonical.canonical_count,
          canonical_dropped_superseded: canonical.dropped_superseded_ids.length,
          canonical_dropped_duplicates: canonical.dropped_duplicate_ids.length,
          closure_open_hypotheses: closure.hypothesis_open,
          closure_open_critical_hypotheses: closure.hypothesis_critical_open,
          closure_incomplete: incomplete ? 1 : 0,
          promotion_gaps: projection.counts.promotion_gaps,
        },
      }),
      output: savedPath
        ? `${report}\n\n---\nSaved report to: ${savedPath}`
        : report,
    }
  },
})
