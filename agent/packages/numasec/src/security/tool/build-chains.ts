/**
 * Tool: build_chains
 *
 * Build attack chains from saved findings. Groups related findings
 * that together form a more impactful attack scenario.
 * Also populates CoverageTable with OWASP coverage data.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { Database, eq } from "../../storage/db"
import { FindingTable, CoverageTable } from "../security.sql"
import { buildChainGroups } from "../chain-builder"

const DESCRIPTION = `Build attack chains from saved findings.
Groups related findings by URL path and vulnerability relationships into attack narratives.

Example chain: SQLi → Data Leak → Account Takeover
Each chain represents a complete attack path that demonstrates business impact.

Call this after you've saved multiple findings to see the bigger picture.`

export const BuildChainsTool = Tool.define("build_chains", {
  description: DESCRIPTION,
  parameters: z.object({}),
  async execute(_params, ctx) {
    const findings = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, ctx.sessionID))
        .all(),
    )

    if (findings.length < 2) {
      return {
        title: "Not enough findings to build chains",
        metadata: { chains: 0, findings: findings.length } as any,
        output:
          findings.length === 0
            ? "No findings saved yet."
            : "Only 1 finding saved. Need 2+ related findings to form a chain.",
      }
    }

    const chains = buildChainGroups(findings)

    // Update chain_id on findings
    for (const chain of chains) {
      for (const f of chain.findings) {
        Database.use((db) =>
          db
            .update(FindingTable)
            .set({ chain_id: chain.id })
            .where(eq(FindingTable.id, f.id))
            .run(),
        )
      }
    }

    // Populate OWASP CoverageTable
    const owaspCounts = new Map<string, number>()
    for (const f of findings) {
      if (!f.owasp_category) continue
      owaspCounts.set(f.owasp_category, (owaspCounts.get(f.owasp_category) ?? 0) + 1)
    }

    // Clear existing coverage for session, then insert fresh
    Database.use((db) =>
      db.delete(CoverageTable).where(eq(CoverageTable.session_id, ctx.sessionID)).run(),
    )

    for (const [category, count] of owaspCounts) {
      Database.use((db) =>
        db
          .insert(CoverageTable)
          .values({
            session_id: ctx.sessionID,
            category,
            tested: true,
            finding_count: count,
          })
          .run(),
      )
    }

    const parts: string[] = [`── ${chains.length} Attack Chain(s) ──`, ""]
    for (const chain of chains) {
      const icon = chain.severity === "critical" ? "🔴" : chain.severity === "high" ? "🟠" : "🟡"
      parts.push(`${icon} ${chain.id}: ${chain.title}`)
      parts.push(`   Severity: ${chain.severity.toUpperCase()} | Impact: ${chain.impact}`)
      for (const f of chain.findings) {
        parts.push(`   ├── [${f.severity.toUpperCase()}] ${f.title}`)
        parts.push(`   │   ${f.url}`)
      }
      parts.push("")
    }

    // Unchained findings
    const chainedIds = new Set(chains.flatMap((c) => c.findings.map((f) => f.id)))
    const unchained = findings.filter((f) => !chainedIds.has(f.id))
    if (unchained.length > 0) {
      parts.push(`── ${unchained.length} Standalone Finding(s) ──`)
      for (const f of unchained) {
        parts.push(`   [${f.severity.toUpperCase()}] ${f.title}`)
      }
    }

    // OWASP coverage summary
    if (owaspCounts.size > 0) {
      parts.push("")
      parts.push(`── OWASP Top 10 Coverage: ${owaspCounts.size}/10 categories ──`)
      for (const [cat, count] of owaspCounts) {
        parts.push(`   ${cat}: ${count} finding(s)`)
      }
    }

    return {
      title: `${chains.length} attack chain(s) from ${findings.length} findings`,
      metadata: { chains: chains.length, findings: findings.length, unchained: unchained.length, owaspCoverage: owaspCounts.size } as any,
      output: parts.join("\n"),
    }
  },
})
