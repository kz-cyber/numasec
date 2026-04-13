import type { Part } from "@numasec/sdk/v2"

type SecurityClient = {
  client?: {
    get: (input: { url: string }) => Promise<{ data?: unknown }>
  }
}

export type SecurityReadState = {
  scope?: unknown
  findings?: unknown
  chains?: unknown
  coverage?: unknown
}

export type SecurityMessage = {
  id: string
  role: string
}

export type SecurityFinding = {
  id: string
  title: string
  severity: string
  url: string
  parameter: string
  payload: string
  evidence: string
  cwe_id: string
  owasp_category: string
  confidence: string
  chain_id: string
  tool_used: string
  description: string
  cvss_score: string
}

export type SecurityChain = {
  chain_id: string
  severity: string
  items: Array<{ title: string; sev: string }>
}

export const OWASP_CATEGORIES = [
  "A01",
  "A02",
  "A03",
  "A04",
  "A05",
  "A06",
  "A07",
  "A08",
  "A09",
  "A10",
] as const

export type SecurityCoverage = {
  tested: Set<string>
  vulnerable: Set<string>
  testedCount: number
  total: number
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const
type Severity = (typeof SEVERITY_ORDER)[number]
const CATEGORY_RE = /A0[1-9]|A10/g

const TOOL_TO_OWASP: Record<string, string[]> = {
  access_control_test: ["A01", "A08"],
  auth_test: ["A01", "A02", "A07"],
  injection_test: ["A03", "A04", "A07"],
  xss_test: ["A03"],
  ssrf_test: ["A10"],
  path_test: ["A03", "A10"],
  recon: ["A05", "A06", "A09"],
  crawl: ["A05"],
  js_analyze: ["A05"],
  dir_fuzz: ["A05"],
  upload_test: ["A04"],
}

function asObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value)
  } catch {
    return
  }
}

function normalizeSeverity(value: string): Severity {
  const next = value.toLowerCase()
  if (next === "critical") return next
  if (next === "high") return next
  if (next === "medium") return next
  if (next === "low") return next
  return "info"
}

function severityRank(value: string) {
  const next = normalizeSeverity(value)
  if (next === "critical") return 0
  if (next === "high") return 1
  if (next === "medium") return 2
  if (next === "low") return 3
  return 4
}

function findingFrom(raw: Record<string, unknown>): SecurityFinding {
  return {
    id: String(raw.id ?? raw.finding_id ?? ""),
    title: String(raw.title ?? "Untitled"),
    severity: normalizeSeverity(String(raw.severity ?? "info")),
    url: String(raw.url ?? ""),
    parameter: String(raw.parameter ?? ""),
    payload: String(raw.payload ?? ""),
    evidence: String(raw.evidence ?? raw.description ?? ""),
    cwe_id: String(raw.cwe_id ?? raw.cwe ?? ""),
    owasp_category: String(raw.owasp_category ?? ""),
    confidence: String(raw.confidence ?? ""),
    chain_id: String(raw.chain_id ?? ""),
    tool_used: String(raw.tool_used ?? ""),
    description: String(raw.description ?? ""),
    cvss_score: String(raw.cvss_score ?? ""),
  }
}

function sortFindings(list: SecurityFinding[]) {
  list.sort((a, b) => {
    const ai = severityRank(a.severity)
    const bi = severityRank(b.severity)
    return ai - bi
  })
  return list
}

function addFinding(list: SecurityFinding[], seen: Set<string>, raw: Record<string, unknown>) {
  const finding = findingFrom(raw)
  if (finding.id && seen.has(finding.id)) return
  if (finding.id) seen.add(finding.id)
  list.push(finding)
}

function emptyCoverage(): SecurityCoverage {
  return {
    tested: new Set<string>(),
    vulnerable: new Set<string>(),
    testedCount: 0,
    total: OWASP_CATEGORIES.length,
  }
}

function coverageWithSets(tested: Set<string>, vulnerable: Set<string>): SecurityCoverage {
  return {
    tested,
    vulnerable,
    testedCount: tested.size,
    total: OWASP_CATEGORIES.length,
  }
}

function matches(value: string) {
  return value.match(CATEGORY_RE) ?? []
}

function addChain(map: Record<string, SecurityChain>, chainID: string, title: string, sev: string) {
  if (!map[chainID]) {
    map[chainID] = {
      chain_id: chainID,
      severity: "info",
      items: [],
    }
  }
  const chain = map[chainID]
  if (!chain.items.some((item) => item.title === title)) {
    chain.items.push({ title, sev: normalizeSeverity(sev) })
  }
  const next = normalizeSeverity(sev)
  if (severityRank(next) < severityRank(chain.severity)) {
    chain.severity = next
  }
}

export async function readCanonicalSecurity(client: unknown, sessionID: string) {
  const sdk = client as SecurityClient
  if (!sdk.client) return
  const response = await sdk.client.get({ url: `/security/${sessionID}/read` }).catch(() => undefined)
  if (!response?.data) return
  if (!asObject(response.data)) return
  return response.data as SecurityReadState
}

export function fallbackFindings(messages: readonly SecurityMessage[], parts: Record<string, Part[]>) {
  const list: SecurityFinding[] = []
  const seen = new Set<string>()

  for (const message of messages) {
    const all = parts[message.id]
    if (!all) continue
    for (const part of all) {
      if (part.type !== "tool") continue
      if (part.state.status !== "completed") continue
      const output = (part.state as { output?: string }).output
      if (!output) continue

      if (part.tool.includes("get_findings")) {
        const data = parseJson(output)
        if (!asObject(data)) continue
        const findings = data.findings
        if (!Array.isArray(findings)) continue
        for (const item of findings) {
          if (!asObject(item)) continue
          addFinding(list, seen, item)
        }
        continue
      }

      if (part.tool.includes("save_finding")) {
        const data = parseJson(output)
        if (!asObject(data)) continue
        const finding = asObject(data.finding) ? data.finding : data
        addFinding(list, seen, finding)
        continue
      }

      const data = parseJson(output)
      if (!asObject(data)) continue
      const findings = data.findings_auto_saved
      if (!Array.isArray(findings)) continue
      for (const item of findings) {
        if (!asObject(item)) continue
        addFinding(list, seen, item)
      }
    }
  }

  return sortFindings(list)
}

export function fallbackChains(
  messages: readonly SecurityMessage[],
  parts: Record<string, Part[]>,
  findings: SecurityFinding[],
) {
  const map: Record<string, SecurityChain> = {}

  for (const finding of findings) {
    if (!finding.chain_id) continue
    const title = finding.title || finding.id || "Finding"
    addChain(map, finding.chain_id, title, finding.severity)
  }

  for (const message of messages) {
    const all = parts[message.id]
    if (!all) continue
    for (const part of all) {
      if (part.type !== "tool") continue
      if (part.state.status !== "completed") continue
      if (!part.tool.includes("build_chains") && !part.tool.includes("generate_report")) continue
      const output = (part.state as { output?: string }).output
      if (!output) continue
      const data = parseJson(output)
      if (!asObject(data)) continue

      if (Array.isArray(data.findings)) {
        for (const entry of data.findings) {
          if (!asObject(entry)) continue
          const chainID = String(entry.chain_id ?? "")
          if (!chainID) continue
          const title = String(entry.title ?? "Finding")
          const sev = String(entry.severity ?? "info")
          addChain(map, chainID, title, sev)
        }
      }

      if (!asObject(data.chains)) continue
      for (const item of Object.entries(data.chains)) {
        const chainID = item[0]
        const ids = item[1]
        if (!Array.isArray(ids)) continue
        if (!map[chainID]) {
          map[chainID] = {
            chain_id: chainID,
            severity: "info",
            items: [],
          }
        }
        if (map[chainID].items.length > 0) continue
        for (const id of ids) {
          if (typeof id !== "string") continue
          addChain(map, chainID, id, "info")
        }
      }
    }
  }

  return Object.values(map).filter((chain) => chain.items.length > 1)
}

export function fallbackTarget(messages: readonly SecurityMessage[], parts: Record<string, Part[]>) {
  for (const message of messages) {
    const all = parts[message.id]
    if (!all) continue
    for (const part of all) {
      if (part.type !== "tool") continue
      if (!part.tool.includes("create_session") && !part.tool.includes("recon")) continue
      const state = part.state as { input?: Record<string, unknown> }
      const url = state.input?.target ?? state.input?.url ?? state.input?.base_url
      if (typeof url !== "string") continue
      if (url.startsWith("http")) return url
    }
  }
  return undefined
}

export function fallbackCoverage(messages: readonly SecurityMessage[], parts: Record<string, Part[]>) {
  const tested = new Set<string>()
  const vulnerable = new Set<string>()

  for (const message of messages) {
    const all = parts[message.id]
    if (!all) continue
    for (const part of all) {
      if (part.type !== "tool") continue
      if (part.state.status !== "completed") continue
      const output = (part.state as { output?: string }).output
      if (!output) continue

      if (part.tool.includes("save_finding") || part.tool.includes("get_findings")) {
        for (const category of matches(output)) {
          tested.add(category)
          vulnerable.add(category)
        }
        continue
      }

      if (part.tool.includes("plan")) {
        for (const category of matches(output)) {
          tested.add(category)
        }
        const data = parseJson(output)
        if (!asObject(data)) continue
        const coverage = asObject(data.coverage) ? data.coverage : undefined
        if (!coverage) continue
        if (!Array.isArray(coverage.covered_categories)) continue
        for (const category of coverage.covered_categories) {
          if (typeof category !== "string") continue
          tested.add(category)
        }
        continue
      }

      const toolName = part.tool.split("/").pop() ?? ""
      for (const entry of Object.entries(TOOL_TO_OWASP)) {
        if (!toolName.includes(entry[0])) continue
        for (const category of entry[1]) {
          tested.add(category)
        }
      }

      const data = parseJson(output)
      if (!asObject(data)) continue
      if (!Array.isArray(data.findings_auto_saved)) continue
      for (const entry of data.findings_auto_saved) {
        if (!asObject(entry)) continue
        const category = String(entry.owasp_category ?? "")
        for (const match of matches(category)) {
          tested.add(match)
          vulnerable.add(match)
        }
      }
    }
  }

  return coverageWithSets(tested, vulnerable)
}

export function canonicalFindings(state: SecurityReadState | undefined) {
  if (!state) return []
  if (!Array.isArray(state.findings)) return []
  const list: SecurityFinding[] = []
  for (const entry of state.findings) {
    if (!asObject(entry)) continue
    list.push(findingFrom(entry))
  }
  return sortFindings(list)
}

export function canonicalChains(state: SecurityReadState | undefined, findings: SecurityFinding[]) {
  if (!state) return []
  const map: Record<string, SecurityChain> = {}

  for (const finding of findings) {
    if (!finding.chain_id) continue
    const title = finding.title || finding.id || "Finding"
    addChain(map, finding.chain_id, title, finding.severity)
  }

  if (Object.keys(map).length > 0) {
    return Object.values(map).filter((chain) => chain.items.length > 1)
  }

  if (!Array.isArray(state.chains)) return []
  for (const entry of state.chains) {
    if (!asObject(entry)) continue
    const chainID = String(entry.chain_id ?? "")
    if (!chainID) continue
    const severity = String(entry.severity ?? "info")
    if (!Array.isArray(entry.finding_ids)) continue
    for (const id of entry.finding_ids) {
      if (typeof id !== "string") continue
      addChain(map, chainID, id, severity)
    }
  }

  return Object.values(map).filter((chain) => chain.items.length > 1)
}

export function canonicalTarget(state: SecurityReadState | undefined) {
  if (!state) return

  if (Array.isArray(state.scope)) {
    for (const item of state.scope) {
      if (typeof item !== "string") continue
      if (item.startsWith("http")) return item
    }
  }

  if (Array.isArray(state.findings)) {
    for (const finding of state.findings) {
      if (!asObject(finding)) continue
      const url = finding.url
      if (typeof url !== "string") continue
      if (url.startsWith("http")) return url
    }
  }

  if (!Array.isArray(state.chains)) return
  for (const chain of state.chains) {
    if (!asObject(chain)) continue
    if (!Array.isArray(chain.urls)) continue
    for (const url of chain.urls) {
      if (typeof url !== "string") continue
      if (url.startsWith("http")) return url
    }
  }
}

export function canonicalCoverage(state: SecurityReadState | undefined, findings: SecurityFinding[]) {
  if (!state) return emptyCoverage()
  const tested = new Set<string>()
  const vulnerable = new Set<string>()

  if (Array.isArray(state.coverage)) {
    for (const entry of state.coverage) {
      if (!asObject(entry)) continue
      const category = String(entry.category ?? "")
      const testedFlag = Boolean(entry.tested)
      const count = Number(entry.finding_count ?? 0)
      for (const item of matches(category)) {
        if (testedFlag || count > 0) tested.add(item)
        if (count > 0) vulnerable.add(item)
      }
    }
  }

  for (const finding of findings) {
    if (!finding.owasp_category) continue
    for (const item of matches(finding.owasp_category)) {
      tested.add(item)
      vulnerable.add(item)
    }
  }

  return coverageWithSets(tested, vulnerable)
}

function hasCoverage(value: SecurityCoverage) {
  if (value.tested.size > 0) return true
  if (value.vulnerable.size > 0) return true
  return false
}

export function selectFindings(state: SecurityReadState | undefined, fallback: SecurityFinding[]) {
  if (!state) return fallback
  const canonical = canonicalFindings(state)
  if (canonical.length > 0) return canonical
  if (fallback.length > 0) return fallback
  return canonical
}

export function selectChains(
  state: SecurityReadState | undefined,
  fallback: SecurityChain[],
  findings: SecurityFinding[],
) {
  if (!state) return fallback
  const canonical = canonicalChains(state, findings)
  if (canonical.length > 0) return canonical
  if (fallback.length > 0) return fallback
  return canonical
}

export function selectTarget(state: SecurityReadState | undefined, fallback: string | undefined) {
  if (!state) return fallback
  const canonical = canonicalTarget(state)
  if (canonical) return canonical
  return fallback
}

export function selectCoverage(
  state: SecurityReadState | undefined,
  fallback: SecurityCoverage,
  findings: SecurityFinding[],
) {
  if (!state) return fallback
  const canonical = canonicalCoverage(state, findings)
  if (hasCoverage(canonical)) return canonical
  if (hasCoverage(fallback)) return fallback
  return canonical
}

export function findingCounts(findings: SecurityFinding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const finding of findings) {
    const severity = normalizeSeverity(finding.severity)
    counts[severity] += 1
  }
  return counts
}
