import type { PlannerEvent, PlannerState } from "./kernel"

type Scope = "quick" | "standard" | "deep"

interface NormalizeInput {
  event_type?: string
  event?: string
  event_payload?: Record<string, unknown>
  target?: string
  scope?: Scope
  hypothesis_id?: string
  finding_id?: string
  evidence_nodes?: string[]
}

export interface NormalizeResult {
  raw_type: string
  canonical_type: PlannerEvent["type"] | ""
  event?: PlannerEvent
  warnings: string[]
}

const ALIAS = new Map<string, PlannerEvent["type"]>([
  ["scope_set", "scope_set"],
  ["scope", "scope_set"],
  ["set_scope", "scope_set"],
  ["scope_defined", "scope_set"],
  ["hypothesis_upserted", "hypothesis_upserted"],
  ["hypothesis", "hypothesis_upserted"],
  ["hypothesis_open", "hypothesis_upserted"],
  ["hypothesis_created", "hypothesis_upserted"],
  ["hypothesis_updated", "hypothesis_upserted"],
  ["evidence_recorded", "evidence_recorded"],
  ["evidence", "evidence_recorded"],
  ["observation_recorded", "evidence_recorded"],
  ["observation", "evidence_recorded"],
  ["verification_recorded", "verification_recorded"],
  ["verification", "verification_recorded"],
  ["assertion_verified", "verification_recorded"],
  ["decision_made", "decision_made"],
  ["decision", "decision_made"],
  ["verdict", "decision_made"],
  ["finding_recorded", "decision_made"],
  ["hypothesis_invalidated", "hypothesis_invalidated"],
  ["invalidated", "hypothesis_invalidated"],
  ["hypothesis_rejected", "hypothesis_invalidated"],
  ["reset", "reset"],
  ["restart", "reset"],
])

function stringValue(input: unknown): string {
  if (typeof input === "string") return input
  return ""
}

function boolValue(input: unknown): boolean | undefined {
  if (typeof input === "boolean") return input
  const value = stringValue(input).toLowerCase()
  if (["true", "1", "yes", "ok", "pass", "passed"].includes(value)) return true
  if (["false", "0", "no", "fail", "failed"].includes(value)) return false
  return
}

function scopeValue(input: unknown): Scope {
  const value = stringValue(input)
  if (value === "quick" || value === "deep") return value
  return "standard"
}

function relationValue(input: unknown): "supports" | "refutes" | "observes" {
  const value = stringValue(input).toLowerCase()
  if (["support", "supports", "positive"].includes(value)) return "supports"
  if (["refute", "refutes", "negative"].includes(value)) return "refutes"
  return "observes"
}

function verdictValue(input: unknown): "confirmed" | "rejected" | "inconclusive" {
  if (typeof input === "boolean") return input ? "confirmed" : "rejected"
  const value = stringValue(input).toLowerCase()
  if (["confirmed", "confirm", "positive", "pass", "passed", "true"].includes(value)) return "confirmed"
  if (["rejected", "reject", "negative", "fail", "failed", "false"].includes(value)) return "rejected"
  return "inconclusive"
}

function nodeID(payload: Record<string, unknown>, input: NormalizeInput): string {
  const direct =
    stringValue(payload.node_id) ||
    stringValue(payload.evidence_node_id) ||
    stringValue(payload.evidence_id) ||
    stringValue(payload.observation_node_id) ||
    stringValue(payload.verification_node_id)
  if (direct) return direct
  const fallback = input.evidence_nodes?.[0]
  return typeof fallback === "string" ? fallback : ""
}

function eventType(input: NormalizeInput): { raw: string; canonical: PlannerEvent["type"] | "" } {
  const raw = (input.event_type ?? input.event ?? "").trim()
  if (!raw) return { raw: "", canonical: "" }
  const key = raw.toLowerCase().replaceAll("-", "_").replaceAll(" ", "_")
  const canonical = ALIAS.get(key) ?? ""
  return { raw, canonical }
}

function objectPayload(input: NormalizeInput): Record<string, unknown> {
  const payload = input.event_payload ?? {}
  if (typeof payload === "object" && payload !== null && !Array.isArray(payload)) {
    return payload as Record<string, unknown>
  }
  return {}
}

export function normalizePlannerEvent(input: NormalizeInput): NormalizeResult {
  const warnings: string[] = []
  const type = eventType(input)
  if (!type.raw) {
    return {
      raw_type: "",
      canonical_type: "",
      warnings,
    }
  }
  if (!type.canonical) {
    throw new Error(`plan_next received unsupported event type: ${type.raw}`)
  }
  if (type.raw.toLowerCase().replaceAll("-", "_").replaceAll(" ", "_") !== type.canonical) {
    warnings.push(`normalized event '${type.raw}' -> '${type.canonical}'`)
  }

  const payload = objectPayload(input)

  if (type.canonical === "reset") {
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: { type: "reset" },
      warnings,
    }
  }

  if (type.canonical === "scope_set") {
    const target = stringValue(payload.target) || input.target || ""
    if (!target) throw new Error("plan_next requires target for scope_set event")
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "scope_set",
        target,
        scope: scopeValue(payload.scope || input.scope),
      },
      warnings,
    }
  }

  if (type.canonical === "hypothesis_upserted") {
    const hypothesisID = stringValue(payload.hypothesis_id) || input.hypothesis_id || ""
    if (!hypothesisID) throw new Error("plan_next requires hypothesis_id for hypothesis_upserted event")
    const summary = stringValue(payload.summary) || stringValue(payload.statement) || stringValue(payload.predicate)
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "hypothesis_upserted",
        hypothesis_id: hypothesisID,
        summary,
      },
      warnings,
    }
  }

  if (type.canonical === "evidence_recorded") {
    const node = nodeID(payload, input)
    if (!node) throw new Error("plan_next requires node_id for evidence_recorded event")
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "evidence_recorded",
        node_id: node,
        relation: relationValue(payload.relation || payload.signal || payload.link_type),
      },
      warnings,
    }
  }

  if (type.canonical === "verification_recorded") {
    const node = nodeID(payload, input)
    if (!node) throw new Error("plan_next requires node_id for verification_recorded event")
    const passedValue =
      boolValue(payload.passed) ??
      boolValue(payload.success) ??
      boolValue(payload.ok) ??
      boolValue(payload.verified) ??
      false
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "verification_recorded",
        node_id: node,
        passed: passedValue,
      },
      warnings,
    }
  }

  if (type.canonical === "decision_made") {
    const verdict = verdictValue(payload.verdict ?? payload.decision ?? payload.status ?? payload.confirmed)
    const findingID = stringValue(payload.finding_id) || input.finding_id || undefined
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "decision_made",
        verdict,
        finding_id: findingID,
      },
      warnings,
    }
  }

  const reason = stringValue(payload.reason) || stringValue(payload.note) || "invalidated"
  return {
    raw_type: type.raw,
    canonical_type: "hypothesis_invalidated",
    event: {
      type: "hypothesis_invalidated",
      reason,
    },
    warnings,
  }
}

export function plannerStateOrDefault(input: unknown): PlannerState {
  if (
    input === "idle" ||
    input === "scope_defined" ||
    input === "hypothesis_open" ||
    input === "evidence_collecting" ||
    input === "decision_pending" ||
    input === "closed_positive" ||
    input === "closed_negative"
  ) {
    return input
  }
  return "idle"
}
