export type PlannerState =
  | "idle"
  | "scope_defined"
  | "hypothesis_open"
  | "evidence_collecting"
  | "decision_pending"
  | "closed_positive"
  | "closed_negative"

export type PlannerVerdict = "confirmed" | "rejected" | "inconclusive"

export type PlannerEvent =
  | {
      type: "scope_set"
      target: string
      scope: "quick" | "standard" | "deep"
    }
  | {
      type: "hypothesis_upserted"
      hypothesis_id: string
      summary: string
    }
  | {
      type: "evidence_recorded"
      node_id: string
      relation: "supports" | "refutes" | "observes"
    }
  | {
      type: "verification_recorded"
      node_id: string
      passed: boolean
    }
  | {
      type: "decision_made"
      verdict: PlannerVerdict
      finding_id?: string
    }
  | {
      type: "hypothesis_invalidated"
      reason: string
    }
  | {
      type: "reset"
    }

export interface PlannerKernel {
  state: PlannerState
  target: string
  scope: "quick" | "standard" | "deep"
  hypothesis_id: string
  finding_id: string
  evidence_nodes: string[]
  notes: string[]
  history: PlannerEvent[]
}

export interface PlannerStep {
  primitive: string
  description: string
}

const INITIAL_SCOPE: "quick" | "standard" | "deep" = "standard"

export function createPlannerKernel(): PlannerKernel {
  return {
    state: "idle",
    target: "",
    scope: INITIAL_SCOPE,
    hypothesis_id: "",
    finding_id: "",
    evidence_nodes: [],
    notes: [],
    history: [],
  }
}

function withHistory(kernel: PlannerKernel, event: PlannerEvent): PlannerKernel {
  return {
    ...kernel,
    history: [...kernel.history, event],
  }
}

export function applyPlannerEvent(kernel: PlannerKernel, event: PlannerEvent): PlannerKernel {
  if (event.type === "reset") return withHistory(createPlannerKernel(), event)

  if (event.type === "scope_set") {
    const next = {
      ...kernel,
      state: "scope_defined" as const,
      target: event.target,
      scope: event.scope,
    }
    return withHistory(next, event)
  }

  if (event.type === "hypothesis_upserted") {
    const next = {
      ...kernel,
      state: "hypothesis_open" as const,
      hypothesis_id: event.hypothesis_id,
      finding_id: "",
      evidence_nodes: [],
    }
    return withHistory(next, event)
  }

  if (event.type === "evidence_recorded") {
    const nodeSet = new Set(kernel.evidence_nodes)
    nodeSet.add(event.node_id)
    const next = {
      ...kernel,
      state: "evidence_collecting" as const,
      evidence_nodes: Array.from(nodeSet),
    }
    return withHistory(next, event)
  }

  if (event.type === "verification_recorded") {
    const nodeSet = new Set(kernel.evidence_nodes)
    nodeSet.add(event.node_id)
    const next = {
      ...kernel,
      state: "decision_pending" as const,
      evidence_nodes: Array.from(nodeSet),
    }
    return withHistory(next, event)
  }

  if (event.type === "decision_made") {
    if (event.verdict === "confirmed") {
      const next = {
        ...kernel,
        state: "closed_positive" as const,
        finding_id: event.finding_id ?? "",
      }
      return withHistory(next, event)
    }
    if (event.verdict === "rejected") {
      const next = {
        ...kernel,
        state: "closed_negative" as const,
        finding_id: "",
      }
      return withHistory(next, event)
    }
    const next = {
      ...kernel,
      state: "hypothesis_open" as const,
      finding_id: "",
    }
    return withHistory(next, event)
  }

  if (event.type === "hypothesis_invalidated") {
    const next = {
      ...kernel,
      state: "closed_negative" as const,
      notes: [...kernel.notes, event.reason],
      finding_id: "",
    }
    return withHistory(next, event)
  }

  return withHistory(kernel, event)
}

export function nextPlannerStep(kernel: PlannerKernel): PlannerStep {
  if (kernel.state === "idle") {
    return {
      primitive: "plan_next",
      description: "Define scope and target before generating hypotheses",
    }
  }
  if (kernel.state === "scope_defined") {
    return {
      primitive: "upsert_hypothesis",
      description: "Generate or refine a hypothesis for the current scope",
    }
  }
  if (kernel.state === "hypothesis_open") {
    return {
      primitive: "observe_surface",
      description: "Collect observations and convert them into evidence nodes",
    }
  }
  if (kernel.state === "evidence_collecting") {
    return {
      primitive: "verify_assertion",
      description: "Run verification against collected evidence and hypothesis",
    }
  }
  if (kernel.state === "decision_pending") {
    return {
      primitive: "upsert_finding",
      description: "Decide and persist finding status from verification outcome",
    }
  }
  if (kernel.state === "closed_positive") {
    return {
      primitive: "derive_attack_paths",
      description: "Link confirmed findings into attack paths and chains",
    }
  }
  return {
    primitive: "plan_next",
    description: "Open a new hypothesis or close the session with negative result",
  }
}

export function plannerIsTerminal(kernel: PlannerKernel): boolean {
  return kernel.state === "closed_positive" || kernel.state === "closed_negative"
}
