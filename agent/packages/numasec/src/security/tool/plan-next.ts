import z from "zod"
import { Tool } from "../../tool/tool"
import { applyPlannerEvent, createPlannerKernel, type PlannerEvent, type PlannerKernel } from "../planner/kernel"
import { normalizePlannerEvent, plannerStateOrDefault } from "../planner/event-normalizer"
import { selectPlannerPrimitives } from "../planner/policy"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Advance the deterministic planner kernel and return the next primitive action.
Use this to move between scope, hypothesis, evidence, decision, and closure states.`

const STATE = z.enum([
  "idle",
  "scope_defined",
  "hypothesis_open",
  "evidence_collecting",
  "decision_pending",
  "closed_positive",
  "closed_negative",
])

const POLICY_SIGNAL = z.enum(["waf_detected", "auth_obtained", "escalation_found", "spa_detected", "api_app_detected"])

const PlanNextParameters = z.object({
  state: STATE.optional(),
  target: z.string().optional(),
  scope: z.enum(["quick", "standard", "deep"]).optional(),
  hypothesis_id: z.string().optional(),
  finding_id: z.string().optional(),
  evidence_nodes: z.array(z.string()).optional(),
  notes: z.array(z.string()).optional(),
  event_type: z.string().optional(),
  event: z.string().optional(),
  event_payload: z.record(z.string(), z.any()).optional(),
  event_payload_json: z.string().optional(),
  policy_signals: z.array(POLICY_SIGNAL).optional(),
  remaining_seconds: z.number().int().min(1).optional(),
  primitive_budget: z.number().int().min(1).max(4).optional(),
})

function readKernel(params: z.infer<typeof PlanNextParameters>) {
  const value = createPlannerKernel()
  if (!params.state) return value
  return {
    ...value,
    state: plannerStateOrDefault(params.state),
    target: params.target ?? "",
    scope: params.scope ?? "standard",
    hypothesis_id: params.hypothesis_id ?? "",
    finding_id: params.finding_id ?? "",
    evidence_nodes: params.evidence_nodes ?? [],
    notes: params.notes ?? [],
  } satisfies PlannerKernel
}

function readEventPayload(params: z.infer<typeof PlanNextParameters>): Record<string, unknown> | undefined {
  if (params.event_payload) return params.event_payload
  const text = params.event_payload_json
  if (!text) return
  const value = JSON.parse(text)
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  throw new Error("plan_next event_payload_json must decode to an object")
}

function readEvent(params: z.infer<typeof PlanNextParameters>): {
  event?: PlannerEvent
  rawType: string
  canonicalType: string
  warnings: string[]
} {
  const normalized = normalizePlannerEvent({
    event_type: params.event_type,
    event: params.event,
    event_payload: readEventPayload(params),
    target: params.target,
    scope: params.scope,
    hypothesis_id: params.hypothesis_id,
    finding_id: params.finding_id,
    evidence_nodes: params.evidence_nodes,
  })
  return {
    event: normalized.event,
    rawType: normalized.raw_type,
    canonicalType: normalized.canonical_type,
    warnings: normalized.warnings,
  }
}

export const PlanNextTool = Tool.define("plan_next", {
  description: DESCRIPTION,
  parameters: PlanNextParameters,
  async execute(params) {
    const current = readKernel(params)
    const event = readEvent(params)
    const next = event.event ? applyPlannerEvent(current, event.event) : current
    const policy = selectPlannerPrimitives(next, {
      signals: params.policy_signals,
      budget: {
        remaining_seconds: params.remaining_seconds,
        primitive_budget: params.primitive_budget,
      },
    })
    const step = policy.primary
    const queue = policy.steps.map((item) => item.primitive)

    return {
      title: `Planner: ${next.state} -> ${step.primitive}`,
      metadata: {
        state: next.state,
        primitive: step.primitive,
        policyPrimitives: queue,
        budgetSeconds: policy.budget.remaining_seconds,
        budgetPrimitives: policy.budget.primitive_budget,
        evidenceSupports: policy.evidence.supports,
        evidenceRefutes: policy.evidence.refutes,
        verificationPassed: policy.evidence.verification_passed,
        hypothesis: next.hypothesis_id,
        evidenceNodes: next.evidence_nodes.length,
        eventRaw: event.rawType,
        eventCanonical: event.canonicalType,
        eventWarnings: event.warnings,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
          {
            type: "planner_state",
            state: next.state,
            primitive: step.primitive,
          },
          {
            type: "planner_policy",
            primitives: queue,
            supports: policy.evidence.supports,
            refutes: policy.evidence.refutes,
            observes: policy.evidence.observes,
            budget_seconds: policy.budget.remaining_seconds,
            primitive_budget: policy.budget.primitive_budget,
          },
        ],
        verifications:
          event.event && event.canonicalType
            ? [
                {
                  type: "planner_event",
                  raw_event: event.rawType,
                  canonical_event: event.canonicalType,
                  warning_count: event.warnings.length,
                },
              ]
            : [],
        metrics: {
          evidence_supports: policy.evidence.supports,
          evidence_refutes: policy.evidence.refutes,
          evidence_observes: policy.evidence.observes,
          policy_primitives: queue.length,
          policy_budget_seconds: policy.budget.remaining_seconds,
          policy_budget_primitives: policy.budget.primitive_budget,
          planner_event_warnings: event.warnings.length,
        },
      }),
      output: [
        `State: ${next.state}`,
        `Next primitive: ${step.primitive}`,
        `Policy sequence: ${queue.join(" -> ")}`,
        `Why: ${step.description}`,
        `Hypothesis: ${next.hypothesis_id || "none"}`,
        `Evidence nodes: ${next.evidence_nodes.length}`,
        event.rawType ? `Event: ${event.rawType} -> ${event.canonicalType || "none"}` : "Event: none",
        event.warnings.length > 0 ? `Event warnings: ${event.warnings.join("; ")}` : "Event warnings: none",
        `Evidence signals: supports=${policy.evidence.supports}, refutes=${policy.evidence.refutes}, observes=${policy.evidence.observes}`,
        `Budget: ${policy.budget.remaining_seconds}s remaining, ${policy.budget.primitive_budget} primitive(s)`,
      ].join("\n"),
    }
  },
})
