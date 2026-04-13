import { expect, test } from "bun:test"
import {
  allowLabel,
  annotateApprovalMetadata,
  formatConstraintPrompt,
  formatRejectionConstraint,
  resolveApproval,
  selectApprovalPatterns,
} from "../../src/permission/approval"

test("resolveApproval - read is low risk", () => {
  const result = resolveApproval({ permission: "read", metadata: {} })
  expect(result).toEqual({
    risk: "low",
    scope: "none",
    reason_required: false,
  })
  expect(allowLabel(result.scope)).toBeUndefined()
})

test("resolveApproval - webfetch is medium risk", () => {
  const result = resolveApproval({ permission: "webfetch", metadata: {} })
  expect(result).toEqual({
    risk: "medium",
    scope: "hypothesis",
    reason_required: false,
  })
  expect(allowLabel(result.scope)).toBe("Allow in hypothesis")
})

test("resolveApproval - bash is high risk", () => {
  const result = resolveApproval({ permission: "bash", metadata: {} })
  expect(result).toEqual({
    risk: "high",
    scope: "scope",
    reason_required: true,
  })
  expect(allowLabel(result.scope)).toBe("Allow in scope")
})

test("resolveApproval - metadata overrides inferred tier", () => {
  const result = resolveApproval({
    permission: "bash",
    metadata: {
      approval_risk: "medium",
      approval_scope: "hypothesis",
      approval_reason_required: false,
    },
  })
  expect(result).toEqual({
    risk: "medium",
    scope: "hypothesis",
    reason_required: false,
  })
})

test("annotateApprovalMetadata - writes normalized approval fields", () => {
  const approval = resolveApproval({ permission: "task", metadata: {} })
  const result = annotateApprovalMetadata({ source: "tool" }, approval)
  expect(result).toMatchObject({
    source: "tool",
    approval_risk: approval.risk,
    approval_scope: approval.scope,
    approval_reason_required: approval.reason_required,
  })
})

test("selectApprovalPatterns - falls back to request patterns when scope is enabled", () => {
  const approval = resolveApproval({ permission: "bash", metadata: {} })
  const result = selectApprovalPatterns({
    always: [],
    patterns: ["git status"],
    approval,
  })
  expect(result).toEqual(["git status"])
})

test("selectApprovalPatterns - keeps empty list when scoped approvals are disabled", () => {
  const approval = resolveApproval({ permission: "read", metadata: {} })
  const result = selectApprovalPatterns({
    always: [],
    patterns: ["*"],
    approval,
  })
  expect(result).toEqual([])
})

test("formatRejectionConstraint - emits concise guidance", () => {
  const result = formatRejectionConstraint({
    permission: "bash",
    patterns: ["rm -rf *"],
    message: "  avoid destructive cleanup here  ",
  })
  expect(result).toBe("Do not run bash (rm -rf *): avoid destructive cleanup here")
})

test("formatConstraintPrompt - wraps constraints in planner context block", () => {
  const result = formatConstraintPrompt(["Do not run bash: use ls"])
  expect(result).toContain("<approval-constraints>")
  expect(result).toContain("Do not run bash: use ls")
  expect(result).toContain("planning next steps")
})
