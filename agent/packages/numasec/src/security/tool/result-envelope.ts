import z from "zod"

export const ToolResultStatus = z.enum([
  "ok",
  "inconclusive",
  "retryable_error",
  "fatal_error",
  "denied",
  "timeout",
])
export type ToolResultStatus = z.infer<typeof ToolResultStatus>

const ToolResultItem = z.record(z.string(), z.any())

export const ToolResultEnvelope = z.object({
  status: ToolResultStatus,
  artifacts: z.array(ToolResultItem).default([]),
  observations: z.array(ToolResultItem).default([]),
  verifications: z.array(ToolResultItem).default([]),
  links: z.array(ToolResultItem).default([]),
  metrics: z.record(z.string(), z.number()).default({}),
  error: z
    .object({
      code: z.string(),
      message: z.string(),
    })
    .optional(),
  text: z.string().optional(),
})
export type ToolResultEnvelope = z.infer<typeof ToolResultEnvelope>

export function makeToolResultEnvelope(input: z.input<typeof ToolResultEnvelope>) {
  return ToolResultEnvelope.parse(input)
}

