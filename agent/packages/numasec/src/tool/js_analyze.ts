import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./js_analyze.txt"

export const JsAnalyzeTool = bridgeTool(
  "js_analyze",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL or JS file URL to analyze"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
    deep: z.boolean().optional().default(false).describe("Follow and analyze imported scripts"),
  }),
)
