import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./injection_test.txt"

export const InjectionTestTool = bridgeTool(
  "injection_test",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL to test"),
    method: z.string().optional().default("GET"),
    params: z.string().optional().describe("JSON object of parameters to test"),
    data: z.string().optional().describe("Request body for POST/PUT"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    tests: z.string().optional().describe("Comma-separated: sqli,nosql,cmdi,ssti,xxe"),
    auth_token: z.string().optional(),
    technique: z.enum(["error", "union", "blind", "time", "auto"]).optional().default("auto"),
  }),
)
