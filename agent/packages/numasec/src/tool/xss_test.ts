import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./xss_test.txt"

export const XssTestTool = bridgeTool(
  "xss_test",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL to test"),
    method: z.string().optional().default("GET"),
    params: z.string().optional().describe("JSON object of parameters to test"),
    data: z.string().optional().describe("Request body for POST"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
    contexts: z.string().optional().describe("Comma-separated: html,attr,js,url"),
  }),
)
