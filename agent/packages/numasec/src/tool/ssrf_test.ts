import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./ssrf_test.txt"

export const SsrfTestTool = bridgeTool(
  "ssrf_test",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL to test"),
    method: z.string().optional().default("GET"),
    params: z.string().optional().describe("JSON object of parameters to test"),
    data: z.string().optional().describe("Request body for POST"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
    callback_url: z.string().optional().describe("External callback URL for OOB detection"),
  }),
)
