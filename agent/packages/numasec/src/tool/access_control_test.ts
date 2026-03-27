import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./access_control_test.txt"

export const AccessControlTestTool = bridgeTool(
  "access_control_test",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL to test"),
    method: z.string().optional().default("GET"),
    params: z.string().optional().describe("JSON object of parameters to test"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional().describe("Bearer token for current user"),
    alt_auth_token: z.string().optional().describe("Bearer token for different user"),
    id_params: z.string().optional().describe("Comma-separated parameter names with IDs"),
  }),
)
