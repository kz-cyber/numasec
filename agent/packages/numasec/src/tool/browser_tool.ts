import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./browser_tool.txt"

export const BrowserTool = bridgeTool(
  "browser",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL to open"),
    actions: z.string().optional().describe("JSON array of browser actions"),
    wait_for: z.string().optional().default("networkidle"),
    screenshot: z.boolean().optional().default(false),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
  }),
)
