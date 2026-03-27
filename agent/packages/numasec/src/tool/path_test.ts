import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./path_test.txt"

export const PathTestTool = bridgeTool(
  "path_test",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL to test"),
    method: z.string().optional().default("GET"),
    params: z.string().optional().describe("JSON object of parameters to test"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
    os: z.enum(["linux", "windows", "auto"]).optional().default("auto"),
  }),
)
