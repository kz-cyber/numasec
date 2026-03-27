import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./create_session.txt"

export const CreateSessionTool = bridgeTool(
  "create_session",
  DESCRIPTION,
  z.object({
    target_url: z.string().describe("Primary target URL"),
    session_name: z.string().optional().describe("Human-readable session name"),
    scope: z.string().optional().describe("Comma-separated allowed domains/IPs"),
  }),
)
