import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./save_finding.txt"

export const SaveFindingTool = bridgeTool(
  "save_finding",
  DESCRIPTION,
  z.object({
    session_id: z.string().describe("Session ID from create_session"),
    title: z.string().describe("Finding title"),
    severity: z.enum(["critical", "high", "medium", "low", "info"]).describe("Severity level"),
    description: z.string().describe("Detailed vulnerability description"),
    url: z.string().optional(),
    method: z.string().optional(),
    parameter: z.string().optional(),
    evidence: z.string().optional(),
    cwe_id: z.string().optional().describe("CWE identifier (e.g., CWE-89)"),
    remediation: z.string().optional(),
  }),
)
