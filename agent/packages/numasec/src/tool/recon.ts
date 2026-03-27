import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./recon.txt"

export const ReconTool = bridgeTool(
  "recon",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target host or URL to scan"),
    checks: z.string().optional().describe("Comma-separated checks: ports,tech,services,cve"),
    ports: z.string().optional().describe("Port range (e.g., '1-1000', 'top100')"),
    service_detection: z.boolean().optional().default(true).describe("Probe services for version info"),
  }),
)
