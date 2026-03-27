import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./run_scanner_batch.txt"

export const RunScannerBatchTool = bridgeTool(
  "run_scanner_batch",
  DESCRIPTION,
  z.object({
    session_id: z.string().describe("Session ID"),
    target: z.string().describe("Target URL"),
    scanners: z.string().describe("Comma-separated scanner names"),
    params: z.string().optional().describe("JSON object of shared parameters"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
  }),
)
