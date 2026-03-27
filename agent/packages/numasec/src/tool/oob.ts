import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./oob.txt"

export const OobTool = bridgeTool(
  "oob",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL to test"),
    method: z.string().optional().default("GET"),
    params: z.string().optional().describe("JSON object of parameters to inject OOB payloads"),
    data: z.string().optional().describe("Request body for POST"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    callback_url: z.string().optional().describe("External OOB callback URL"),
    payload_types: z.string().optional().default("dns,http"),
  }),
)
