import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./http_request.txt"

export const HttpRequestTool = bridgeTool(
  "http_request",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Full URL to send request to"),
    method: z.string().optional().default("GET"),
    headers: z.string().optional().describe("JSON object of request headers"),
    data: z.string().optional().describe("Request body"),
    params: z.string().optional().describe("JSON object of query parameters"),
    auth_token: z.string().optional(),
    follow_redirects: z.boolean().optional().default(true),
    timeout: z.number().optional().default(30),
    verify_ssl: z.boolean().optional().default(true),
  }),
)
