import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./crawl.txt"

export const CrawlTool = bridgeTool(
  "crawl",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL to crawl"),
    max_depth: z.number().optional().default(3),
    max_pages: z.number().optional().default(100),
    mode: z.enum(["html", "spa", "auto"]).optional().default("auto"),
    openapi_url: z.string().optional().describe("OpenAPI/Swagger spec URL to import"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
  }),
)
