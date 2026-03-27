import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./kb_search.txt"

export const KbSearchTool = bridgeTool(
  "kb_search",
  DESCRIPTION,
  z.object({
    query: z.string().describe("Search query for the knowledge base"),
    category: z.string().optional().describe("Filter: detection,exploitation,post_exploitation,remediation,payloads,protocols,chains"),
    top_k: z.number().optional().default(5),
  }),
)
