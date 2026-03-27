import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./dir_fuzz.txt"

export const DirFuzzTool = bridgeTool(
  "dir_fuzz",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target base URL"),
    wordlist: z.string().optional().default("common"),
    extensions: z.string().optional().describe("Comma-separated extensions (e.g., 'php,asp,jsp')"),
    threads: z.number().optional().default(10),
    status_codes: z.string().optional().default("200,201,204,301,302,307,401,403"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
  }),
)
