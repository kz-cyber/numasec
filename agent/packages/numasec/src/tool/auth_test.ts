import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./auth_test.txt"

export const AuthTestTool = bridgeTool(
  "auth_test",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Target URL or auth endpoint"),
    tests: z.string().optional().describe("Comma-separated: jwt,oauth,spray,session,default_creds"),
    jwt_token: z.string().optional().describe("JWT token to analyze"),
    username_list: z.string().optional().describe("Newline-separated usernames for spray"),
    password_list: z.string().optional().describe("Newline-separated passwords for spray"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    auth_token: z.string().optional(),
  }),
)
