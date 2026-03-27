import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./relay_credentials.txt"

export const RelayCredentialsTool = bridgeTool(
  "relay_credentials",
  DESCRIPTION,
  z.object({
    session_id: z.string().describe("Session ID"),
    credentials: z.string().describe("JSON object with credential data"),
  }),
)
