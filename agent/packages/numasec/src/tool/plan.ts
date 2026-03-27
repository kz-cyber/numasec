import z from "zod"
import { Tool } from "./tool"
import { Question } from "../question"
import { Session } from "../session"
import { MessageV2 } from "../session/message-v2"
import { Provider } from "../provider/provider"
import { type SessionID, MessageID, PartID } from "../session/schema"

async function getLastModel(sessionID: SessionID) {
  for await (const item of MessageV2.stream(sessionID)) {
    if (item.info.role === "user" && item.info.model) return item.info.model
  }
  return Provider.defaultModel()
}

export const PlanExitTool = Tool.define("plan_exit", {
  description:
    "Signal that reconnaissance is complete and ask the user whether to proceed to active vulnerability testing (pentest agent).",
  parameters: z.object({}),
  async execute(_params, ctx) {
    const answers = await Question.ask({
      sessionID: ctx.sessionID,
      questions: [
        {
          question: `Reconnaissance phase is complete. Would you like to switch to the pentest agent and begin vulnerability testing?`,
          header: "Pentest Agent",
          custom: false,
          options: [
            { label: "Yes", description: "Switch to pentest agent and start exploitation testing" },
            { label: "No", description: "Stay in recon mode to continue mapping the attack surface" },
          ],
        },
      ],
      tool: ctx.callID ? { messageID: ctx.messageID, callID: ctx.callID } : undefined,
    })

    const answer = answers[0]?.[0]
    if (answer === "No") throw new Question.RejectedError()

    const model = await getLastModel(ctx.sessionID)

    const userMsg: MessageV2.User = {
      id: MessageID.ascending(),
      sessionID: ctx.sessionID,
      role: "user",
      time: {
        created: Date.now(),
      },
      agent: "pentest",
      model,
    }
    await Session.updateMessage(userMsg)
    await Session.updatePart({
      id: PartID.ascending(),
      messageID: userMsg.id,
      sessionID: ctx.sessionID,
      type: "text",
      text: `Reconnaissance is complete and approved. You can now run vulnerability tests. Begin testing the identified attack surface.`,
      synthetic: true,
    } satisfies MessageV2.TextPart)

    return {
      title: "Switching to pentest agent",
      output: "User approved switching to pentest agent. Begin vulnerability testing on the identified attack surface.",
      metadata: {},
    }
  },
})
