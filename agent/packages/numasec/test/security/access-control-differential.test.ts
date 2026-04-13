import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { AccessControlTestTool } from "../../src/security/tool/access-control-test"
import { startSecurityTarget, type SecurityTargetFixture } from "../fixture/security-target"

let app: SecurityTargetFixture

beforeAll(() => {
  app = startSecurityTarget()
})

afterAll(() => {
  app.stop()
})

function toolContext(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-access-control-differential-test",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runTool(args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await AccessControlTestTool.init()
  return impl.execute(args as never, toolContext(sessionID))
}

describe("access_control_test differential IDOR", () => {
  test("flags cross-actor path access when both actors can read each other's resource", async () => {
    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "idor-user@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const userID = String(body.data.id)

    const out = await runTool(
      {
        url: `${app.baseUrl}/api/Users/{id}`,
        test_type: "idor",
        parameter: "id",
        headers: {
          authorization: `Bearer ${app.tokenFor(body.data.id)}`,
        },
        secondary_headers: {
          authorization: `Bearer ${app.tokenFor(1)}`,
        },
        own_value: userID,
        foreign_value: "1",
      },
      "sess-access-idor-diff" as SessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("cross-actor access confirmed")
    expect(JSON.stringify(out.envelope)).toContain("cross_actor_access")
  })
})
