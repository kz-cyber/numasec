import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { AccessControlTestTool } from "../../src/security/tool/access-control-test"

let server: ReturnType<typeof Bun.serve>
let baseUrl = ""

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const url = new URL(req.url)
      if (url.pathname === "/wildcard") {
        return new Response("ok", {
          headers: {
            "access-control-allow-origin": "*",
          },
        })
      }
      if (url.pathname === "/reflected") {
        const origin = req.headers.get("origin") ?? ""
        return new Response("ok", {
          headers: {
            "access-control-allow-origin": origin,
            "access-control-allow-credentials": "true",
          },
        })
      }
      return new Response("not-found", { status: 404 })
    },
  })
  baseUrl = server.url.origin
})

afterAll(() => {
  server.stop()
})

function toolContext(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-access-control-cors-test",
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

describe("access_control_test CORS risk tiering", () => {
  test("treats wildcard without credentials as informational only", async () => {
    const out = await runTool(
      {
        url: `${baseUrl}/wildcard`,
        test_type: "cors",
      },
      "sess-access-cors-wildcard" as SessionID,
    )
    expect((out.metadata as any).findings).toBe(0)
    expect(out.output).toContain("informational")
  })

  test("flags reflected origin with credentials as a finding", async () => {
    const out = await runTool(
      {
        url: `${baseUrl}/reflected`,
        test_type: "cors",
      },
      "sess-access-cors-reflected" as SessionID,
    )
    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("high risk")
  })
})
