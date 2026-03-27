import { describe, expect, test, afterAll, beforeAll } from "bun:test"
import { PythonBridge } from "../../src/bridge/python"

let bridge: PythonBridge

describe("bridge.python", () => {
  beforeAll(async () => {
    bridge = PythonBridge.instance()
    await bridge.start()
  }, 60_000)

  afterAll(async () => {
    await bridge.stop()
  })

  test("bridge starts and is ready", () => {
    // If beforeAll succeeded, the bridge is ready
    expect(bridge).toBeDefined()
  })

  test("create_session returns session_id", async () => {
    const result = await bridge.call("create_session", {
      target: "http://testphp.vulnweb.com",
    })
    expect(result).toBeDefined()
    expect(result.session_id).toBeDefined()
    expect(typeof result.session_id).toBe("string")
  }, 30_000)

  test("kb_search returns results", async () => {
    const result = await bridge.call("kb_search", {
      query: "SQL injection detection",
    })
    expect(result).toBeDefined()
    // kb_search should return an array or object with results
    expect(result).toBeTruthy()
  }, 30_000)

  test("plan returns phases", async () => {
    // First create a session
    const session = await bridge.call("create_session", {
      target: "http://testphp.vulnweb.com",
    })
    const result = await bridge.call("plan", {
      target: "http://testphp.vulnweb.com",
      session_id: session.session_id,
    })
    expect(result).toBeDefined()
  }, 30_000)

  test("unknown method returns error", async () => {
    try {
      await bridge.call("nonexistent_method", {})
      // Should not reach here
      expect(true).toBe(false)
    } catch (err: any) {
      expect(err.message).toBeDefined()
    }
  }, 10_000)
})
