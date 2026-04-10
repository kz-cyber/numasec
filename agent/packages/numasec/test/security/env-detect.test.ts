import { describe, expect, test } from "bun:test"
import { detectEnvironment } from "../../src/security/env/detect"

describe("detectEnvironment", () => {
  test("returns a valid Environment object", () => {
    const env = detectEnvironment()
    expect(env.os).toBeTruthy()
    expect(Array.isArray(env.tools)).toBe(true)
    expect(typeof env.summary).toBe("string")
  })

  test("checks 20+ tools", () => {
    const env = detectEnvironment()
    expect(env.tools.length).toBeGreaterThanOrEqual(20)
  })

  test("every tool has name and available fields", () => {
    const env = detectEnvironment()
    for (const tool of env.tools) {
      expect(typeof tool.name).toBe("string")
      expect(tool.name).toBeTruthy()
      expect(typeof tool.available).toBe("boolean")
    }
  })

  test("curl is typically available on Linux", () => {
    const env = detectEnvironment()
    const curl = env.tools.find((t) => t.name === "curl")
    expect(curl).toBeDefined()
    if (process.platform !== "win32") {
      expect(curl!.available).toBe(true)
    }
  })

  test("available tools have path set", () => {
    const env = detectEnvironment()
    for (const tool of env.tools) {
      if (tool.available) {
        expect(tool.path).toBeTruthy()
      }
    }
  })

  test("unavailable tools have no path", () => {
    const env = detectEnvironment()
    for (const tool of env.tools) {
      if (!tool.available) {
        expect(tool.path).toBeFalsy()
      }
    }
  })

  test("summary is a non-empty string", () => {
    const env = detectEnvironment()
    expect(env.summary.length).toBeGreaterThan(0)
  })

  test("checks specific security tools", () => {
    const env = detectEnvironment()
    const names = env.tools.map((t) => t.name)
    expect(names).toContain("nmap")
    expect(names).toContain("sqlmap")
    expect(names).toContain("nuclei")
    expect(names).toContain("ffuf")
    expect(names).toContain("hydra")
  })
})
