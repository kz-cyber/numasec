import { describe, expect, test, beforeEach } from "bun:test"
import { Scope } from "../../src/security/scope"

beforeEach(() => {
  Scope.clear()
})

describe("Scope", () => {
  test("check fails when no scope is set", () => {
    const result = Scope.check("http://example.com")
    expect(result.allowed).toBe(false)
    expect(result.reason).toContain("No scope defined")
  })

  test("allows URL within scope", () => {
    Scope.set({
      allowedPatterns: ["example.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check("http://example.com/api").allowed).toBe(true)
  })

  test("blocks URL outside scope", () => {
    Scope.set({
      allowedPatterns: ["example.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    const result = Scope.check("http://evil.com/api")
    expect(result.allowed).toBe(false)
    expect(result.reason).toContain("not in scope")
  })

  test("glob matching: *.example.com matches subdomains", () => {
    Scope.set({
      allowedPatterns: ["*.example.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check("http://api.example.com").allowed).toBe(true)
    expect(Scope.check("http://dev.example.com").allowed).toBe(true)
    expect(Scope.check("http://example.com").allowed).toBe(false)
  })

  test("blocked patterns take priority over allowed", () => {
    Scope.set({
      allowedPatterns: ["*.example.com"],
      blockedPatterns: ["admin.example.com"],
      allowInternal: false,
    })

    expect(Scope.check("http://api.example.com").allowed).toBe(true)
    const result = Scope.check("http://admin.example.com")
    expect(result.allowed).toBe(false)
    expect(result.reason).toContain("Blocked")
  })

  test("blocks private IPs by default", () => {
    Scope.set({
      allowedPatterns: ["*"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check("http://127.0.0.1").allowed).toBe(false)
    expect(Scope.check("http://10.0.0.1").allowed).toBe(false)
    expect(Scope.check("http://192.168.1.1").allowed).toBe(false)
    expect(Scope.check("http://172.16.0.1").allowed).toBe(false)
    expect(Scope.check("http://localhost").allowed).toBe(false)
  })

  test("allows private IPs when allowInternal=true", () => {
    Scope.set({
      allowedPatterns: ["*"],
      blockedPatterns: [],
      allowInternal: true,
    })

    expect(Scope.check("http://127.0.0.1:3000").allowed).toBe(true)
    expect(Scope.check("http://localhost:8080").allowed).toBe(true)
    expect(Scope.check("http://192.168.1.1").allowed).toBe(true)
  })

  test("handles host with port", () => {
    Scope.set({
      allowedPatterns: ["example.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check("http://example.com:8080/api").allowed).toBe(true)
  })

  test("set/get/clear lifecycle", () => {
    expect(Scope.get()).toBeNull()

    Scope.set({
      allowedPatterns: ["test.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.get()).toBeDefined()
    expect(Scope.get()!.allowedPatterns).toContain("test.com")

    Scope.clear()
    expect(Scope.get()).toBeNull()
  })

  test("0.0.0.0 blocked as private", () => {
    Scope.set({
      allowedPatterns: ["*"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check("http://0.0.0.0").allowed).toBe(false)
  })
})
