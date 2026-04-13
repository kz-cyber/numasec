/**
 * Tool: access_control_test
 *
 * Tests for IDOR, CSRF, CORS misconfigurations, and mass assignment.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { httpRequest } from "../http-client"
import { makeToolResultEnvelope } from "./result-envelope"

function slug(value: string) {
  return value.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase()
}

function target(url: string, parameter: string, value: string) {
  const token = `{${parameter}}`
  if (url.includes(token)) return url.replaceAll(token, encodeURIComponent(value))
  const colon = `:${parameter}`
  if (url.includes(colon)) return url.replaceAll(colon, encodeURIComponent(value))
  const next = new URL(url)
  next.searchParams.set(parameter, value)
  return next.toString()
}

function success(status: number) {
  return status >= 200 && status < 300
}

function actorLabel(input: "primary" | "secondary") {
  if (input === "secondary") return "secondary"
  return "primary"
}

type Actor = {
  name: "primary" | "secondary"
  headers?: Record<string, string>
  cookies?: string
}

const DESCRIPTION = `Test for access control vulnerabilities:
- IDOR: change resource IDs to access other users' data
- CSRF: check for missing anti-CSRF protections
- CORS: test for permissive cross-origin policies
- Mass Assignment: send extra fields to modify protected attributes

Requires: target URL. For IDOR, also provide the parameter with the resource ID.

CHAIN POTENTIAL:
- IDOR → data leak of all users' data
- CORS misconfiguration → cross-site data theft via victim's browser
- CSRF + IDOR → modify other users' data from attacker's site
- Mass assignment → privilege escalation (role: "admin")`

export const AccessControlTestTool = Tool.define("access_control_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL"),
    test_type: z
      .enum(["idor", "csrf", "cors", "mass_assignment", "all"])
      .default("all")
      .describe("Specific test type or all"),
    parameter: z.string().optional().describe("Parameter with resource ID (for IDOR)"),
    method: z.enum(["GET", "POST", "PUT", "DELETE"]).optional().describe("HTTP method"),
    headers: z.record(z.string(), z.string()).optional().describe("Headers including auth"),
    secondary_headers: z.record(z.string(), z.string()).optional().describe("Optional secondary actor headers for differential authz testing"),
    cookies: z.string().optional().describe("Cookies"),
    secondary_cookies: z.string().optional().describe("Optional secondary actor cookies for differential authz testing"),
    body: z.string().optional().describe("Request body"),
    id_values: z.array(z.string()).optional().describe("Optional custom identifier values for IDOR testing"),
    own_value: z.string().optional().describe("Known resource identifier owned by the primary actor"),
    foreign_value: z.string().optional().describe("Known resource identifier owned by another actor"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "access_control_test",
      patterns: [params.url],
      always: ["*"] as string[],
      metadata: { url: params.url, test_type: params.test_type } as Record<string, any>,
    })

    const tests = params.test_type === "all" ? ["idor", "csrf", "cors", "mass_assignment"] : [params.test_type]
    const parts: string[] = []
    let totalFindings = 0
    const artifacts: Record<string, any>[] = []
    const observations: Record<string, any>[] = []
    const verifications: Record<string, any>[] = []

    // CORS test
    if (tests.includes("cors")) {
      ctx.metadata({ title: "Testing CORS..." })
      const origins = ["https://evil.com", "null", "https://evil." + new URL(params.url).hostname]
      const details: string[] = []
      let critical = false
      let reflected = false
      let wildcard = false

      for (const origin of origins) {
        const resp = await httpRequest(params.url, {
          method: "GET",
          headers: { ...params.headers, Origin: origin },
          cookies: params.cookies,
        })

        const acao = resp.headers["access-control-allow-origin"]
        const acac = resp.headers["access-control-allow-credentials"]
        if (!acao) continue
        const allowCredentials = acac === "true"
        const reflectOrigin = acao === origin
        if (reflectOrigin && allowCredentials) {
          critical = true
          details.push(`  Origin ${origin} reflected with credentials enabled`)
          continue
        }
        if (reflectOrigin) {
          reflected = true
          details.push(`  Origin ${origin} reflected without credentials`)
          continue
        }
        if (acao === "*" && allowCredentials) {
          critical = true
          details.push(`  Wildcard origin with credentials enabled`)
          continue
        }
        if (acao === "*") {
          wildcard = true
          details.push(`  Wildcard origin without credentials`)
        }
      }

      if (critical) {
        parts.push(`\n── ⚠ CORS Misconfiguration (high risk) ──`)
        for (const detail of details) parts.push(detail)
        totalFindings++
        const item = `cors-${slug(new URL(params.url).pathname || "root")}`
        artifacts.push({
          key: item,
          subtype: "cors_scan",
          url: params.url,
          details,
          tested_origins: origins,
        })
        verifications.push({
          key: `${item}-verified`,
          family: "cors",
          kind: "dangerous_policy",
          title: "Dangerous CORS policy on sensitive endpoint",
          technical_severity: "high",
          passed: true,
          control: "positive",
          url: params.url,
          method: "GET",
          evidence_keys: [item],
        })
      } else if (reflected) {
        parts.push(`\n── ⚠ CORS Misconfiguration (review required) ──`)
        for (const detail of details) parts.push(detail)
        totalFindings++
        observations.push({
          key: `cors-review-${slug(new URL(params.url).pathname || "root")}`,
          family: "cors",
          kind: "origin_reflection_without_credentials",
          url: params.url,
          details,
        })
      } else if (wildcard) {
        parts.push(`\n── CORS wildcard observed (informational) ──`)
        for (const detail of details) parts.push(detail)
        observations.push({
          key: `cors-info-${slug(new URL(params.url).pathname || "root")}`,
          family: "cors",
          kind: "wildcard_without_credentials",
          url: params.url,
          details,
        })
      } else {
        parts.push("\n── CORS: properly configured ──")
      }
    }

    // CSRF test
    if (tests.includes("csrf")) {
      ctx.metadata({ title: "Testing CSRF..." })
      const method = params.method ?? "POST"

      if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
        // Send request without CSRF token
        const resp = await httpRequest(params.url, {
          method,
          headers: {
            ...params.headers,
            "Content-Type": "application/x-www-form-urlencoded",
            Referer: "https://evil.com",
            Origin: "https://evil.com",
          },
          body: params.body ?? "test=1",
          cookies: params.cookies,
        })

        if (resp.status >= 200 && resp.status < 400) {
          parts.push(`\n── ⚠ Potential CSRF ──`)
          parts.push(`  ${method} ${params.url} accepted cross-origin request`)
          parts.push(`  Status: ${resp.status}`)
          parts.push(`  No CSRF token validation detected`)
          totalFindings++
          const item = `csrf-${method.toLowerCase()}-${slug(new URL(params.url).pathname || "root")}`
          artifacts.push({
            key: item,
            subtype: "csrf_check",
            url: params.url,
            method,
            status: resp.status,
            response_preview: resp.body.slice(0, 300),
          })
          verifications.push({
            key: `${item}-verified`,
            family: "csrf",
            kind: "cross_origin_state_change",
            title: "Potential CSRF on state-changing endpoint",
            technical_severity: "medium",
            passed: true,
            control: "positive",
            url: params.url,
            method,
            evidence_keys: [item],
          })
        } else {
          parts.push(`\n── CSRF: ${method} request rejected (status ${resp.status}) ──`)
        }
      } else {
        parts.push("\n── CSRF: GET requests not vulnerable by design ──")
      }
    }

    // IDOR test
    if (tests.includes("idor") && params.parameter) {
      ctx.metadata({ title: `Testing IDOR on ${params.parameter}...` })

      const testIds = params.id_values ?? ["1", "2", "0", "999999", "-1", "admin", "test"]
      const values = Array.from(new Set([params.own_value, params.foreign_value, ...testIds].filter((item): item is string => typeof item === "string" && item.length > 0)))
      const baseUrl = new URL(params.url)
      const actors: Actor[] = [
        {
          name: "primary" as const,
          headers: params.headers,
          cookies: params.cookies,
        },
      ]
      if (params.secondary_headers || params.secondary_cookies) {
        actors.push({
          name: "secondary" as const,
          headers: params.secondary_headers,
          cookies: params.secondary_cookies,
        })
      }
      const ids: Array<{ actor: string; id: string; status: number; length: number; url: string }> = []
      for (const actor of actors) {
        for (const id of values) {
          const testUrl = target(params.url, params.parameter, id)
          const resp = await httpRequest(testUrl, {
            method: params.method ?? "GET",
            headers: actor.headers,
            cookies: actor.cookies,
          })
          ids.push({
            actor: actor.name,
            id,
            status: resp.status,
            length: resp.body.length,
            url: testUrl,
          })
        }
      }

      const ownPrimary = ids.find((item) => item.actor === "primary" && item.id === params.own_value)
      const foreignPrimary = ids.find((item) => item.actor === "primary" && item.id === params.foreign_value)
      const ownSecondary = ids.find((item) => item.actor === "secondary" && item.id === params.foreign_value)
      const foreignSecondary = ids.find((item) => item.actor === "secondary" && item.id === params.own_value)
      const primaryCross = !!ownPrimary && !!foreignPrimary && success(ownPrimary.status) && success(foreignPrimary.status)
      const secondaryCross = !!ownSecondary && !!foreignSecondary && success(ownSecondary.status) && success(foreignSecondary.status)

      if (primaryCross && secondaryCross) {
        parts.push(`\n── ⚠ IDOR: cross-actor access confirmed on ${params.parameter} ──`)
        parts.push(`  Primary actor accessed foreign resource ${params.foreign_value}`)
        parts.push(`  Secondary actor accessed foreign resource ${params.own_value}`)
        totalFindings++
        const item = `idor-diff-${slug(params.parameter)}-${slug(baseUrl.pathname || "root")}`
        artifacts.push({
          key: item,
          subtype: "idor_differential_scan",
          url: params.url,
          parameter: params.parameter,
          own_value: params.own_value ?? "",
          foreign_value: params.foreign_value ?? "",
          results: ids,
        })
        verifications.push({
          key: `${item}-verified`,
          family: "idor",
          kind: "cross_actor_access",
          title: `Cross-actor access confirmed on ${params.parameter}`,
          technical_severity: "high",
          passed: true,
          control: "positive",
          url: params.url,
          method: params.method ?? "GET",
          parameter: params.parameter,
          evidence_keys: [item],
        })
      }

      if (!primaryCross || !secondaryCross) {
        let idorFindings = 0
        for (const item of ids.filter((row) => row.actor === "primary")) {
          if (item.status === 200 && item.length > 100) {
            idorFindings++
            parts.push(`  ${actorLabel("primary")} ID ${item.id}: ${item.status} (${item.length} bytes)`)
          }
        }

        if (idorFindings > 1) {
          parts.push(`\n── ⚠ IDOR: ${idorFindings} different IDs returned data ──`)
          parts.push(`  Parameter: ${params.parameter}`)
          totalFindings++
          const item = `idor-${slug(params.parameter)}-${slug(baseUrl.pathname || "root")}`
          artifacts.push({
            key: item,
            subtype: "idor_scan",
            url: params.url,
            parameter: params.parameter,
            results: ids,
          })
          verifications.push({
            key: `${item}-verified`,
            family: "idor",
            kind: "resource_enumeration",
            title: `IDOR indicated on ${params.parameter}`,
            technical_severity: "high",
            passed: true,
            control: "positive",
            url: params.url,
            method: params.method ?? "GET",
            parameter: params.parameter,
            evidence_keys: [item],
          })
        }

        if (idorFindings <= 1) {
          parts.push(`\n── IDOR: no enumeration detected on ${params.parameter} ──`)
        }
      }
    }

    // Mass assignment test
    if (tests.includes("mass_assignment")) {
      ctx.metadata({ title: "Testing mass assignment..." })
      const extraFields = ["role", "admin", "is_admin", "isAdmin", "privilege", "status", "verified", "active"]

      const baseBody = params.body ? JSON.parse(params.body) : {}
      for (const field of extraFields) {
        const testBody = { ...baseBody, [field]: field === "role" ? "admin" : true }
        const resp = await httpRequest(params.url, {
          method: params.method ?? "POST",
          headers: { ...params.headers, "Content-Type": "application/json" },
          body: JSON.stringify(testBody),
          cookies: params.cookies,
        })

        if (resp.status >= 200 && resp.status < 300) {
          const respLower = resp.body.toLowerCase()
          if (respLower.includes(`"${field}"`) || respLower.includes(`"${field}":true`) || respLower.includes(`"${field}":"admin"`)) {
            parts.push(`\n── ⚠ Mass Assignment: "${field}" accepted ──`)
            parts.push(`  Response includes the injected field`)
            parts.push(`  Response: ${resp.body.slice(0, 300)}`)
            totalFindings++
            const item = `mass-${slug(field)}-${slug(new URL(params.url).pathname || "root")}`
            artifacts.push({
              key: item,
              subtype: "mass_assignment_scan",
              url: params.url,
              field,
              status: resp.status,
              payload: testBody,
              response_preview: resp.body.slice(0, 300),
            })
            verifications.push({
              key: `${item}-verified`,
              family: "mass_assignment",
              kind: "protected_field_accepted",
              title: `Mass assignment accepted protected field ${field}`,
              technical_severity: field === "role" || field === "admin" || field === "is_admin" || field === "isAdmin" ? "high" : "medium",
              passed: true,
              control: "positive",
              url: params.url,
              method: params.method ?? "POST",
              parameter: field,
              evidence_keys: [item],
            })
          }
        }
      }
      if (!parts.some((l) => l.includes("Mass Assignment"))) {
        parts.push("\n── Mass Assignment: extra fields not reflected ──")
      }
    }

    return {
      title: totalFindings > 0
        ? `⚠ ${totalFindings} access control issue(s)`
        : "Access control: no issues",
      metadata: { findings: totalFindings, tests: tests.length } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        artifacts,
        observations,
        verifications,
        metrics: {
          findings: totalFindings,
          tests: tests.length,
        },
      }),
      output: parts.join("\n"),
    }
  },
})
