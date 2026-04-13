import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { SecurityTools } from "../../src/security"
import { ReconTool } from "../../src/security/tool/recon"
import { CrawlTool } from "../../src/security/tool/crawl"
import { DirFuzzTool } from "../../src/security/tool/dir-fuzz"
import { JsAnalyzeTool } from "../../src/security/tool/js-analyze"
import { ShellTool } from "../../src/security/tool/shell"

let server: ReturnType<typeof Bun.serve>
let baseUrl = ""

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const url = new URL(req.url)
      const origin = url.origin
      if (url.pathname === "/" || url.pathname === "/index.html") {
        return new Response(
          `<html><head><script src="/app.js"></script></head><body><a href="/about">About</a><form method="POST" action="/login"><input name="email" type="email" /></form></body></html>`,
          {
            headers: {
              "x-powered-by": "Express",
            },
          },
        )
      }
      if (url.pathname === "/about") {
        return new Response("<html><body>about</body></html>", {
          headers: {
            "x-powered-by": "Express",
          },
        })
      }
      if (url.pathname === "/login") {
        return new Response("ok")
      }
      if (url.pathname === "/api/users") {
        return new Response("[]", {
          headers: {
            "content-type": "application/json",
            "x-powered-by": "Express",
          },
        })
      }
      if (url.pathname === "/app.js") {
        return new Response(
          `fetch('/api/users'); const token = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; const route = '/dashboard';`,
          {
            headers: {
              "content-type": "application/javascript",
            },
          },
        )
      }
      if (url.pathname === "/robots.txt") {
        return new Response("User-agent: *\nDisallow: /private")
      }
      if (url.pathname === "/sitemap.xml") {
        return new Response(`<urlset><url><loc>${origin}/about</loc></url></urlset>`, {
          headers: {
            "content-type": "application/xml",
          },
        })
      }
      if (url.pathname === "/openapi.json") {
        return new Response(`{"openapi":"3.0.0","paths":{}}`, {
          headers: {
            "content-type": "application/json",
          },
        })
      }
      if (url.pathname === "/admin") {
        return new Response("admin panel")
      }
      return new Response("Not Found", { status: 404 })
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
    callID: "call-legacy-wrapper",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runTool(tool: Tool.Info, args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await tool.init()
  return impl.execute(args as never, toolContext(sessionID))
}

describe("legacy wrapper compatibility", () => {
  test("legacy tool IDs remain registered", () => {
    const ids = SecurityTools.map((tool) => tool.id)
    expect(ids).toContain("recon")
    expect(ids).toContain("crawl")
    expect(ids).toContain("dir_fuzz")
    expect(ids).toContain("js_analyze")
    expect(ids).toContain("security_shell")
  })

  test("recon wrapper returns legacy-style output", async () => {
    const out = await runTool(
      ReconTool,
      {
        target: baseUrl,
        ports: [server.port],
        skip_js: true,
      },
      "sess-legacy-recon" as SessionID,
    )
    expect(out.title).toContain("Recon:")
    expect(typeof (out.metadata as any).openPorts).toBe("number")
    expect(out.output).toContain("── Port Scan")
  })

  test("crawl wrapper returns legacy-style output", async () => {
    const out = await runTool(
      CrawlTool,
      {
        url: baseUrl,
        max_urls: 10,
        max_depth: 2,
        fuzz: false,
      },
      "sess-legacy-crawl" as SessionID,
    )
    expect(out.title).toContain("Crawl:")
    expect((out.metadata as any).urls).toBeGreaterThan(0)
    expect(out.output).toContain("── Crawl Results")
  })

  test("dir_fuzz wrapper returns legacy-style output", async () => {
    const out = await runTool(
      DirFuzzTool,
      {
        url: baseUrl,
        wordlist: ["admin"],
        extensions: [],
      },
      "sess-legacy-dir-fuzz" as SessionID,
    )
    expect(out.title).toContain("Dir fuzz:")
    expect((out.metadata as any).found).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("/admin")
  })

  test("js_analyze wrapper returns legacy-style output", async () => {
    const out = await runTool(
      JsAnalyzeTool,
      {
        url: baseUrl,
      },
      "sess-legacy-js-analyze" as SessionID,
    )
    expect(out.title).toContain("JS:")
    expect((out.metadata as any).endpoints).toBeGreaterThan(0)
    expect(out.output).toContain("── JS Analysis")
  })

  test("security_shell wrapper executes command via legacy ID", async () => {
    const out = await runTool(
      ShellTool,
      {
        command: "echo legacy-shell-wrapper",
        timeout: 5000,
        description: "Echo wrapper output",
      },
      "sess-legacy-shell" as SessionID,
    )
    expect(out.title).toBe("Echo wrapper output")
    expect((out.metadata as any).exitCode).toBe(0)
    expect(out.output).toContain("legacy-shell-wrapper")
    expect(out.output).toContain("Exit code:")
  })
})
