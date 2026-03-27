import { describe, expect, test } from "bun:test"
import z from "zod"

// Import bridge tool definitions to validate schemas load correctly
import { ReconTool } from "../../src/tool/recon"
import { CrawlTool } from "../../src/tool/crawl"
import { InjectionTestTool } from "../../src/tool/injection_test"
import { XssTestTool } from "../../src/tool/xss_test"
import { SsrfTestTool } from "../../src/tool/ssrf_test"
import { AuthTestTool } from "../../src/tool/auth_test"
import { AccessControlTestTool } from "../../src/tool/access_control_test"
import { PathTestTool } from "../../src/tool/path_test"
import { DirFuzzTool } from "../../src/tool/dir_fuzz"
import { JsAnalyzeTool } from "../../src/tool/js_analyze"
import { BrowserTool } from "../../src/tool/browser_tool"
import { OobTool } from "../../src/tool/oob"
import { HttpRequestTool } from "../../src/tool/http_request"
import { SaveFindingTool } from "../../src/tool/save_finding"
import { GetFindingsTool } from "../../src/tool/get_findings"
import { GenerateReportTool } from "../../src/tool/generate_report"
import { KbSearchTool } from "../../src/tool/kb_search"
import { CreateSessionTool } from "../../src/tool/create_session"
import { RelayCredentialsTool } from "../../src/tool/relay_credentials"
import { RunScannerBatchTool } from "../../src/tool/run_scanner_batch"

const allTools = [
  { name: "recon", tool: ReconTool },
  { name: "crawl", tool: CrawlTool },
  { name: "injection_test", tool: InjectionTestTool },
  { name: "xss_test", tool: XssTestTool },
  { name: "ssrf_test", tool: SsrfTestTool },
  { name: "auth_test", tool: AuthTestTool },
  { name: "access_control_test", tool: AccessControlTestTool },
  { name: "path_test", tool: PathTestTool },
  { name: "dir_fuzz", tool: DirFuzzTool },
  { name: "js_analyze", tool: JsAnalyzeTool },
  { name: "browser", tool: BrowserTool },
  { name: "oob", tool: OobTool },
  { name: "http_request", tool: HttpRequestTool },
  { name: "save_finding", tool: SaveFindingTool },
  { name: "get_findings", tool: GetFindingsTool },
  { name: "generate_report", tool: GenerateReportTool },
  { name: "kb_search", tool: KbSearchTool },
  { name: "create_session", tool: CreateSessionTool },
  { name: "relay_credentials", tool: RelayCredentialsTool },
  { name: "run_scanner_batch", tool: RunScannerBatchTool },
]

describe("bridge.tools", () => {
  test("all bridge tools are importable", () => {
    for (const { name, tool } of allTools) {
      expect(tool).toBeDefined()
      expect(tool.id).toBe(name)
    }
  })

  test("all bridge tools have descriptions", async () => {
    for (const { name, tool } of allTools) {
      const initialized = await tool.init()
      expect(typeof initialized.description).toBe("string")
      expect(initialized.description.length).toBeGreaterThan(10)
    }
  })

  test("all bridge tools have parameter schemas", async () => {
    for (const { name, tool } of allTools) {
      const initialized = await tool.init()
      expect(initialized.parameters).toBeDefined()
    }
  })

  test("recon tool validates target param", async () => {
    const initialized = await ReconTool.init()
    const schema = initialized.parameters as z.ZodObject<any>
    const valid = schema.safeParse({ target: "example.com" })
    expect(valid.success).toBe(true)

    const invalid = schema.safeParse({})
    expect(invalid.success).toBe(false)
  })

  test("save_finding validates required fields", async () => {
    const initialized = await SaveFindingTool.init()
    const schema = initialized.parameters as z.ZodObject<any>
    const valid = schema.safeParse({
      title: "XSS in search",
      url: "http://example.com/search",
      severity: "high",
      description: "Reflected XSS",
    })
    expect(valid.success).toBe(true)

    const missing = schema.safeParse({ title: "XSS" })
    expect(missing.success).toBe(false)
  })

  test("http_request validates method enum", async () => {
    const initialized = await HttpRequestTool.init()
    const schema = initialized.parameters as z.ZodObject<any>
    const valid = schema.safeParse({
      url: "http://example.com",
      method: "GET",
    })
    expect(valid.success).toBe(true)
  })

  test("create_session requires target", async () => {
    const initialized = await CreateSessionTool.init()
    const schema = initialized.parameters as z.ZodObject<any>
    const valid = schema.safeParse({ target: "http://example.com" })
    expect(valid.success).toBe(true)

    const missing = schema.safeParse({})
    expect(missing.success).toBe(false)
  })
})
