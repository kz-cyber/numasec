import { describe, expect, test } from "bun:test"
import { loadTemplates, type KBTemplate } from "../../src/security/kb/loader"
import { KnowledgeRetriever, chunkTemplate, buildRetriever } from "../../src/security/kb/retriever"

// ── Template Loader ──────────────────────────────────────────

describe("loadTemplates", () => {
  test("loads bundled templates", () => {
    const templates = loadTemplates()
    expect(templates.size).toBeGreaterThan(30)
  })

  test("every template has an id field", () => {
    const templates = loadTemplates()
    for (const [id, template] of templates) {
      expect(template.id).toBe(id)
      expect(typeof template.id).toBe("string")
    }
  })

  test("covers all expected categories", () => {
    const templates = loadTemplates()
    const categories = new Set<string>()
    for (const t of templates.values()) {
      if (t.category) categories.add(t.category)
    }

    expect(categories.has("detection")).toBe(true)
    expect(categories.has("exploitation")).toBe(true)
    expect(categories.has("remediation")).toBe(true)
    expect(categories.has("methodology")).toBe(true)
    expect(categories.has("tools")).toBe(true)
  })

  test("methodology templates exist (≥5)", () => {
    const templates = loadTemplates()
    const methodology = [...templates.values()].filter((t) => t.category === "methodology")
    expect(methodology.length).toBeGreaterThanOrEqual(5)
  })

  test("tools templates exist (≥8)", () => {
    const templates = loadTemplates()
    const tools = [...templates.values()].filter((t) => t.category === "tools")
    expect(tools.length).toBeGreaterThanOrEqual(8)
  })

  test("excludes bundled when option set", () => {
    const templates = loadTemplates([], { includeBundled: false })
    expect(templates.size).toBe(0)
  })

  test("handles non-existent extra directory gracefully", () => {
    const templates = loadTemplates(["/nonexistent/path/xyz"])
    expect(templates.size).toBeGreaterThan(0)
  })
})

// ── Chunker ──────────────────────────────────────────────────

describe("chunkTemplate", () => {
  test("produces chunks from template", () => {
    const template: KBTemplate = {
      id: "test-template",
      title: "Test Template",
      category: "detection",
      content: "This is test content about SQL injection detection techniques.",
    }

    const chunks = chunkTemplate(template)
    expect(chunks.length).toBeGreaterThan(0)
    expect(chunks[0].templateId).toBe("test-template")
    expect(chunks[0].category).toBe("detection")
  })

  test("skips metadata fields", () => {
    const template: KBTemplate = {
      id: "test",
      title: "Title",
      category: "detection",
      version: "1.0",
      tags: ["sql", "injection"],
      cwe_ids: ["CWE-89"],
      content: "Actual content here.",
    }

    const chunks = chunkTemplate(template)
    expect(chunks.some((c) => c.section === "id")).toBe(false)
    expect(chunks.some((c) => c.section === "category")).toBe(false)
  })

  test("handles object values as sections", () => {
    const template: KBTemplate = {
      id: "test",
      category: "detection",
      techniques: {
        passive: "observe responses",
        active: "send payloads",
      },
    }

    const chunks = chunkTemplate(template)
    expect(chunks.length).toBeGreaterThan(0)
  })

  test("handles array values", () => {
    const template: KBTemplate = {
      id: "test",
      category: "detection",
      steps: ["Step 1", "Step 2", "Step 3"],
    }

    const chunks = chunkTemplate(template)
    expect(chunks.length).toBeGreaterThan(0)
    const text = chunks.map((c) => c.text).join(" ")
    expect(text).toContain("Step 1")
  })
})

// ── BM25 Retriever ───────────────────────────────────────────

describe("KnowledgeRetriever", () => {
  test("empty retriever returns empty results", () => {
    const retriever = new KnowledgeRetriever()
    expect(retriever.query("sql injection")).toEqual([])
  })

  test("basic BM25 search returns relevant chunks", () => {
    const retriever = new KnowledgeRetriever([
      { text: "SQL injection detection using single quote payloads", section: "content", templateId: "sqli", category: "detection", score: 0, metadata: {} },
      { text: "XSS detection using script tag injection", section: "content", templateId: "xss", category: "detection", score: 0, metadata: {} },
      { text: "CSRF token validation bypass techniques", section: "content", templateId: "csrf", category: "exploitation", score: 0, metadata: {} },
    ])

    const results = retriever.query("sql injection")
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].templateId).toBe("sqli")
    expect(results[0].score).toBeGreaterThan(0)
  })

  test("category filter restricts results", () => {
    const retriever = new KnowledgeRetriever([
      { text: "SQL injection detection", section: "content", templateId: "sqli-detect", category: "detection", score: 0, metadata: {} },
      { text: "SQL injection exploitation", section: "content", templateId: "sqli-exploit", category: "exploitation", score: 0, metadata: {} },
    ])

    const results = retriever.query("sql injection", { category: "exploitation" })
    expect(results.length).toBe(1)
    expect(results[0].category).toBe("exploitation")
  })

  test("topK limits results", () => {
    const chunks = Array.from({ length: 20 }, (_, i) => ({
      text: `SQL injection variant ${i} detection technique`,
      section: "content",
      templateId: `sqli-${i}`,
      category: "detection",
      score: 0,
      metadata: {},
    }))

    const retriever = new KnowledgeRetriever(chunks)
    const results = retriever.query("sql injection detection", { topK: 3 })
    expect(results.length).toBeLessThanOrEqual(3)
  })

  test("addChunks updates the index", () => {
    const retriever = new KnowledgeRetriever()
    expect(retriever.query("test").length).toBe(0)

    retriever.addChunks([
      { text: "Test content for searching", section: "content", templateId: "test", category: "test", score: 0, metadata: {} },
    ])

    expect(retriever.query("test content").length).toBe(1)
  })

  test("empty query returns empty results", () => {
    const retriever = new KnowledgeRetriever([
      { text: "Some content", section: "content", templateId: "t", category: "c", score: 0, metadata: {} },
    ])

    expect(retriever.query("").length).toBe(0)
  })

  test("results are sorted by score descending", () => {
    const chunks = [
      { text: "SQL injection single quote test", section: "content", templateId: "a", category: "detection", score: 0, metadata: {} },
      { text: "SQL injection union select blind boolean time-based SQL injection", section: "content", templateId: "b", category: "detection", score: 0, metadata: {} },
      { text: "CSRF token validation", section: "content", templateId: "c", category: "detection", score: 0, metadata: {} },
    ]

    const retriever = new KnowledgeRetriever(chunks)
    const results = retriever.query("sql injection")

    for (let i = 1; i < results.length; i++) {
      expect(results[i - 1].score).toBeGreaterThanOrEqual(results[i].score)
    }
  })
})

describe("buildRetriever", () => {
  test("builds retriever from loaded templates", () => {
    const templates = loadTemplates()
    const retriever = buildRetriever(templates)

    const results = retriever.query("sql injection detection")
    expect(results.length).toBeGreaterThan(0)
  })

  test("retriever finds methodology templates", () => {
    const templates = loadTemplates()
    const retriever = buildRetriever(templates)

    const results = retriever.query("web application penetration test methodology", { category: "methodology" })
    expect(results.length).toBeGreaterThan(0)
  })

  test("retriever finds tool guides", () => {
    const templates = loadTemplates()
    const retriever = buildRetriever(templates)

    const results = retriever.query("nmap port scanning", { category: "tools" })
    expect(results.length).toBeGreaterThan(0)
  })
})
