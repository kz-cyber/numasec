export interface ResolvedSlashCommand {
  command: string
  arguments: string
}

function tokens(value: string) {
  const text = value.trim()
  if (!text) return []
  return text.split(/\s+/)
}

export function resolveSlashCommand(input: string, names: string[]): ResolvedSlashCommand | undefined {
  if (!input.startsWith("/")) return

  const lineBreak = input.indexOf("\n")
  const line = lineBreak === -1 ? input : input.slice(0, lineBreak)
  const rest = lineBreak === -1 ? "" : input.slice(lineBreak + 1)
  const source = tokens(line.slice(1))
  if (source.length === 0) return

  const candidates = Array.from(new Set(names))
    .map((item) => ({
      name: item,
      tokens: tokens(item),
    }))
    .filter((item) => item.tokens.length > 0)
    .sort((a, b) => b.tokens.length - a.tokens.length || b.name.length - a.name.length)

  for (const candidate of candidates) {
    if (candidate.tokens.length > source.length) continue
    let match = true
    for (let i = 0; i < candidate.tokens.length; i++) {
      if (candidate.tokens[i] === source[i]) continue
      match = false
      break
    }
    if (!match) continue

    const head = source.slice(candidate.tokens.length).join(" ")
    const args = rest ? (head ? `${head}\n${rest}` : rest) : head
    return {
      command: candidate.name,
      arguments: args,
    }
  }
}
