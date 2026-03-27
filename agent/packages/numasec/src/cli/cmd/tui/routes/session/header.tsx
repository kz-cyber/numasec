import { type Accessor, createMemo, createSignal, Match, Show, Switch } from "solid-js"
import { useRouteData } from "@tui/context/route"
import { useSync } from "@tui/context/sync"
import { pipe, sumBy } from "remeda"
import { useTheme } from "@tui/context/theme"
import { SplitBorder } from "@tui/component/border"
import type { AssistantMessage, Session } from "@numasec/sdk/v2"
import { useCommandDialog } from "@tui/component/dialog-command"
import { useKeybind } from "../../context/keybind"
import { Flag } from "@/flag/flag"
import { useTerminalDimensions } from "@opentui/solid"

const Title = (props: { session: Accessor<Session> }) => {
  const { theme } = useTheme()
  return (
    <text fg={theme.text}>
      <span style={{ bold: true }}>#</span> <span style={{ bold: true }}>{props.session().title}</span>
    </text>
  )
}

const ContextInfo = (props: { context: Accessor<string | undefined>; cost: Accessor<string> }) => {
  const { theme } = useTheme()
  return (
    <Show when={props.context()}>
      <text fg={theme.textMuted} wrapMode="none" flexShrink={0}>
        {props.context()} ({props.cost()})
      </text>
    </Show>
  )
}

const WorkspaceInfo = (props: { workspace: Accessor<string | undefined> }) => {
  const { theme } = useTheme()
  return (
    <Show when={props.workspace()}>
      <text fg={theme.textMuted} wrapMode="none" flexShrink={0}>
        {props.workspace()}
      </text>
    </Show>
  )
}

export function Header() {
  const route = useRouteData("session")
  const sync = useSync()
  const session = createMemo(() => sync.session.get(route.sessionID)!)
  const messages = createMemo(() => sync.data.message[route.sessionID] ?? [])

  const cost = createMemo(() => {
    const total = pipe(
      messages(),
      sumBy((x) => (x.role === "assistant" ? x.cost : 0)),
    )
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
    }).format(total)
  })

  const context = createMemo(() => {
    const last = messages().findLast((x) => x.role === "assistant" && x.tokens.output > 0) as AssistantMessage
    if (!last) return
    const total =
      last.tokens.input + last.tokens.output + last.tokens.reasoning + last.tokens.cache.read + last.tokens.cache.write
    const model = sync.data.provider.find((x) => x.id === last.providerID)?.models[last.modelID]
    let result = total.toLocaleString()
    if (model?.limit.context) {
      result += "  " + Math.round((total / model.limit.context) * 100) + "%"
    }
    return result
  })

  const workspace = createMemo(() => {
    const id = session()?.workspaceID
    if (!id) return "Workspace local"
    const info = sync.workspace.get(id)
    if (!info) return `Workspace ${id}`
    return `Workspace ${id} (${info.type})`
  })

  // Derive target URL from recon/create_session tool inputs
  const targetUrl = createMemo(() => {
    for (const msg of messages()) {
      const parts = sync.data.part[msg.id] ?? []
      for (const part of parts) {
        if (part.type !== "tool") continue
        if (!part.tool.includes("create_session") && !part.tool.includes("recon")) continue
        const state = part.state as { input?: Record<string, unknown> }
        const url = state.input?.target ?? state.input?.url ?? state.input?.base_url
        if (typeof url === "string" && url.startsWith("http")) return url
      }
    }
    return undefined
  })

  // Derive OWASP coverage from save_finding tool results
  const owaspCategories = [
    "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10",
  ] as const
  const coverageInfo = createMemo(() => {
    const covered = new Set<string>()
    const categoryRe = /A0[1-9]|A10/g
    for (const msg of messages()) {
      const parts = sync.data.part[msg.id] ?? []
      for (const part of parts) {
        if (part.type !== "tool" || part.state.status !== "completed") continue
        if (!part.tool.includes("save_finding")) continue
        const out = (part.state as { output?: string }).output ?? ""
        const matches = out.match(categoryRe)
        if (matches) matches.forEach((m) => covered.add(m))
      }
    }
    return { covered: covered.size, total: owaspCategories.length }
  })

  const { theme } = useTheme()
  const keybind = useKeybind()
  const command = useCommandDialog()
  const [hover, setHover] = createSignal<"parent" | "prev" | "next" | null>(null)
  const dimensions = useTerminalDimensions()
  const narrow = createMemo(() => dimensions().width < 80)

  return (
    <box flexShrink={0}>
      <box
        paddingTop={1}
        paddingBottom={1}
        paddingLeft={2}
        paddingRight={1}
        {...SplitBorder}
        border={["left"]}
        borderColor={theme.border}
        flexShrink={0}
        backgroundColor={theme.backgroundPanel}
      >
        <Switch>
          <Match when={session()?.parentID}>
            <box flexDirection="column" gap={1}>
              <box flexDirection={narrow() ? "column" : "row"} justifyContent="space-between" gap={narrow() ? 1 : 0}>
                {Flag.NUMASEC_EXPERIMENTAL_WORKSPACES ? (
                  <box flexDirection="column">
                    <text fg={theme.text}>
                      <b>Subagent session</b>
                    </text>
                    <WorkspaceInfo workspace={workspace} />
                  </box>
                ) : (
                  <text fg={theme.text}>
                    <b>Subagent session</b>
                  </text>
                )}

                <ContextInfo context={context} cost={cost} />
              </box>
              <box flexDirection="row" gap={2}>
                <box
                  onMouseOver={() => setHover("parent")}
                  onMouseOut={() => setHover(null)}
                  onMouseUp={() => command.trigger("session.parent")}
                  backgroundColor={hover() === "parent" ? theme.backgroundElement : theme.backgroundPanel}
                >
                  <text fg={theme.text}>
                    Parent <span style={{ fg: theme.textMuted }}>{keybind.print("session_parent")}</span>
                  </text>
                </box>
                <box
                  onMouseOver={() => setHover("prev")}
                  onMouseOut={() => setHover(null)}
                  onMouseUp={() => command.trigger("session.child.previous")}
                  backgroundColor={hover() === "prev" ? theme.backgroundElement : theme.backgroundPanel}
                >
                  <text fg={theme.text}>
                    Prev <span style={{ fg: theme.textMuted }}>{keybind.print("session_child_cycle_reverse")}</span>
                  </text>
                </box>
                <box
                  onMouseOver={() => setHover("next")}
                  onMouseOut={() => setHover(null)}
                  onMouseUp={() => command.trigger("session.child.next")}
                  backgroundColor={hover() === "next" ? theme.backgroundElement : theme.backgroundPanel}
                >
                  <text fg={theme.text}>
                    Next <span style={{ fg: theme.textMuted }}>{keybind.print("session_child_cycle")}</span>
                  </text>
                </box>
              </box>
            </box>
          </Match>
          <Match when={true}>
            <box flexDirection="column" gap={0}>
              <box flexDirection={narrow() ? "column" : "row"} justifyContent="space-between" gap={1}>
                {Flag.NUMASEC_EXPERIMENTAL_WORKSPACES ? (
                  <box flexDirection="column">
                    <Title session={session} />
                    <WorkspaceInfo workspace={workspace} />
                  </box>
                ) : (
                  <Title session={session} />
                )}
                <ContextInfo context={context} cost={cost} />
              </box>
              <Show when={targetUrl() || coverageInfo().covered > 0}>
                <box flexDirection={narrow() ? "column" : "row"} justifyContent="space-between" gap={1}>
                  <Show when={targetUrl()}>
                    <text fg={theme.textMuted} wrapMode="none" flexShrink={1}>
                      ☠ {targetUrl()}
                    </text>
                  </Show>
                  <Show when={coverageInfo().covered > 0}>
                    <text fg={theme.textMuted} wrapMode="none" flexShrink={0}>
                      OWASP {coverageInfo().covered}/{coverageInfo().total}
                    </text>
                  </Show>
                </box>
              </Show>
            </box>
          </Match>
        </Switch>
      </box>
    </box>
  )
}
