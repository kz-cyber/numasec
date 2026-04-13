import { createMemo, onMount } from "solid-js"
import { useSync } from "@tui/context/sync"
import { DialogSelect, type DialogSelectOption } from "@tui/ui/dialog-select"
import type { TextPart } from "@numasec/sdk/v2"
import { Locale } from "@/util/locale"
import { DialogMessage } from "./dialog-message"
import { useDialog } from "../../ui/dialog"
import type { PromptInfo } from "../../component/prompt/history"

const OLDER_OPTION = "__older_messages__"

export function DialogTimeline(props: {
  sessionID: string
  onMove: (messageID: string) => void
  setPrompt?: (prompt: PromptInfo) => void
}) {
  const sync = useSync()
  const dialog = useDialog()

  onMount(() => {
    dialog.setSize("large")
  })

  const options = createMemo((): DialogSelectOption<string>[] => {
    const messages = sync.data.message[props.sessionID] ?? []
    const result = [] as DialogSelectOption<string>[]
    for (const message of messages) {
      if (message.role !== "user") continue
      const part = (sync.data.part[message.id] ?? []).find(
        (x) => x.type === "text" && !x.synthetic && !x.ignored,
      ) as TextPart
      if (!part) continue
      result.push({
        title: part.text.replace(/\n/g, " "),
        value: message.id,
        footer: Locale.time(message.time.created),
        onSelect: (dialog) => {
          dialog.replace(() => (
            <DialogMessage messageID={message.id} sessionID={props.sessionID} setPrompt={props.setPrompt} />
          ))
        },
      })
    }
    result.reverse()
    const loading = sync.session.loadingOlder(props.sessionID)
    const older = sync.session.hasOlder(props.sessionID)
    if (loading || older) {
      result.unshift({
        title: loading ? "Loading older messages..." : "Load older messages",
        value: OLDER_OPTION,
        description: loading ? "Please wait" : "Fetch older timeline messages",
        onSelect: async (dialog) => {
          if (sync.session.loadingOlder(props.sessionID)) return
          await sync.session.loadOlder(props.sessionID)
          dialog.replace(() => (
            <DialogTimeline sessionID={props.sessionID} onMove={props.onMove} setPrompt={props.setPrompt} />
          ))
        },
      })
    }
    return result
  })

  return (
    <DialogSelect
      onMove={(option) => {
        if (option.value === OLDER_OPTION) return
        props.onMove(option.value)
      }}
      title="Timeline"
      options={options()}
    />
  )
}
