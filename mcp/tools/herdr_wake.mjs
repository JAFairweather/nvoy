// Wake an agent in a herdr pane from its channel's wake markers. Claude Code turns a channel's
// `notifications/claude/channel` into a prompt by itself; a client that cannot (the Antigravity CLI,
// agy) holds the same one channel session, and this types the prompt into its pane instead. One
// session keeps the channel lock rule whole: a second session for the identity would be refused.
//
// Only what is checked reaches the terminal: an envelope id must be 64 hex characters, and the line
// is built here, never copied from the server. The message itself stays on the fleet, read through
// nvoy_channel_read. A wake is typed only while herdr reports the agent idle, so it never lands in
// the middle of a turn; until then wakes wait, deduplicated, and go as one line.

const HEX64 = /^[0-9a-f]{64}$/

export function wakeOf(message) {
  if (message?.method !== 'notifications/claude/channel') return null
  const meta = message.params?.meta || {}
  if (typeof meta.envelope === 'string' && HEX64.test(meta.envelope)) return { envelope: meta.envelope }
  if (meta.capabilities !== undefined) return { capabilities: true }
  return null
}

export function wakeLine({ envelopes, capabilities }) {
  const parts = []
  if (envelopes.length === 1) parts.push(`nvoy wake: envelope ${envelopes[0]} is ready. Read it with nvoy_channel_read before deciding whether to act.`)
  if (envelopes.length > 1) parts.push(`nvoy wake: envelopes ${envelopes.join(', ')} are ready. Read each with nvoy_channel_read before deciding whether to act.`)
  if (capabilities) parts.push('nvoy: this identity\'s capabilities changed. Call nvoy_channel_list once to acknowledge.')
  return parts.join(' ')
}

export function herdrWaker({ agent, herdr, log = () => {}, everyMs = 2000, maxQueued = 64, settleMs = 300 }) {
  const seen = new Set(), envelopes = []
  let capabilities = false, missing = false, busy = false
  const sleep = ms => new Promise(done => setTimeout(done, ms))
  const tick = async () => {
    if (busy || (!envelopes.length && !capabilities)) return
    busy = true
    try {
      const found = herdr.agentNamed(agent)
      if (!found) { if (!missing) log(`herdr has no agent named ${agent}; holding ${envelopes.length} wake(s)`); missing = true; return }
      missing = false
      if (found.agent_status !== 'idle') return
      const line = wakeLine({ envelopes, capabilities })
      herdr.text(found.pane_id, line)
      await sleep(settleMs)
      herdr.keys(found.pane_id, 'Enter')
      log(`woke ${agent} in ${found.pane_id}: ${envelopes.length} envelope(s)${capabilities ? ', capabilities' : ''}`)
      envelopes.length = 0; capabilities = false
    } catch (error) { log(`wake for ${agent} failed, will retry: ${error.message}`) }
    finally { busy = false }
  }
  const timer = setInterval(tick, everyMs)
  timer.unref?.()
  return {
    notice(message) {
      const wake = wakeOf(message)
      if (!wake) return false
      if (wake.capabilities) capabilities = true
      else if (!seen.has(wake.envelope)) {
        seen.add(wake.envelope)
        if (seen.size > 4096) seen.delete(seen.values().next().value)
        if (envelopes.length >= maxQueued) envelopes.shift()
        envelopes.push(wake.envelope)
      }
      setImmediate(tick)
      return true
    },
    stop() { clearInterval(timer) },
  }
}
