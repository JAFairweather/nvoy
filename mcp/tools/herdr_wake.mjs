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

export function wakeLine({ envelopes, capabilities, overflow = false }) {
  const parts = []
  if (envelopes.length === 1) parts.push(`nvoy wake: envelope ${envelopes[0]} is ready. Read it with nvoy_channel_read before deciding whether to act.`)
  if (envelopes.length > 1) parts.push(`nvoy wake: envelopes ${envelopes.join(', ')} are ready. Read each with nvoy_channel_read before deciding whether to act.`)
  if (capabilities) parts.push('nvoy: this identity\'s capabilities changed. Call nvoy_channel_list once to acknowledge.')
  if (overflow) parts.push('nvoy: more envelopes arrived than one wake holds. Call nvoy_channel_list to find the rest.')
  return parts.join(' ')
}

// A batch is fixed when it is typed: wakes that arrive while it is typed or settling wait for the
// next one, and only what was submitted is retired. Text typed but not submitted (Enter failed) is
// submitted on the next try, never typed again. An envelope dropped from a full queue is forgotten,
// so a reannouncement can queue it again, and the next wake asks for nvoy_channel_list to find it.
export function herdrWaker({ agent, herdr, log = () => {}, everyMs = 2000, maxQueued = 64, settleMs = 300 }) {
  const seen = new Set()
  let envelopes = [], capabilities = 0, overflow = 0, pasted = null, missing = false, busy = false
  const sleep = ms => new Promise(done => setTimeout(done, ms))
  const retire = batch => {
    const done = new Set(batch.envelopes)
    envelopes = envelopes.filter(e => !done.has(e))
    if (batch.capabilities) capabilities = Math.max(0, capabilities - batch.capabilities)
    if (batch.overflow && overflow === batch.overflow) overflow = 0
    log(`woke ${agent} in ${batch.pane}: ${batch.envelopes.length} envelope(s)${batch.capabilities ? ', capabilities' : ''}${batch.overflow ? ', overflow' : ''}`)
  }
  const tick = async () => {
    if (busy || (!pasted && !envelopes.length && !capabilities && !overflow)) return
    busy = true
    try {
      const found = herdr.agentNamed(agent)
      if (!found) { if (!missing) log(`herdr has no agent named ${agent}; holding ${envelopes.length} wake(s)`); missing = true; return }
      missing = false
      if (found.agent_status !== 'idle') return
      if (pasted && pasted.pane !== found.pane_id) pasted = null
      if (!pasted) {
        const batch = { pane: found.pane_id, envelopes: envelopes.slice(), capabilities, overflow }
        herdr.text(batch.pane, wakeLine({ envelopes: batch.envelopes, capabilities: batch.capabilities > 0, overflow: Boolean(batch.overflow) }))
        pasted = batch
        await sleep(settleMs)
      }
      herdr.keys(pasted.pane, 'Enter')
      retire(pasted)
      pasted = null
    } catch (error) { log(`wake for ${agent} failed, will retry: ${error.message}`) }
    finally { busy = false }
  }
  const timer = setInterval(tick, everyMs)
  timer.unref?.()
  return {
    notice(message) {
      const wake = wakeOf(message)
      if (!wake) return false
      if (wake.capabilities) capabilities += 1
      else if (!seen.has(wake.envelope) && !envelopes.includes(wake.envelope)) {
        seen.add(wake.envelope)
        if (seen.size > 4096) seen.delete(seen.values().next().value)
        if (envelopes.length >= maxQueued) { seen.delete(envelopes.shift()); overflow += 1 }
        envelopes.push(wake.envelope)
      }
      setImmediate(tick)
      return true
    },
    stop() { clearInterval(timer) },
  }
}
