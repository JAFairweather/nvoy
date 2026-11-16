// reply_attempt.mjs — one daemon attempt at a queued reply: prepare it, then enact it when the actuator
// says no approval is needed. Split out of instance-broker-daemon.mjs so the retry accounting can be
// tested on the real sequence (nvoy#401, Neil): a successful prepare must not reset the backoff before
// the direct send has also succeeded, or a direct send that keeps failing retries every 5 s forever.
//
// prepare() and direct() return { status, stdout, stderr } like spawnSync. isTerminal(stderr) says a
// failure can never succeed; onTerminal(stderr, phase) records it. Returns one of:
//   'held'      a retryable failure; backoff.fail(key) was recorded
//   'terminal'  recorded by onTerminal; no retry
//   'enacted'   the direct reply was sent; backoff reset
//   'proposed'  awaiting a discrete approval; backoff reset

export function attemptReply({ key, backoff, prepare, direct, isTerminal, onTerminal, log = () => {} }) {
  const proposed = prepare()
  if (proposed.status !== 0) {
    const stderr = String(proposed.stderr || '').trim()
    if (isTerminal(stderr)) { onTerminal(stderr, 'proposal'); return 'terminal' }
    backoff.fail(key)
    log(`proposal held: ${stderr}`)
    return 'held'
  }
  let verdict = null
  try { verdict = JSON.parse(String(proposed.stdout || '')) } catch { verdict = null }
  if (verdict?.approval_required === false && ['nostr-private-reply', 'buzz-channel-reply'].includes(verdict?.action)) {
    const enacted = direct()
    if (enacted.status !== 0) {
      const stderr = String(enacted.stderr || '').trim()
      if (isTerminal(stderr)) { onTerminal(stderr, 'reply'); return 'terminal' }
      backoff.fail(key)
      log(`reply held for retry: ${stderr}`)
      return 'held'
    }
    backoff.ok(key)
    return 'enacted'
  }
  backoff.ok(key)
  return 'proposed'
}
