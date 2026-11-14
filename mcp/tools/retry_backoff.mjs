// retry_backoff.mjs — how long the broker daemon waits before retrying held work.
//
// A held delivery, post, memory claim or reply used to retry every 5 s for as long as it failed. Each
// retry is a fresh process that opens a NIP-46 session (connect + get_public_key) before doing
// anything, so a signer outage turned every held item into about 24 Bunker requests a minute,
// indefinitely (14 Nov: about 140k Bunker actions in a day, mostly get_public_key). Now each key
// waits 5 s after its first failure, doubling to a cap, and starts again from nothing on success.

export const RETRY_BASE_MS = 5000
export const RETRY_MAX_MS = 120000

export function createBackoff({ baseMs = RETRY_BASE_MS, maxMs = RETRY_MAX_MS, now = () => Date.now() } = {}) {
  const state = new Map()
  return Object.freeze({
    // True when `key` has no wait pending.
    ready(key) { const s = state.get(key); return !s || s.until <= now() },
    // Records a failure; returns the wait in ms before the next attempt.
    fail(key) {
      const failures = (state.get(key)?.failures || 0) + 1
      const wait = Math.min(maxMs, baseMs * 2 ** Math.min(failures - 1, 30))
      state.set(key, { failures, until: now() + wait })
      return wait
    },
    // Records a success (or a terminal outcome): the next failure waits baseMs again.
    ok(key) { state.delete(key) },
    failures(key) { return state.get(key)?.failures || 0 },
  })
}
