// Relay login pacing for a long-lived watcher. Every login costs a Bunker signature, so the
// watcher logged in ~8k times a day at baseline and ~60k a day once its logins began failing.
//
// The backoff resets only after a session has stayed up for `stableMs`. Resetting it on the
// first EOSE, as before, let a relay that accepts a login and then drops the socket drive a
// reconnect every second or so forever. Equal jitter keeps several watchers from reconnecting
// in lockstep after a shared outage.

export function loginBackoff({ baseMs = 1000, maxMs = 5 * 60 * 1000, stableMs = 2 * 60 * 1000, random = Math.random } = {}) {
  let ceiling = baseMs
  return Object.freeze({
    next() {
      const delay = Math.round(ceiling / 2 + random() * ceiling / 2)
      ceiling = Math.min(ceiling * 2, maxMs)
      return Math.min(delay, maxMs)
    },
    sessionEnded(livedMs) { if (livedMs >= stableMs) ceiling = baseMs },
    get ceiling() { return ceiling },
  })
}

// At most one login in flight: a second caller shares the first attempt instead of starting another.
export function singleFlight(fn) {
  let inflight = null
  return () => (inflight ??= Promise.resolve().then(fn).finally(() => { inflight = null }))
}
