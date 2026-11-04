// What the relays said when a broker looked for a sender's grant, in a form that can be logged.
//
// "No grant" used to be silent and was always believed. On 10-19 nos.lol had evicted every grant,
// so every relay answered, every answer was empty, and every mention was dropped as data only
// with nothing in the logs. An answer is only as good as the relay's memory: when every relay
// that answered returned nothing, yet some relay has held this identity's grants before, the
// "no" is marked suspect. Revocations are events too, so a genuine withdrawal does not look empty.
//
// The history is the minimum needed for that judgement: which relays have ever returned grant
// events, and when that was last noted. No grant, sender or content is stored.

import { readFileSync, renameSync, writeFileSync } from 'node:fs'

const IP_HOST = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\])(?::\d+)?$/i
// A relay that keeps answering is re-noted at most hourly, so a busy broker does not rewrite the
// file on every message.
const NOTE_EVERY_MS = 60 * 60 * 1000

// A public relay is named by its host; an address literal is not printed.
export function relayLabel(url, index = 0) {
  let host = ''
  try { host = new URL(String(url)).host.toLowerCase() } catch { /* unlabelled */ }
  return host && !IP_HOST.test(host) ? host : `relay#${index + 1}`
}

export function readGrantHistory(path) {
  try {
    const relays = JSON.parse(readFileSync(path, 'utf8'))?.relays
    return relays && typeof relays === 'object' && !Array.isArray(relays) ? relays : {}
  } catch { return {} }
}

// `relays` is attention's per-relay answer: [{ relay, answered, events }].
export function grantLookup(path, relays, { now = Date.now() } = {}) {
  const rows = (Array.isArray(relays) ? relays : []).map((r, i) => ({ label: relayLabel(r?.relay, i), answered: r?.answered === true,
    events: Number.isSafeInteger(r?.events) && r.events > 0 ? r.events : 0 }))
  const history = readGrantHistory(path)
  const holding = rows.filter(r => r.events > 0)
  if (holding.some(r => !Number.isFinite(history[r.label]) || now - history[r.label] >= NOTE_EVERY_MS)) {
    const next = { ...history }
    for (const r of holding) next[r.label] = now
    // Evidence, never a gate: an unwritable history only costs the suspect judgement later.
    try {
      const tmp = `${path}.${process.pid}.tmp`
      writeFileSync(tmp, JSON.stringify({ version: 1, relays: next }) + '\n', { mode: 0o600 })
      renameSync(tmp, path)
    } catch { /* see above */ }
  }
  const heldBefore = Object.keys(history).sort()
  return {
    suspect: rows.some(r => r.answered) && !holding.length && heldBefore.length > 0,
    heldBefore,
    summary: rows.map(r => `${r.label}=${r.answered ? r.events : 'unanswered'}`).join(' ') || 'none',
  }
}

export const noGrantVerdict = lookup => lookup.suspect
  ? `no-grant-suspect: every relay returned no grant events, but ${lookup.heldBefore.join(', ')} held them before; relays ${lookup.summary}`
  : `no-grant: relays ${lookup.summary}`
