// reply_retry.mjs — durable terminal classification for brokered reply requests.
//
// An admitted-reply receipt is deliberately short lived.  Once it is no longer
// live, retrying can never make it valid again and would needlessly re-query
// relays once per broker tick.  Keep only an opaque request id and a bounded
// reason in broker-owned state: this is an audit record, not message storage.

import { appendFileSync, existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

const ID = /^[0-9a-f]{32}$/
const TERMINAL = [
  'admission receipt is missing',
  'admission receipt is not a live broker-bound sender capability',
  'admission receipt no longer has a live matching grant',
]

export function isTerminalReplyFailure(stderr) {
  const text = String(stderr || '')
  return TERMINAL.some(reason => text.includes(reason))
}

export function loadTerminalReplyIds(path) {
  if (!existsSync(path)) return new Set()
  const st = lstatSync(path)
  if (!st.isFile() || st.isSymbolicLink()) throw new Error('terminal reply log is not a regular file')
  const ids = new Set()
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    try {
      const record = JSON.parse(line)
      if (record?.version === 1 && record?.type === 'terminal-reply' && ID.test(String(record.id || ''))) ids.add(record.id)
    } catch { /* trailing partial line never changes retry policy */ }
  }
  return ids
}

// Successful replies already have a broker-owned, immutable outbound record. Derive the
// durable completion set from those records at boot so an append-only request queue does not
// spawn one replay-checking child per completed reply on every daemon tick forever.
export function loadPublishedReplyIds(dir) {
  if (!existsSync(dir)) return new Set()
  const st = lstatSync(dir)
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('outbound reply path is not a regular directory')
  const ids = new Set()
  for (const name of readdirSync(dir)) {
    const match = name.match(/^([0-9a-f]{32})\.json$/)
    if (!match) continue
    const path = resolve(dir, name)
    const file = lstatSync(path)
    if (!file.isFile() || file.isSymbolicLink()) continue
    try {
      const record = JSON.parse(readFileSync(path, 'utf8'))
      if (record?.version === 1 && record?.request_id === match[1] && record?.published === true) ids.add(match[1])
    } catch { /* malformed records remain visible to the normal broker validation path */ }
  }
  return ids
}

export function recordTerminalReply(path, ids, id, stderr, at = Date.now()) {
  if (!ID.test(String(id || ''))) throw new Error('terminal reply id is invalid')
  if (ids.has(id)) return false
  const reason = String(stderr || '').includes('live matching grant') ? 'grant-no-longer-live' : 'receipt-not-live'
  appendFileSync(path, JSON.stringify({ version: 1, type: 'terminal-reply', id, reason, at }) + '\n', { mode: 0o600 })
  ids.add(id)
  return true
}
