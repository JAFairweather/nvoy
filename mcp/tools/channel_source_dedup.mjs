// Durable replay boundary for grant-authorized channel carries.
//
// A carrier may legitimately retry one outer envelope, but it must never amplify one signed
// source event by rewrapping it under fresh kind:1059 ids. The broker owns this append-only index
// and claims the source before it creates a reply receipt or exposes plaintext to an adapter.

import { appendFileSync, existsSync, lstatSync, readFileSync } from 'node:fs'

const HEX64 = /^[0-9a-f]{64}$/

function records(path) {
  if (!existsSync(path)) return []
  const st = lstatSync(path)
  if (!st.isFile() || st.isSymbolicLink()) throw new Error('channel source index is not a regular file')
  return readFileSync(path, 'utf8').split('\n').flatMap(line => {
    try {
      const row = JSON.parse(line)
      return row?.version === 1 && HEX64.test(String(row.source_event || '')) &&
        HEX64.test(String(row.envelope || '')) && ['claimed', 'delivered'].includes(row.state) ? [row] : []
    } catch { return [] }
  })
}

export function claimChannelSource(path, sourceEvent, envelope, at = Date.now()) {
  if (!HEX64.test(String(sourceEvent || '')) || !HEX64.test(String(envelope || ''))) throw new Error('channel source claim is invalid')
  const prior = records(path).reverse().find(row => row.source_event === sourceEvent)
  if (prior) return { accepted: prior.envelope === envelope, replay: prior.envelope === envelope, prior }
  appendFileSync(path, JSON.stringify({ version: 1, source_event: sourceEvent, envelope, state: 'claimed', at }) + '\n', { mode: 0o600 })
  return { accepted: true, replay: false }
}

export function completeChannelSource(path, sourceEvent, envelope, at = Date.now()) {
  const prior = records(path).reverse().find(row => row.source_event === sourceEvent)
  if (!prior || prior.envelope !== envelope) throw new Error('channel source completion has no matching claim')
  if (prior.state === 'delivered') return false
  appendFileSync(path, JSON.stringify({ version: 1, source_event: sourceEvent, envelope, state: 'delivered', at }) + '\n', { mode: 0o600 })
  return true
}

export function channelSourceClaims(path) {
  const out = new Map()
  for (const row of records(path)) out.set(row.source_event, row)
  return out
}
