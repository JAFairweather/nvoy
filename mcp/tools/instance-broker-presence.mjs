// instance-broker-presence.mjs — sign and publish this agent's channel presence (waggle #721 step 4).
//
// The broker daemon runs it every 30 s. It reads the host collector's snapshot (presence-collect.mjs,
// mounted read-only), judges it (presence.mjs), and signs only when the state changed or the last event
// is due for a refresh. An unproven snapshot (missing, stale, older untagged sessions only) signs
// nothing: a collector outage is never published as a drop. The signed event is recorded before it is
// sent, and a retry sends that same record, so a late `connected: true` cannot follow a newer state.

import { readFileSync, renameSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { verifyEvent } from 'nostr-tools/pure'
import WebSocket from 'ws'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { cardRelays } from './agent_card.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { PRESENCE_D, PRESENCE_KIND, nextPresence, presenceTemplate, presenceVerdict } from './presence.mjs'

const flag = name => { const index = process.argv.indexOf(name); return index < 0 ? '' : process.argv[index + 1] || '' }
const id = flag('--instance')
if (!id) throw new Error('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
const manifest = readManifest(root, instanceId(id))
assertNoCollisions(root, manifest)
const snapshotPath = resolve(process.env.NVOY_PRESENCE_DIR || '/run/nvoy-presence', `${manifest.id}.json`)
const statePath = resolve(manifest.stateDir, 'presence.json')
const relays = () => cardRelays(process.env.NVOY_PRESENCE_RELAYS || '')

const readJson = path => { try { return JSON.parse(readFileSync(path, 'utf8')) } catch (error) { if (error.code !== 'ENOENT') console.error(`instance-broker-presence: ignoring unreadable ${path}`); return null } }
let last = readJson(statePath)
const record = value => {
  const temporary = `${statePath}.${process.pid}.tmp`
  writeFileSync(temporary, JSON.stringify(value), { mode: 0o600 })
  renameSync(temporary, statePath)
}

function publishAndReadBack(url, event) {
  return new Promise(done => {
    const result = { relay: url, accepted: false, read_back: false, message: '' }
    let settled = false
    const ws = new WebSocket(url)
    const finish = message => {
      if (settled) return
      settled = true; clearTimeout(timer)
      if (message) result.message = String(message).slice(0, 160)
      try { ws.close() } catch {}
      done(result)
    }
    const timer = setTimeout(() => finish(result.accepted ? 'read-back timed out' : 'timed out'), 10000)
    ws.on('open', () => ws.send(JSON.stringify(['EVENT', event])))
    ws.on('message', raw => {
      let frame
      try { frame = JSON.parse(raw.toString()) } catch { return }
      if (frame[0] === 'OK' && frame[1] === event.id) {
        result.accepted = !!frame[2]
        if (!result.accepted) return finish(frame[3] || 'refused')
        ws.send(JSON.stringify(['REQ', 'presence', { kinds: [PRESENCE_KIND], authors: [event.pubkey], '#d': [PRESENCE_D], limit: 1 }]))
      }
      if (frame[0] === 'EVENT' && frame[1] === 'presence' && frame[2]?.id === event.id) result.read_back = true
      if (frame[0] === 'EOSE' && frame[1] === 'presence') finish(result.read_back ? '' : 'not read back')
    })
    ws.on('error', error => finish(error.message))
  })
}

const now = Date.now()
const snapshot = readJson(snapshotPath)
// The collector is the trust anchor for which key the installed seat binds: it read that line as root.
const fp = snapshot?.key_fp || ''
const verdict = presenceVerdict(snapshot, { instance: manifest.id, fp, now })
const owed = nextPresence(last, verdict, now)
if (owed) {
  let keys
  try {
    keys = brokerSigner(message => { throw new Error(message) }, { idleMs: 30000 })
    const template = presenceTemplate({ instance: manifest.id, fp, ...owed, seenAt: owed.seen_at }, now, last?.event?.created_at)
    const event = await keys.signer.signEvent({ pubkey: manifest.pubkey, ...template })
    if (event?.pubkey !== manifest.pubkey || event.kind !== PRESENCE_KIND || event.content !== template.content ||
        JSON.stringify(event.tags) !== JSON.stringify(template.tags) || !verifyEvent(event)) throw new Error('signer returned a different presence event')
    // The newest decision replaces the record before anything is sent; older ones are never retried.
    last = { version: 1, connected: owed.connected, since: owed.since, event_at: owed.seen_at, event, relays: [] }
    record(last)
  } finally {
    try { keys?.signer?.close?.() } catch {}
  }
}
if (!last?.event) { console.log(JSON.stringify({ presence: 'nothing to publish', verdict: verdict.state, why: verdict.why || '' })); process.exit(0) }
const live = Number(last.event.tags.find(t => t[0] === 'expiration')?.[1]) > Math.floor(now / 1000)
const pending = relays().filter(url => !(last.relays || []).some(r => r.relay === url && r.read_back))
if (!live || !pending.length) {
  console.log(JSON.stringify({ presence: live ? 'current' : 'expired', verdict: verdict.state, why: verdict.why || '', event_id: last.event.id }))
  process.exit(0)
}
const results = await Promise.all(pending.map(url => publishAndReadBack(url, last.event)))
last.relays = [...(last.relays || []).filter(r => !pending.includes(r.relay)), ...results]
record(last)
const missing = results.filter(r => !r.read_back)
console.log(JSON.stringify({ presence: missing.length ? 'incomplete' : 'published', connected: last.connected, event_id: last.event.id, missing: missing.map(r => `${r.relay}: ${r.message}`) }))
if (missing.length) process.exitCode = 1
