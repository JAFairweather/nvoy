#!/usr/bin/env node
// keyless-wake-watcher.mjs — watch the cleartext outer p-tag of NIP-59 mail.
//
// This process deliberately has NO nsec. It can say only that an envelope for one
// public key reached a relay; it cannot decrypt it, identify its sender, or turn its
// contents into a prompt. The keyed agent runtime must run attention.mjs to decrypt
// and apply the live task-grant gate before presenting anything to an agent.
//
//   WAKE_RECIPIENT=npub1... node tools/keyless-wake-watcher.mjs [--dry-run]
//
// The optional WAKE_COMMAND is an owner-installed fixed command. It is invoked with
// an empty environment addition and no message-derived argv/stdin. A command that
// needs text, a sender, or a secret does not belong here.

import WebSocket from 'ws'
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { homedir } from 'node:os'
import { decode } from 'nostr-tools/nip19'
import { spawn } from 'node:child_process'

const arg = (name, fallback = '') => { const i = process.argv.indexOf(name); return i < 0 ? fallback : process.argv[i + 1] }
const die = msg => { console.error(`keyless-wake: ${msg}`); process.exit(1) }
const rawRecipient = arg('--recipient', process.env.WAKE_RECIPIENT || '')
const recipient = rawRecipient.startsWith('npub1') ? decode(rawRecipient).data : rawRecipient.toLowerCase()
if (!/^[0-9a-f]{64}$/.test(recipient)) die('set WAKE_RECIPIENT (npub or 64-hex public key)')
if (process.env.NVOY_NSEC) die('refusing to start while NVOY_NSEC is set — this watcher must stay keyless')

const relays = (process.env.NVOY_RELAYS?.split(',') || ['wss://nos.lol', 'wss://relay.primal.net', 'wss://relay.ditto.pub'])
  .map(x => x.trim()).filter(Boolean)
const DRY = process.argv.includes('--dry-run')
const cooldown = Number(arg('--cooldown', '90')) * 1000
const statePath = arg('--seen-path', resolve(homedir(), '.nvoy', 'keyless-wake-seen.log'))
const queuePath = arg('--queue-path', resolve(homedir(), '.nvoy', 'keyless-wake-queue.jsonl'))
const markerDir = arg('--marker-dir', '')
const command = process.env.WAKE_COMMAND || ''
const seen = new Set()
try { for (const line of readFileSync(statePath, 'utf8').split('\n')) if (/^[0-9a-f]{64}$/.test(line)) seen.add(line) } catch { /* first run */ }
const mark = id => {
  if (seen.has(id)) return false
  seen.add(id)
  try { mkdirSync(dirname(statePath), { recursive: true }); appendFileSync(statePath, id + '\n') } catch (e) { console.error(`keyless-wake: seen write failed: ${e.message}`); return false }
  if (seen.size > 5000) { const keep = [...seen].slice(-4000); seen.clear(); keep.forEach(x => seen.add(x)); try { writeFileSync(statePath, keep.join('\n') + '\n') } catch {} }
  return true
}
let lastWake = 0
function record(id) {
  const now = Date.now()
  const marker = { observed_at: Math.floor(now / 1000), envelope: id }
  // The per-envelope marker is the authoritative watcher→broker handoff. It is written BEFORE
  // the seen log, so an I/O failure causes the relay event to be retried rather than suppressed.
  if (markerDir) {
    try { mkdirSync(markerDir, { recursive: true }); writeFileSync(resolve(markerDir, `${id}.pending`), JSON.stringify(marker) + '\n', { flag: 'wx', mode: 0o600 }) }
    catch (e) { if (e.code !== 'EEXIST') { console.error(`keyless-wake: marker write failed: ${e.message}`); return false } }
  }
  try { mkdirSync(dirname(queuePath), { recursive: true }); appendFileSync(queuePath, JSON.stringify(marker) + '\n') }
  catch (e) { if (!markerDir) { console.error(`keyless-wake: queue write failed: ${e.message}`); return false } }
  console.log(`keyless-wake: envelope ${id.slice(0, 12)}… recorded — keyed runtime must run attention.mjs`)
  // Every observed envelope is durable. Cooldown applies only to the optional *notification*;
  // applying it to queueing loses authorised arrivals forever once the seen log has advanced.
  if (now - lastWake < cooldown) return true
  lastWake = now
  if (!command || DRY) return true
  // The fixed command receives no arrival data. Its own runtime owns its signer and chooses
  // whether to read the queue, then attention.mjs makes the authorisation decision.
  const child = spawn(command, [], { shell: true, stdio: 'ignore', detached: true })
  child.unref()
  return true
}
function connect(url) {
  let ws
  const open = () => {
    try { ws = new WebSocket(url) } catch { return setTimeout(open, 10_000) }
    ws.on('open', () => ws.send(JSON.stringify(['REQ', 'wake', { kinds: [1059], '#p': [recipient], since: Math.floor(Date.now() / 1000) - 172920 } ])))
    ws.on('message', data => { try { const m = JSON.parse(data.toString()); if (m[0] === 'EVENT' && m[2]?.id && !seen.has(m[2].id) && record(m[2].id)) mark(m[2].id) } catch {} })
    ws.on('close', () => setTimeout(open, 10_000)); ws.on('error', () => {})
  }
  open()
}
for (const relay of relays) connect(relay)
console.log(`keyless-wake: watching ${relays.length} relay(s) for ${recipient.slice(0, 12)}…${DRY ? ' (dry-run)' : ''}`)
