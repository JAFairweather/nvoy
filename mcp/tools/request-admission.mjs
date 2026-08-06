// request-admission.mjs — a participant asks the maintainer to admit its identity to a waggle
// channel. By default it mints an EPHEMERAL key (waggle#141). A standing participant may instead
// name its already-created mode-0600 nsec file with --key; the secret is never printed.
//
// Why this exists: an interactive session normally generates a throwaway key, gets a
// maintainer-approved NIP-DA grant, acts, and discards it. A standing participant has a different
// bootstrap lifecycle: it is minted once, requests admission under that same identity, then moves
// signing into its dedicated Bunker runtime. --key supports that bootstrap without minting a
// second, incorrect identity.
//
// SECURITY POSTURE — the nsec never enters the agent's transcript. This tool either writes a fresh
// nsec to a 0600 tmpfile or descriptor-pins a caller-selected 0600 nsec file, then prints only its
// PATH + the public npub. The session then chats with
//   NVOY_NSEC=$(cat <path>) node tools/relay-send.mjs        (shell substitutes it; agent never reads it)
// and burns it with `shred -u <path>` (or `rm`) on exit. This mirrors how claude-identity.env is
// used: the value goes file → env → tool, never through the model's eyes.
//
// Usage:
//   node tools/request-admission.mjs --purpose "review #140 with the crew"
//   node tools/request-admission.mjs --key /absolute/path/identity.nsec --purpose "Claude runtime"
//   node tools/request-admission.mjs --channel <uuid> --maintainer <npub|hex> --purpose "…"
//   DRY_RUN=1 node tools/request-admission.mjs --purpose "…"     # mint + build, publish nothing
//
// Defaults: channel = #waggle-test, maintainer = James's npub (the grantor). Override via flags/env.
//
// After it runs: the request lands in the maintainer's inbox (a sealed NIP-17 DM). The maintainer
// approves by issuing the grant — `grant.mjs issue --to <this npub> --channel <uuid> --cap admit`
// (see waggle tools/grant.mjs) — which admits the session key AND, once #141's grant↔return-lane
// linkage lands, auto-registers it for reply delivery. Confirm admission by a cold read-back
// (first relay-send acks) before treating yourself as in.

import { getPublicKey, getEventHash, finalizeEvent, generateSecretKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import * as nip44 from 'nostr-tools/nip44'
import { writeFileSync, mkdtempSync, openSync, fstatSync, readFileSync, closeSync, constants } from 'node:fs'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import WebSocket from 'ws'

const flag = (n, d) => { const i = process.argv.indexOf(n); return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : d }
const CHANNEL = flag('--channel', process.env.RELAY_CHANNEL || 'a8186b53-537d-46ad-a7e7-b6486c58970e')
const MAINT_RAW = flag('--maintainer', process.env.WAGGLE_MAINTAINER_NPUB ||
  '4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d')
const MAINT = MAINT_RAW.startsWith('npub1') ? nip19.decode(MAINT_RAW).data : MAINT_RAW.toLowerCase()
const PURPOSE = flag('--purpose', '(unspecified)')
const EXISTING_KEY = flag('--key', null)
const RELAYS = (process.env.RELAY_RELAYS || 'wss://nos.lol,wss://relay.primal.net')
  .split(',').map(s => s.trim()).filter(Boolean)
const DRY = !!process.env.DRY_RUN

function loadSecret(path) {
  const absolute = resolve(path)
  let fd
  try { fd = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW) }
  catch { throw new Error('--key must name a readable regular, non-symlink file') }
  let encoded
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile()) throw new Error('--key must name a regular file')
    if ((stat.mode & 0o077) !== 0) throw new Error('--key file must be mode 0600 (not group/world accessible)')
    if (stat.size < 60 || stat.size > 256) throw new Error('--key file has an invalid size')
    encoded = readFileSync(fd, 'utf8').trim()
  } finally { closeSync(fd) }
  let decoded
  try { decoded = nip19.decode(encoded) } catch { throw new Error('--key file must contain one valid nsec') }
  if (decoded.type !== 'nsec' || !(decoded.data instanceof Uint8Array) || decoded.data.length !== 32) {
    throw new Error('--key file must contain one valid nsec')
  }
  return { sk: decoded.data, path: absolute }
}

// 1. Reuse the explicitly assigned participant key, or mint an ephemeral session key.
let sk, keyPath, ephemeral = false
if (EXISTING_KEY) {
  ({ sk, path: keyPath } = loadSecret(EXISTING_KEY))
} else {
  sk = generateSecretKey()
  ephemeral = true
}
const pk = getPublicKey(sk)
const npub = nip19.npubEncode(pk)

// 2. Build the admission request — a structured payload the maintainer's approval step can parse.
const now = Math.floor(Date.now() / 1000)
const request = { type: 'waggle_admission_request', v: 1, npub, channel: CHANNEL, cap: 'admit', purpose: PURPOSE, ts: now }

// Seal it as a NIP-17 DM to the maintainer (rumor kind:14 → seal kind:13 signed by the session key
// → 1059 wrap under a throwaway key). A fresh key can gift-wrap a DM with no prior grant — the
// whole point: this is how an un-admitted key bootstraps a request.
const rumor = { kind: 14, pubkey: pk, created_at: now, tags: [['p', MAINT], ['subject', 'waggle-admission-request']], content: JSON.stringify(request) }
rumor.id = getEventHash(rumor)
const seal = finalizeEvent({ kind: 13, created_at: now, tags: [], content: nip44.encrypt(JSON.stringify(rumor), nip44.getConversationKey(sk, MAINT)) }, sk)
const wsk = generateSecretKey()
const wrap = finalizeEvent({ kind: 1059, created_at: now, tags: [['p', MAINT]], content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(wsk, MAINT)) }, wsk)

// 3. Stash the nsec in a 0600 tmpfile — NOT stdout. The agent references it by path only.
if (ephemeral) {
  const dir = mkdtempSync(resolve(tmpdir(), 'waggle-session-'))
  keyPath = resolve(dir, 'session.nsec')
  writeFileSync(keyPath, nip19.nsecEncode(sk), { mode: 0o600 })
}

console.error(`request-admission: ${ephemeral ? 'minted session' : 'existing participant'} npub ${npub}`)
console.error(`  participant key (0600, path only — do NOT cat into your context): ${keyPath}`)
console.error(`  request: admit to channel ${CHANNEL.slice(0, 8)}…  purpose: ${PURPOSE}`)
console.error(`  to the maintainer ${MAINT.slice(0, 8)}…  (wrap ${wrap.id.slice(0, 12)}…, ${JSON.stringify(wrap).length}B)`)

if (DRY) { console.error('request-admission: DRY_RUN — nothing published'); console.log(keyPath); process.exit(0) }

let ok = 0
for (const url of RELAYS) {
  await new Promise((r) => {
    const ws = new WebSocket(url); let done = false
    const t = setTimeout(() => { if (!done) { done = true; try { ws.close() } catch { /* */ } r() } }, 9000)
    ws.on('open', () => ws.send(JSON.stringify(['EVENT', wrap])))
    ws.on('message', (m) => { try {
      const x = JSON.parse(m.toString())
      if (x[0] === 'OK' && x[1] === wrap.id) { if (x[2]) ok++
        console.error(`  ${url.replace('wss://', '')}: ${x[2] ? 'OK' : 'REJECTED ' + (x[3] || '')}`)
        done = true; clearTimeout(t); try { ws.close() } catch { /* */ } r() }
    } catch { /* non-OK */ } })
    ws.on('error', () => { if (!done) { done = true; clearTimeout(t); r() } })
  })
}
console.error(`request-admission: request delivered to ${ok}/${RELAYS.length} relay(s).`)
console.error(`  next: ask the maintainer to run  grant.mjs issue --to ${npub} --channel ${CHANNEL} --cap admit`)
console.error(`  then chat:  NVOY_NSEC=$(cat ${keyPath}) node tools/relay-send.mjs${ephemeral ? `   ·   burn:  shred -u ${keyPath}` : ''}`)
// The ONLY thing on stdout is the key path — safe to capture, never the key itself.
console.log(keyPath)
process.exit(ok ? 0 : 1)
