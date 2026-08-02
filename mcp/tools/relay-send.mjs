// relay-send.mjs — message the Buzz crew PRIVATELY, through waggle's relay lane.
//
// This is the sanctioned Claude -> Buzz path (waggle#122, DESIGN_RELAY_INGRESS). You seal a
// request to waggle's OWN key; waggle opens its own mail, verifies your signature against your
// live grant, and posts it into the channel as the member it already is — with your name and
// npub, rendered by the bridge, NOT typed. No public note is published. Contrast:
//   - nvoy_chat_post  -> a PUBLIC kind:1 the read lane carries in (works, but permanent + public)
//   - the buzz CLI as `bridge` -> FORBIDDEN: that signs AS waggle (impersonation, see WAGGLE_BRIEF)
//
// Usage (body on stdin so multi-line + @mentions survive intact):
//   NVOY_NSEC=$(grep -oE 'nsec1[0-9a-z]+' ~/.nvoy/claude-identity.env | head -1) \
//     node tools/relay-send.mjs < message.txt
//   echo "@Neil — ping" | NVOY_NSEC=… node tools/relay-send.mjs
//
// Env:
//   NVOY_NSEC              (required) your identity — never printed, never in argv
//   WAGGLE_BRIDGE_PUBKEY   waggle's hex pubkey        (default: the live bridge key)
//   RELAY_CHANNEL          destination channel UUID   (default: #waggle-test)
//   RELAY_RELAYS           comma-sep relays           (default: damus, nos.lol, primal)
//   DRY_RUN=1              build + report, publish nothing
//
// After sending, VERIFY by reading your own inbox (inbox.mjs) — the crew's replies come back
// sealed to your key. Do NOT SSH-poll the channel; the inbox is the mechanism.

import { getPublicKey, getEventHash, finalizeEvent, generateSecretKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import * as nip44 from 'nostr-tools/nip44'
import WebSocket from 'ws'

const BRIDGE = (process.env.WAGGLE_BRIDGE_PUBKEY ||
  '84753207f2c6ae73af247da174e8e7c91a7d939a8eb0b4c2b98b54ea567786e6').toLowerCase()
const CHANNEL = process.env.RELAY_CHANNEL || 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const RELAYS = (process.env.RELAY_RELAYS || 'wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net')
  .split(',').map(s => s.trim()).filter(Boolean)
const DRY = !!process.env.DRY_RUN

const raw = process.env.NVOY_NSEC
if (!raw) { console.error('relay-send: set NVOY_NSEC (your identity)'); process.exit(1) }
const sk = raw.startsWith('nsec1') ? nip19.decode(raw).data : Uint8Array.from(Buffer.from(raw, 'hex'))
const pk = getPublicKey(sk)

const body = await new Promise((res) => {
  let s = ''
  process.stdin.on('data', d => s += d).on('end', () => res(s.replace(/\s+$/, '')))
})
if (!body) { console.error('relay-send: empty body on stdin — nothing to send'); process.exit(1) }

// rumor(kind:14, relay tag = destination) -> seal(kind:13, signed by ME) -> wrap(kind:1059,
// throwaway key, p-tagged to waggle). The seal carries my signature; that is what waggle verifies.
const now = Math.floor(Date.now() / 1000)
const rumor = { kind: 14, pubkey: pk, created_at: now, tags: [['relay', CHANNEL]], content: body }
rumor.id = getEventHash(rumor)
const seal = finalizeEvent({ kind: 13, created_at: now, tags: [],
  content: nip44.encrypt(JSON.stringify(rumor), nip44.getConversationKey(sk, BRIDGE)) }, sk)
const wsk = generateSecretKey()
const wrap = finalizeEvent({ kind: 1059, created_at: now, tags: [['p', BRIDGE]],
  content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(wsk, BRIDGE)) }, wsk)

console.error(`relay-send: sealed wrap ${wrap.id.slice(0, 12)}… (${JSON.stringify(wrap).length}B) ` +
  `-> waggle ${BRIDGE.slice(0, 8)}… for channel ${CHANNEL.slice(0, 8)}…  [${body.length}B body]`)
if (DRY) { console.error('relay-send: DRY_RUN — nothing published'); process.exit(0) }

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
    } catch { /* non-OK frame */ } })
    ws.on('error', () => { if (!done) { done = true; clearTimeout(t); r() } })
  })
}
console.error(`relay-send: accepted by ${ok}/${RELAYS.length} relay(s).` +
  (ok ? '  Verify with inbox.mjs — replies return sealed to your key.' : '  NOT sent — no relay accepted.'))
process.exit(ok ? 0 : 1)
