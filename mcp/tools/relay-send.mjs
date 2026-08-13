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
//   NVOY_BUNKER_URI_FILE=/run/secrets/uri NVOY_NIP46_CLIENT_FILE=/run/secrets/client \
//     node tools/relay-send.mjs < message.txt
//
// Env:
//   NVOY_NSEC              local identity (one of this or the Bunker pair is required)
//   NVOY_BUNKER_URI_FILE   Bunker connection capability file
//   NVOY_NIP46_CLIENT_FILE Bunker transport nsec file (not the identity nsec)
//   WAGGLE_BRIDGE_PUBKEY   waggle's hex pubkey        (default: the live bridge key)
//   RELAY_CHANNEL          destination channel UUID   (default: #waggle-test)
//   RELAY_RELAYS           comma-sep relays           (default: nos.lol, primal)
//   EXPECT_PUBKEY          required signer identity (npub or 64-hex); mismatch fails before send
//   DRY_RUN=1              build + report, publish nothing
//
// After sending, VERIFY by reading your own inbox (inbox.mjs) — the crew's replies come back
// sealed to your key. Do NOT SSH-poll the channel; the inbox is the mechanism.

import { readFileSync } from 'node:fs'
import { getPublicKey, getEventHash, finalizeEvent, generateSecretKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import * as nip44 from 'nostr-tools/nip44'
import WebSocket from 'ws'
import { makeBunkerSigner } from './nip46-signer.mjs'

const BRIDGE = (process.env.WAGGLE_BRIDGE_PUBKEY ||
  '84753207f2c6ae73af247da174e8e7c91a7d939a8eb0b4c2b98b54ea567786e6').toLowerCase()
const CHANNEL = process.env.RELAY_CHANNEL || 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const RELAYS = (process.env.RELAY_RELAYS || 'wss://nos.lol,wss://relay.primal.net')
  .split(',').map(s => s.trim()).filter(Boolean)
const DRY = !!process.env.DRY_RUN

const readCredential = (path, label) => {
  if (!path) return ''
  try { return readFileSync(path, 'utf8').trim() } catch { console.error(`relay-send: cannot read ${label}`); process.exit(1) }
}
const bunkerUri = readCredential(process.env.NVOY_BUNKER_URI_FILE, 'Bunker URI credential')
const bunkerClient = readCredential(process.env.NVOY_NIP46_CLIENT_FILE, 'Bunker client credential')
if (!!bunkerUri !== !!bunkerClient) { console.error('relay-send: Bunker URI and client credential must be supplied together'); process.exit(1) }
const raw = process.env.NVOY_NSEC || ''
if (raw && bunkerUri) { console.error('relay-send: choose local NVOY_NSEC or the Bunker signer, never both'); process.exit(1) }
if (!raw && !bunkerUri) { console.error('relay-send: set NVOY_NSEC or the Bunker credential-file pair'); process.exit(1) }
const sk = raw ? (raw.startsWith('nsec1') ? nip19.decode(raw).data : Uint8Array.from(Buffer.from(raw, 'hex'))) : null
const signer = bunkerUri ? makeBunkerSigner(bunkerUri, bunkerClient) : null
const pk = signer ? await signer.getPublicKey() : getPublicKey(sk)
const expectedRaw = String(process.env.EXPECT_PUBKEY || '').trim()
if (expectedRaw) {
  let expected
  try { expected = expectedRaw.startsWith('npub1') ? nip19.decode(expectedRaw).data : expectedRaw.toLowerCase() } catch { expected = '' }
  if (!/^[0-9a-f]{64}$/.test(String(expected || ''))) { console.error('relay-send: EXPECT_PUBKEY must be an npub or 64-hex pubkey'); process.exit(1) }
  if (pk !== expected) { console.error(`relay-send: signer identity mismatch (resolved ${nip19.npubEncode(pk)}, expected ${nip19.npubEncode(expected)})`); process.exit(1) }
}

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
const sealTemplate = { kind: 13, created_at: now, tags: [],
  content: signer ? await signer.nip44Encrypt(BRIDGE, JSON.stringify(rumor)) : nip44.encrypt(JSON.stringify(rumor), nip44.getConversationKey(sk, BRIDGE)) }
const seal = signer ? await signer.signEvent(sealTemplate) : finalizeEvent(sealTemplate, sk)
const wsk = generateSecretKey()
const wrap = finalizeEvent({ kind: 1059, created_at: now, tags: [['p', BRIDGE]],
  content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(wsk, BRIDGE)) }, wsk)

// #382: name the resolved identity on SUCCESS, not only on mismatch. EXPECT_PUBKEY is enforced
// correctly above and then says nothing, which is indistinguishable from the flag not existing —
// the only way to learn which key signed is to get it wrong. #338 was precisely a session acting
// as the wrong key, so a send that succeeds under an unnamed identity is the one thing that
// should not be possible. Say whether the identity was CHECKED, too: "signing as X" with no
// EXPECT_PUBKEY set is a statement about this process's own belief, not a verified fact.
console.error(`relay-send: signing as ${nip19.npubEncode(pk)}` +
  (expectedRaw ? ' — matches EXPECT_PUBKEY' : ' — EXPECT_PUBKEY not set, identity NOT verified'))
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
  (ok ? '  Relay OK is an ACKNOWLEDGEMENT, not delivery — read the id above back from a fresh connection.'
      : '  NOT sent — no relay accepted.'))
// #182: everything above is a human-readable summary on stderr, and the wrap id in it is cut to 12
// of 64 characters so the line stays readable. That left the operator unable to do the one check
// this repo insists on — a publish is proven by fetching it back BY ID — because 12 characters is
// not an id. The full id goes to stdout, alone, so `ID=$(… | relay-send.mjs)` works while the
// summary still reads well in a terminal. Printed only after a relay accepted: an id for an event
// that was never published is worse than no id.
if (ok) console.log(wrap.id)
process.exit(ok ? 0 : 1)
