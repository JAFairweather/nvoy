#!/usr/bin/env node
// buzz-probe.mjs — the Phase 2.1 join test: can this key speak in a Buzz community natively?
//
// It answers three questions, each separately, because a yes to one says nothing about the next:
//   auth  — does the relay accept a NIP-42 login from this key? (needs a relay_members row)
//   read  — does a channel REQ return the channel's stored messages?  (#399 Gate 0, read half)
//   post  — does the relay accept a kind:9 signed by this key, and does a cold re-read on a
//           FRESH connection return it under this key? (#399 Gate 0, write half)
// No carrier, no waggle. The admin step before it is the OpenClaw one: add the pubkey as a
// community member and give it the room's bot role (`buzz channels add-member --role bot`).
// Or the key joins itself: BUZZ_INVITE=<invite link or code> makes it claim an admin-minted
// invite first (NIP-98 signed by this key; the claim endpoint is exempt from the member gate).
// If the community has join terms the probe stops and names them — agreeing is a human act,
// done by re-running with --accept-policy <version> (plus --age-confirmed if the terms ask).
//
// Usage:
//   BUZZ_RELAY=wss://<community host> BUZZ_CHANNEL=<uuid> NVOY_NSEC_FILE=/abs/test.nsec \
//     node mcp/tools/buzz-probe.mjs                       # auth + read; posts nothing
//   echo "native join test" | BUZZ_RELAY=… BUZZ_CHANNEL=… NVOY_NSEC_FILE=… \
//     node mcp/tools/buzz-probe.mjs --post --confirm      # + post and cold read-back
//   NVOY_BUNKER_URI_FILE=… NVOY_NIP46_CLIENT_FILE=… instead of NVOY_NSEC_FILE signs via the Bunker.
//
//   echo "…" | BUZZ_INVITE='https://<host>/invite/v2.…' BUZZ_RELAY=… BUZZ_CHANNEL=… NVOY_NSEC_FILE=… \
//     node mcp/tools/buzz-probe.mjs --post --confirm      # claim, then everything above
//
// Env: EXPECT_PUBKEY (npub or hex) pins the identity before anything is sent. --limit N bounds the
// read (default 20). --post without --confirm builds and signs nothing, and says so.
// Output: one JSON verdict on stdout. The key is read from a file and never printed; message
// content is not printed either, only ids, authors (8-hex) and counts.

import { readFileSync, statSync } from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import { makeBunkerSigner } from './nip46-signer.mjs'
import { CHANNEL_KINDS, normalizeBuzzRelay, openBuzzSession, validChannel } from './buzz_native.mjs'

const die = (m) => { console.error(`buzz-probe: ${m}`); process.exit(1) }
const flag = (n, d) => { const i = process.argv.indexOf(n); return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : d }
const has = n => process.argv.includes(n)

let RELAY
try { RELAY = normalizeBuzzRelay(process.env.BUZZ_RELAY) } catch (e) { die(e.message) }
const CHANNEL = String(process.env.BUZZ_CHANNEL || '').toLowerCase()
if (!validChannel(CHANNEL)) die('set BUZZ_CHANNEL to the channel UUID')
const LIMIT = Number(flag('--limit', 20))
if (!Number.isInteger(LIMIT) || LIMIT < 1 || LIMIT > 500) die('--limit must be an integer from 1 to 500')
const POST = has('--post'), CONFIRM = has('--confirm')
const HTTP = RELAY.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:')
// The invite code is a capability: accepted as a link or a bare code, never printed.
const INVITE = (() => {
  const raw = String(process.env.BUZZ_INVITE || '').trim()
  if (!raw) return ''
  const code = decodeURIComponent(raw.includes('/invite/') ? raw.split('/invite/')[1].split(/[?#]/)[0] : raw)
  if (!/^[A-Za-z0-9._~-]{8,512}$/.test(code)) die('BUZZ_INVITE is not an invite link or code')
  return code
})()
const ACCEPT_POLICY = flag('--accept-policy', null), AGE_CONFIRMED = has('--age-confirmed')

const credential = (path, label, { privateFile = false } = {}) => {
  if (!path) return ''
  let value
  try {
    if (privateFile && (statSync(path).mode & 0o077)) die(`${label} at ${path} must be mode 0600`)
    value = readFileSync(path, 'utf8').trim()
  } catch (e) { if (e?.code) die(`cannot read ${label} at ${path}`); throw e }
  if (!value) die(`${label} at ${path} is empty`)
  return value
}
// A raw key in the environment is refused outright: a join-test identity is a file, so the value
// never passes through argv, env or a transcript.
if (process.env.NVOY_NSEC) die('NVOY_NSEC is refused — put the test key in a 0600 file and set NVOY_NSEC_FILE')
const bunkerUri = credential(process.env.NVOY_BUNKER_URI_FILE, 'Bunker URI credential')
const bunkerClient = credential(process.env.NVOY_NIP46_CLIENT_NSEC_FILE || process.env.NVOY_NIP46_CLIENT_FILE, 'Bunker client credential')
const keyText = credential(process.env.NVOY_NSEC_FILE, 'identity key', { privateFile: true })
if (!!bunkerUri !== !!bunkerClient) die('the Bunker URI and client credential files must be supplied together')
if (!!keyText === !!bunkerUri) die('choose exactly one signer: NVOY_NSEC_FILE, or the Bunker credential-file pair')

let signer
if (bunkerUri) {
  // Held open for the whole probe: the relay allows 5s from challenge to AUTH, and a Bunker that
  // reconnects per call can spend most of that before it signs.
  signer = makeBunkerSigner(bunkerUri, bunkerClient, { idleMs: 30000 })
} else {
  let sk
  try { sk = keyText.startsWith('nsec1') ? nip19.decode(keyText).data : Uint8Array.from(Buffer.from(keyText, 'hex')) } catch { sk = null }
  if (!(sk instanceof Uint8Array) || sk.length !== 32) die('identity key file does not hold a valid nsec')
  signer = { getPublicKey: async () => getPublicKey(sk), signEvent: async t => finalizeEvent(t, sk) }
}

let me
try { me = await signer.getPublicKey() } catch (e) { die(`signer unavailable: ${e.message}`) }
const expectedRaw = String(process.env.EXPECT_PUBKEY || '').trim()
if (expectedRaw) {
  let expected = ''
  try { expected = expectedRaw.startsWith('npub1') ? nip19.decode(expectedRaw).data : expectedRaw.toLowerCase() } catch { /* judged below */ }
  if (!/^[0-9a-f]{64}$/.test(expected)) die('EXPECT_PUBKEY must be an npub or 64-hex pubkey')
  if (me !== expected) die(`signer identity mismatch (resolved ${nip19.npubEncode(me)}, expected ${nip19.npubEncode(expected)})`)
}

let body = ''
if (POST) {
  body = await new Promise(res => { let s = ''; process.stdin.setEncoding('utf8'); process.stdin.on('data', d => { s += d }); process.stdin.on('end', () => res(s.trim())) })
  if (!body) die('--post needs the message body on stdin')
  if (/(^|\s)@\S/.test(body)) console.error('buzz-probe: note — @names in the body are plain text; Buzz routes mentions by p tag only, and this probe adds none')
}

const verdict = { relay: RELAY, channel: CHANNEL, npub: nip19.npubEncode(me), ...(INVITE ? { claim: null } : {}), auth: null, read: null, post: null }

// POST to the community's HTTP API; NIP-98 signs it as this key when `signed`, binding the exact
// URL, method and body hash so the request cannot be replayed elsewhere or with another body.
const postJson = async (path, payload, signed) => {
  const body = JSON.stringify(payload), headers = { 'content-type': 'application/json' }
  if (signed) {
    const auth = await signer.signEvent({ kind: 27235, created_at: Math.floor(Date.now() / 1000), content: '', tags: [
      ['u', `${HTTP}${path}`], ['method', 'POST'], ['payload', createHash('sha256').update(body).digest('hex')], ['nonce', randomUUID()]] })
    headers.authorization = `Nostr ${Buffer.from(JSON.stringify(auth)).toString('base64')}`
  }
  const res = await fetch(`${HTTP}${path}`, { method: 'POST', headers, body })
  let json = {}
  try { json = await res.json() } catch { /* judged by status */ }
  return { status: res.status, json }
}
async function claimInvite() {
  let policy
  try { policy = (await (await fetch(`${HTTP}/api/join-policy`)).json())?.policy } catch (e) { return { ok: false, reason: `join-policy unreachable: ${e.message}` } }
  let policy_receipt
  if (policy) {
    const version = String(policy.version)
    if (ACCEPT_POLICY !== version || (policy.age_attestation_required && !AGE_CONFIRMED))
      return { ok: false, reason: `this community has join terms (version ${version}). Read ${HTTP}/api/join-policy/terms and ${HTTP}/api/join-policy/privacy, then re-run with --accept-policy ${version}${policy.age_attestation_required ? ' --age-confirmed' : ''}` }
    const accepted = await postJson('/api/invites/accept-policy', { code: INVITE, policy_version: version, age_confirmed: AGE_CONFIRMED }, false)
    if (accepted.status !== 200 || typeof accepted.json.receipt !== 'string') return { ok: false, http: accepted.status, reason: accepted.json.error || 'policy acceptance refused' }
    policy_receipt = accepted.json.receipt
  }
  const claimed = await postJson('/api/invites/claim', { code: INVITE, ...(policy_receipt ? { policy_receipt } : {}) }, true)
  return claimed.status === 200 ? { ok: true, status: claimed.json.status, role: claimed.json.role }
    : { ok: false, http: claimed.status, reason: claimed.json.error || '(no reason)' }
}
if (INVITE) {
  try { verdict.claim = await claimInvite() } catch (e) { verdict.claim = { ok: false, reason: e.message } }
  // Terms not yet agreed is a stop, not a failed login: say so and try nothing further.
  if (!verdict.claim.ok && /join terms/.test(verdict.claim.reason || '')) { console.log(JSON.stringify(verdict, null, 2)); signer.close?.(); process.exit(10) }
}
const short = pk => `${String(pk).slice(0, 8)}…`
const filter = extra => ({ kinds: [...CHANNEL_KINDS], '#h': [CHANNEL], ...extra })
const finish = () => { console.log(JSON.stringify(verdict, null, 2)); signer.close?.(); process.exit(verdict.auth?.ok && verdict.read?.ok && (!POST || !CONFIRM || verdict.post?.readback) ? 0 : 10) }

let session
try { session = await openBuzzSession({ relay: RELAY, signer }); verdict.auth = { ok: true } }
catch (e) { verdict.auth = { ok: false, reason: e.message }; finish() }

try {
  const events = await session.fetch(filter({ limit: LIMIT }))
  verdict.read = { ok: true, count: events.length, authors: [...new Set(events.map(e => short(e.pubkey)))], newest: Math.max(0, ...events.map(e => e.created_at || 0)) }
  // Zero is an answer, not a pass: an empty channel and a relay that hides it look the same.
  if (!events.length) verdict.read.note = 'no events returned — indistinguishable from a read refusal unless the channel is known to hold messages'
} catch (e) { verdict.read = { ok: false, reason: e.message } }

if (POST && !CONFIRM) verdict.post = { ok: null, note: 'dry run — add --confirm to publish; nothing was signed or sent' }
else if (POST) {
  try {
    const { event, accepted, message } = await session.publish({ kind: 9, created_at: Math.floor(Date.now() / 1000), content: body, tags: [['h', CHANNEL]] })
    verdict.post = { ok: accepted, id: event.id, relay_message: message || undefined, readback: false }
    if (accepted) {
      // Proof is a cold read-back: a new connection, a new login, and the relay's stored copy.
      session.close()
      const cold = await openBuzzSession({ relay: RELAY, signer })
      const back = await cold.fetch(filter({ ids: [event.id] }))
      cold.close()
      verdict.post.readback = back.some(e => e.id === event.id && e.pubkey === me)
    }
  } catch (e) { verdict.post = { ok: false, reason: e.message } }
}
session.close()
finish()
