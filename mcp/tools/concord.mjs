#!/usr/bin/env node
// concord.mjs — Claude's Concord consumer for the Buzz Crew community.
//
// Concord (concord-protocol) is the group-chat layer under Armada/Vector: a community is a
// set of private streams whose keys DERIVE from a community_root carried in a kind:3313 Direct
// Invite. Membership is key possession — "if you can decrypt the room, you're in it." This tool
// lets Claude, holding that invite, list the community's channels, read them, and (deliberately)
// post to them. It NEVER prints community_root or owner_salt; only public plane addresses.
//
//   NVOY_NSEC=<nsec|hex> node tools/concord.mjs channels
//   NVOY_NSEC=... node tools/concord.mjs read <channel> [--limit N]
//   NVOY_NSEC=... node tools/concord.mjs post <channel> "<text>" [--confirm]
//
// `post` is DRY-RUN by default: it builds, wraps, and round-trip-verifies the event but does
// NOT publish unless --confirm is given. Posting speaks in the community in Claude's name —
// it is a deliberate act, gated behind that flag.
//
// Security recipe (all verified against the live Buzz Crew community, see
// RESEARCH/CONCORD_PROTOCOL_SPEC_NOTES.md):
//   - Invite provenance: the seal (kind 13) signature verifies, its signer is the expected
//     sender (James), the rumor author matches the signer, and community_id self-certifies.
//     If zero or MORE THAN ONE invite passes, we refuse — never silently pick a credential.
//   - Reads on auth-gated relays authenticate AS THE PLANE: a Concord plane key is a full
//     keypair, so we sign the NIP-42 challenge with the derived plane secret.
//   - Chat rumors are checked for the mandatory ["channel"]/["epoch"] binding (CORD-03 §3);
//     a mismatch is dropped (stops a member re-wrapping a message into another channel).

import WebSocket from 'ws'
import { nip44, verifyEvent, finalizeEvent, getEventHash } from 'nostr-tools'
import { decode, npubEncode } from 'nostr-tools/nip19'
import { getPublicKey } from 'nostr-tools/pure'
import { schnorr } from '@noble/curves/secp256k1.js'
import * as lib from './concord_lib.mjs'
const { hex, toHex } = lib

const die = (m) => { console.error(`concord: ${m}`); process.exit(1) }
const arg = (n, d) => { const i = process.argv.indexOf(n); return i === -1 ? d : process.argv[i + 1] }

// --- identity ---
const raw = process.env.NVOY_NSEC || die('set NVOY_NSEC (Claude identity that holds the invite)')
const sk = raw.startsWith('nsec1') ? decode(raw).data : hex(raw)
const ME = getPublicKey(sk)
const JAMES = '4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'

// Known crew keys for friendlier rendering; unknown authors fall back to a short npub.
const NAMES = {
  [ME]: 'Claude',
  [JAMES]: 'James',
  '0a8e0720c3ec52c6bfd9e2545d620cf58e2e8d371244255efce3ddd57ba0a32c': 'My Dude',
  '5d3848a699e82f81e218ce8b0e9b0f8c8f0e6c8e0a0c0e0a0c0e0a0c0e0a0c0e0': 'Neil?', // prefix-known only
}
const who = (pk) => NAMES[pk] || (() => { try { const n = npubEncode(pk); return `${n.slice(0, 10)}…${n.slice(-5)}` } catch { return pk.slice(0, 12) + '…' } })()

// Armada relay set. ditto/dreamith gate author queries behind NIP-42 (auth AS the plane / self).
const RELAYS = [
  { url: 'wss://jskitty.com/nostr', auth: false },
  { url: 'wss://asia.vectorapp.io/nostr', auth: false },
  { url: auth: false },
  { url: 'wss://relay.ditto.pub', auth: true },
  { url: 'wss://relay.dreamith.to', auth: true },
]

// One relay round-trip. If `signKey` is given, answer a NIP-42 AUTH challenge by signing 22242
// with that key (self for my inbox, the plane secret for a plane read), then re-issue the REQ.
function query(url, filter, signKey = null, ms = 15000) {
  return new Promise(res => {
    const out = []; let done = false, authed = false, ws
    try { ws = new WebSocket(url) } catch { return res(out) }
    const fin = () => { if (done) return; done = true; try { ws.close() } catch {} ; res(out) }
    const t = setTimeout(fin, ms)
    const req = (sub) => ws.send(JSON.stringify(['REQ', sub, filter]))
    ws.on('open', () => req(signKey ? 'pre' : 'q'))
    ws.on('message', d => {
      let m; try { m = JSON.parse(d.toString()) } catch { return }
      if (m[0] === 'AUTH' && signKey && !authed) {
        authed = true
        ws.send(JSON.stringify(['AUTH', finalizeEvent({ kind: 22242, created_at: Math.floor(Date.now() / 1000),
          tags: [['relay', url], ['challenge', m[1]]], content: '' }, signKey)]))
        return
      }
      if (m[0] === 'OK' && authed) { req('q'); return }
      if (m[0] === 'EVENT' && m[1] === 'q') { out.push(m[2]); return }
      if ((m[0] === 'EOSE' || m[0] === 'CLOSED') && m[1] === 'q') { clearTimeout(t); fin() }
    })
    ws.on('error', () => { clearTimeout(t); fin() })
  })
}

function publish(url, ev, ms = 15000) {
  return new Promise(res => {
    let done = false, ws
    try { ws = new WebSocket(url) } catch { return res(`${new URL(url).host} ctor-fail`) }
    const fin = (s) => { if (done) return; done = true; try { ws.close() } catch {} ; res(`${new URL(url).host.padEnd(22)} ${s}`) }
    const t = setTimeout(() => fin('TIMEOUT'), ms)
    ws.on('open', () => ws.send(JSON.stringify(['EVENT', ev])))
    ws.on('message', d => { let m; try { m = JSON.parse(d.toString()) } catch { return }
      if (m[0] === 'OK') { clearTimeout(t); fin(m[2] ? 'OK accepted' : 'REJECTED ' + (m[3] || '')) }
      if (m[0] === 'NOTICE') { clearTimeout(t); fin('NOTICE ' + m[1]) } })
    ws.on('error', e => { clearTimeout(t); fin('ERR ' + e.message) })
  })
}

// Gather all gift-wraps to me, find the kind:3313 invites, and adjudicate provenance. Returns
// the single verified CommunityInvite payload, or dies (0 pass, or >1 pass = refuse to choose).
async function loadInvite() {
  const wraps = new Map()
  for (const r of RELAYS) {
    const evs = await query(r.url, { kinds: [1059], '#p': [ME], limit: 200 }, r.auth ? sk : null)
    for (const e of evs) wraps.set(e.id, e)
  }
  const invites = []
  for (const w of wraps.values()) {
    try {
      const seal = JSON.parse(nip44.v2.decrypt(w.content, nip44.v2.utils.getConversationKey(sk, w.pubkey)))
      if (seal.kind !== 13) continue
      const rumor = JSON.parse(nip44.v2.decrypt(seal.content, nip44.v2.utils.getConversationKey(sk, seal.pubkey)))
      if (rumor.kind !== 3313) continue
      invites.push({ seal, rumor, payload: JSON.parse(rumor.content) })
    } catch { /* not for me */ }
  }
  const good = []
  for (const inv of invites) {
    const p = inv.payload
    let selfCert = false
    try { selfCert = lib.communityId(hex(p.owner), hex(p.owner_salt)) === p.community_id } catch { /* bad fields */ }
    const ok = verifyEvent(inv.seal) && inv.seal.pubkey === JAMES && inv.rumor.pubkey === inv.seal.pubkey && selfCert
    if (ok) good.push(p)
  }
  if (good.length === 0) die(`no valid invite (${invites.length} kind:3313 seen, none passed provenance)`)
  if (good.length > 1) die(`${good.length} invites passed provenance — refusing to choose a community`)
  return good[0]
}

const open = (ev, plane) => {
  const seal = JSON.parse(nip44.v2.decrypt(ev.content, plane.conv))
  const rumor = seal.kind === 20013 ? JSON.parse(nip44.v2.decrypt(seal.content, plane.conv)) : JSON.parse(seal.content)
  return { seal, rumor }
}

// Enumerate every channel from the Control Plane: collect 3308 ChannelMetadata editions, keep
// the latest (highest vsk) per channel_id (its eid), skip the community-def and deleted ones.
async function channelRegistry(inv) {
  const root = hex(inv.community_root), cid = hex(inv.community_id), ep = Number(inv.root_epoch || 0)
  const cidHex = toHex(cid)
  const control = lib.controlPlane(root, cid, ep)
  const evs = new Map()
  for (const r of RELAYS) for (const e of await query(r.url, { authors: [control.pub], kinds: [1059], limit: 300 }, r.auth ? control.sk : null)) evs.set(e.id, e)
  const byChan = new Map()
  for (const ev of evs.values()) {
    try {
      const { rumor } = open(ev, control)
      if (rumor.kind !== 3308) continue
      const t = Object.fromEntries((rumor.tags || []).map(x => [x[0], x[1]]))
      const eid = t.eid; if (!eid || eid === cidHex) continue // community def, not a channel
      const body = JSON.parse(rumor.content); const vsk = Number(t.vsk ?? -1)
      const prev = byChan.get(eid)
      if (!prev || vsk > prev.vsk) byChan.set(eid, { vsk, body })
    } catch { /* not ours */ }
  }
  const chans = []
  for (const [eid, { body }] of byChan) {
    if (body.deleted) continue
    const plane = lib.publicChannel(root, hex(eid), ep) // TODO: private channels use a delivered channel_key
    chans.push({ name: body.name, channel_id: eid, plane, private: !!body.private, epoch: ep })
  }
  return { chans, controlCount: evs.size }
}

const findChan = (reg, name) => {
  const n = String(name).replace(/^#/, '').toLowerCase()
  const hit = reg.chans.find(c => (c.name || '').toLowerCase() === n) || reg.chans.find(c => c.channel_id.startsWith(n))
  if (!hit) die(`no channel "${name}" — known: ${reg.chans.map(c => '#' + c.name).join(', ') || '(none)'}`)
  return hit
}

async function readChannel(inv, name, limit) {
  const reg = await channelRegistry(inv)
  const c = findChan(reg, name)
  const evs = new Map()
  for (const r of RELAYS) for (const e of await query(r.url, { authors: [c.plane.pub], kinds: [1059], limit: 300 }, r.auth ? c.plane.sk : null)) evs.set(e.id, e)
  const msgs = []
  for (const ev of evs.values()) {
    try {
      const { seal, rumor } = open(ev, c.plane)
      const t = Object.fromEntries((rumor.tags || []).map(x => [x[0], x[1]]))
      // CORD-03 §3: the channel/epoch binding is mandatory — drop a mismatch.
      if (t.channel !== c.channel_id || String(t.epoch) !== String(c.epoch)) continue
      if (rumor.pubkey !== seal.pubkey) continue // author spoof guard
      const ms = Math.min(999, Math.max(0, Number(t.ms || 0)))
      msgs.push({ at: rumor.created_at * 1000 + ms, from: rumor.pubkey, kind: rumor.kind, content: String(rumor.content || '') })
    } catch { /* can't open — not a member write we can read, or malformed */ }
  }
  msgs.sort((a, b) => a.at - b.at)
  console.log(`#${c.name}  ·  ${c.private ? 'private' : 'public'}  ·  plane ${c.plane.pub.slice(0, 12)}…  ·  epoch ${c.epoch}`)
  console.log(`${msgs.length} message(s)${limit && msgs.length > limit ? ` (showing last ${limit})` : ''}:\n`)
  for (const m of msgs.slice(-(limit || msgs.length))) {
    console.log(`  [${new Date(m.at).toISOString()}] ${who(m.from)}${m.kind !== 9 ? ` (kind ${m.kind})` : ''}`)
    console.log(`    ${m.content.replace(/\n/g, '\n    ')}\n`)
  }
}

async function postChannel(inv, name, text, confirm) {
  if (!text) die('post needs text')
  const reg = await channelRegistry(inv)
  const c = findChan(reg, name)
  if (c.private) die(`#${c.name} is private — this consumer derives public channels only (private needs a delivered channel_key)`)
  const now = Math.floor(Date.now() / 1000), ms = Date.now() % 1000
  const rumor = { kind: 9, pubkey: ME, content: text, created_at: now,
    tags: [['channel', c.channel_id], ['epoch', String(c.epoch)], ['ms', String(ms)]] }
  rumor.id = getEventHash(rumor)
  const seal = finalizeEvent({ kind: 20013, created_at: now, tags: [], content: nip44.v2.encrypt(JSON.stringify(rumor), c.plane.conv) }, sk)
  const pTag = toHex(schnorr.getPublicKey(crypto.getRandomValues(new Uint8Array(32)))) // CORD-01: ephemeral, fresh
  const outer = finalizeEvent({ kind: 1059, created_at: now, tags: [['p', pTag]], content: nip44.v2.encrypt(JSON.stringify(seal), c.plane.conv) }, c.plane.sk)
  // Round-trip check before it can ever go on the wire.
  const rt = open(outer, c.plane)
  const bindOk = rt.rumor.tags.some(t => t[0] === 'channel' && t[1] === c.channel_id) && rt.rumor.pubkey === ME
  console.log(`#${c.name}  plane ${c.plane.pub.slice(0, 12)}…  rumor ${rumor.id.slice(0, 12)}…`)
  console.log(`  seal ok=${verifyEvent(seal)}  outer ok=${verifyEvent(outer)}  author==plane=${outer.pubkey === c.plane.pub}  binding ok=${bindOk}`)
  console.log(`  as: ${who(ME)}  text: ${JSON.stringify(text)}`)
  if (!bindOk) die('round-trip binding failed — refusing to publish')
  if (!confirm) { console.log('\n  DRY RUN — not published. Re-run with --confirm to post.'); return }
  console.log('\n  publishing…')
  for (const r of RELAYS) console.log('  ' + await publish(r.url, outer))
}

// --- CLI ---
const verb = process.argv[2]
const inv = await loadInvite()
if (verb === 'channels') {
  const reg = await channelRegistry(inv)
  console.log(`community "${inv.name}"  ·  ${inv.community_id.slice(0, 12)}…  ·  epoch ${inv.root_epoch || 0}  ·  ${reg.controlCount} control events`)
  console.log(`${reg.chans.length} channel(s):\n`)
  for (const c of reg.chans) console.log(`  #${(c.name || '?').padEnd(20)} ${c.private ? 'private' : 'public '}  id ${c.channel_id.slice(0, 12)}…  plane ${c.plane.pub.slice(0, 12)}…`)
} else if (verb === 'read') {
  await readChannel(inv, process.argv[3] || die('read <channel>'), Number(arg('--limit', 0)) || 0)
} else if (verb === 'post') {
  await postChannel(inv, process.argv[3] || die('post <channel> <text>'), process.argv[4], process.argv.includes('--confirm'))
} else {
  die('verbs: channels | read <channel> [--limit N] | post <channel> "<text>" [--confirm]')
}
process.exit(0)
