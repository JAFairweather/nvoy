// CORD-05 link invite primitives for an isolated Nvoy identity.
//
// This module deliberately has no filesystem or relay side effects.  The URL fragment is a
// bearer credential: callers keep it in memory, query only its bootstrap relays, and never put
// it in a log, event, state file, or command argument.

import { getEventHash, finalizeEvent, generateSecretKey, getPublicKey, nip44, verifyEvent } from 'nostr-tools'
import * as nip19 from 'nostr-tools/nip19'
import * as derive from './concord_lib.mjs'

const HEX64 = /^[0-9a-f]{64}$/i
const KIND_BUNDLE = 33301, KIND_JOIN = 3306, KIND_SEAL = 20013, KIND_WRAP = 1059
const VSK_LIVE = '6', VSK_REVOKED = '9'
const MAX_CHANNELS = 64, MAX_RELAYS = 12
const DICT = { 1: 'wss://jskitty.com/nostr', 2: 'wss://asia.vectorapp.io/nostr', 3: 'wss://relay.ditto.pub', 4: 'wss://relay.dreamith.to' }
const STOCK = Object.values(DICT)

const fail = m => { throw new Error(`CORD-05: ${m}`) }
const tag = (event, name) => (event.tags || []).find(t => t[0] === name)?.[1]
const b64url = s => {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) fail('fragment is not base64url')
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)
  return new Uint8Array(Buffer.from(padded, 'base64'))
}

export function decodeFragment(fragment) {
  const bytes = b64url(String(fragment || '').trim())
  let offset = 0
  const need = n => { if (offset + n > bytes.length) fail('fragment is truncated') }
  need(2)
  const version = bytes[offset++]
  if (version !== 4) fail(version < 4 ? `legacy fragment version ${version}` : `unsupported fragment version ${version}`)
  const flags = bytes[offset++], relays = []
  if (flags & 1) relays.push(...STOCK)
  else {
    need(1); const count = bytes[offset++]
    if (count > 3) fail('fragment has too many bootstrap relays')
    const decoder = new TextDecoder()
    for (let i = 0; i < count; i++) {
      need(1); const lead = bytes[offset++]
      if (lead >= 1 && lead <= 254) { if (DICT[lead]) relays.push(DICT[lead]); continue }
      need(1); const len = bytes[offset++]; need(len)
      const literal = decoder.decode(bytes.slice(offset, offset + len)); offset += len
      relays.push(lead === 255 ? literal : `wss://${literal}`)
    }
  }
  need(16); const token = bytes.slice(offset, offset + 16); offset += 16
  if (offset !== bytes.length) fail('fragment has trailing bytes')
  return { token, relays: [...new Set(relays.filter(r => /^wss:\/\/[^\s/]+/i.test(r)))] }
}

/** Parse a CORD-05 URL, retaining the bearer fragment only in the returned in-memory object. */
export function parseInviteLink(input) {
  const text = String(input || '').trim()
  let naddr = '', fragment = ''
  if (/^naddr1[a-z0-9]+#.+$/i.test(text)) [naddr, fragment] = text.split('#', 2)
  else {
    let url; try { url = new URL(text) } catch { fail('not an invite URL') }
    if (!url.pathname.startsWith('/invite/')) fail('not a CORD-05 invite path')
    naddr = decodeURIComponent(url.pathname.slice('/invite/'.length)).replace(/\/$/, '')
    fragment = url.hash.slice(1)
  }
  if (!fragment) fail('invite is missing its fragment')
  let decoded
  try { decoded = nip19.decode(naddr) } catch { fail('invite coordinate is not a valid naddr') }
  if (decoded.type !== 'naddr' || decoded.data.kind !== KIND_BUNDLE || decoded.data.identifier !== '' || !HEX64.test(decoded.data.pubkey)) fail('invite is not the 33301 empty-d bundle coordinate')
  const { token, relays } = decodeFragment(fragment)
  return { linkSigner: decoded.data.pubkey.toLowerCase(), token, bootstrapRelays: relays, coordinate: naddr }
}

function validBundle(bundle) {
  if (!bundle || typeof bundle !== 'object') fail('bundle is not an object')
  for (const field of ['community_id', 'owner', 'owner_salt', 'community_root', 'name']) if (typeof bundle[field] !== 'string') fail(`bundle is missing ${field}`)
  for (const field of ['community_id', 'owner', 'owner_salt', 'community_root']) if (!HEX64.test(bundle[field])) fail(`bundle ${field} is not 32-byte hex`)
  if (!Number.isSafeInteger(bundle.root_epoch) || bundle.root_epoch < 0) fail('bundle root_epoch is invalid')
  if (!Array.isArray(bundle.channels) || bundle.channels.length > MAX_CHANNELS) fail('bundle channel bounds failed')
  if (!Array.isArray(bundle.relays) || bundle.relays.length > MAX_RELAYS || bundle.relays.some(r => typeof r !== 'string' || !/^wss:\/\/[^\s/]+/i.test(r))) fail('bundle relay bounds failed')
  if (derive.communityId(derive.hex(bundle.owner), derive.hex(bundle.owner_salt)) !== bundle.community_id.toLowerCase()) fail('bundle community_id does not self-certify')
  if (bundle.expires_at != null && (!Number.isFinite(bundle.expires_at) || Date.now() > bundle.expires_at)) fail('invite has expired')
  return bundle
}

/** Verify the coordinate/signature/liveness, then decrypt and bounds-check a bundle. */
export function openBundle(event, invite, nowMs = Date.now()) {
  if (!event || event.kind !== KIND_BUNDLE || event.pubkey !== invite.linkSigner || !verifyEvent(event)) fail('bundle event does not verify at its invite coordinate')
  if (tag(event, 'd') !== '') fail('bundle event does not use the empty d coordinate')
  const marker = tag(event, 'vsk')
  if (marker === VSK_REVOKED) fail('invite has been revoked')
  if (marker !== VSK_LIVE) fail('bundle does not carry the live marker')
  let bundle
  try { bundle = JSON.parse(nip44.v2.decrypt(event.content, derive.hex(derive.inviteBundleKey(invite.token)))) } catch { fail('bundle cannot be decrypted by this invite') }
  validBundle(bundle)
  if (bundle.expires_at != null && nowMs > bundle.expires_at) fail('invite has expired')
  return bundle
}

export function latestCoordinateEvent(events, invite) {
  const candidates = (events || []).filter(e => e?.kind === KIND_BUNDLE && e.pubkey === invite.linkSigner && tag(e, 'd') === '' && verifyEvent(e))
  if (!candidates.length) fail('no signed bundle event found at the invite coordinate')
  return candidates.sort((a, b) => Number(b.created_at) - Number(a.created_at) || String(b.id).localeCompare(String(a.id)))[0]
}

/** Construct a Bunker-signable join and locally verify both stream layers. */
export async function buildJoin(bundle, signer) {
  const pubkey = await signer.getPublicKey()
  if (!HEX64.test(pubkey)) fail('signer did not return a public key')
  const group = derive.guestbookPlane(derive.hex(bundle.community_root), derive.hex(bundle.community_id), bundle.root_epoch)
  const now = Date.now(), created_at = Math.floor(now / 1000)
  const attribution = bundle.creator_npub && HEX64.test(bundle.creator_npub) ? bundle.creator_npub.toLowerCase() : undefined
  const rumor = { kind: KIND_JOIN, pubkey: pubkey.toLowerCase(), content: 'join', created_at,
    tags: [...(attribution ? [['invite', attribution, String(bundle.label || '')]] : []), ['ms', String(now % 1000)]] }
  rumor.id = getEventHash(rumor)
  const seal = await signer.signEvent({ kind: KIND_SEAL, created_at, tags: [], content: nip44.v2.encrypt(JSON.stringify(rumor), group.conv) })
  if (!verifyEvent(seal) || seal.pubkey !== rumor.pubkey) fail('signer returned an invalid join seal')
  const wrapSk = generateSecretKey()
  const wrap = finalizeEvent({ kind: KIND_WRAP, created_at, tags: [['p', getPublicKey(wrapSk)]], content: nip44.v2.encrypt(JSON.stringify(seal), group.conv) }, group.sk)
  // A complete local opening proof before the caller can publish it.
  const openedSeal = JSON.parse(nip44.v2.decrypt(wrap.content, group.conv))
  const openedRumor = JSON.parse(nip44.v2.decrypt(openedSeal.content, group.conv))
  if (!verifyEvent(wrap) || !verifyEvent(openedSeal) || openedRumor.id !== rumor.id || openedRumor.pubkey !== rumor.pubkey || openedRumor.content !== 'join') fail('join did not round-trip locally')
  return { wrap, rumor, group }
}

/** Verify an exact post-publish guestbook read from a newly opened relay connection. */
export function verifyColdJoin(events, group, rumor) {
  for (const wrap of events || []) {
    try {
      if (wrap.id === undefined || wrap.kind !== KIND_WRAP || wrap.pubkey !== group.pub || !verifyEvent(wrap)) continue
      const seal = JSON.parse(nip44.v2.decrypt(wrap.content, group.conv))
      if (!verifyEvent(seal) || seal.kind !== KIND_SEAL || seal.pubkey !== rumor.pubkey) continue
      const opened = JSON.parse(nip44.v2.decrypt(seal.content, group.conv))
      if (opened.id === rumor.id && opened.pubkey === rumor.pubkey && opened.kind === KIND_JOIN && opened.content === 'join') return true
    } catch { /* malformed relay content */ }
  }
  return false
}
