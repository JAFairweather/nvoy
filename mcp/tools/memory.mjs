// memory.mjs — Hive Shared Memory library ("Waggle Claims & Wake Digest", docs/DESIGN_HIVE_MEMORY.md).
//
// Core invariants enforced here:
//   1. Nostr is the replication bus; the local broker (in-memory Map + atomic memory_claims.json)
//      serves reads (`memory_wake`, `memory_query`) with zero network wait and zero page cap.
//   2. Memory is data, never instruction. Every record returned carries `authority: null` and
//      `trustedInstruction: false`.
//   3. Rank and write rights are computed by the reader at read time from scope (`s`), author
//      `pubkey`, and live grant / room-membership views. No rank tag on the wire is trusted.
//   4. One memory owner key (`ownerPubkey`, defaulting to James `4010ac43...`), never a per-broker
//      manifest `grantors` list, governs `hive:canon`, the `hive:ops` owner bypass, and the memory
//      grant fold so every broker reaches the exact same verdict.
//   5. Memory never stores, caches, or re-broadcasts grants.

import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { verifyEvent } from 'nostr-tools/pure'
import { DEFAULT_MEMORY_OWNER, MEMORY_WRITE_CAP } from './admission.mjs'
import { foldMemoryGrants } from './grant_fold.mjs'
import { relayLabel } from './grant_evidence.mjs'
import { credentialIn } from './outbound_secrets.mjs'

export { DEFAULT_MEMORY_OWNER }
export const MEMORY_KIND = 30079
export const FALLBACK_MEMORY_KIND = 30078
export const MEMORY_D_PREFIX = 'hive-memory:'
export const DEFAULT_TTL_SEC = 14 * 86400
export const MAX_TTL_SEC = 30 * 86400
export const TOMBSTONE_GRACE_SEC = 30 * 86400
export const DEFAULT_AUTH_MAX_AGE_SEC = 900
export const DEFAULT_WAKE_MAX_CHARS = 6000
export const GRANT_LOOKUP_LIMIT = 100

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const SLUG = /^[a-z0-9][a-z0-9._-]{0,127}$/

// Memory-specific secret patterns required by DESIGN_HIVE_MEMORY.md in addition to outbound_secrets.mjs.
// 64-character hex strings (pubkeys, event IDs, git SHAs) and npub1/nevent1 are explicitly permitted.
// Bracketed IPv6 requires at least one colon so ordinary bracketed hex words like "[dead]" or "[add]" pass.
const MEMORY_SECRET_PATTERNS = Object.freeze([
  ['a Nostr secret key', /\bnsec1[02-9ac-hj-np-z]{20,}\b/i],
  ['an encrypted Nostr key', /\bncryptsec1[02-9ac-hj-np-z]{20,}\b/i],
  ['a bunker URI', /\bbunker:\/\/[^\s"']+/i],
  ['a nostrconnect URI', /\bnostrconnect:\/\/[^\s"']+/i],
  ['a relay WebSocket URL', /\bwss?:\/\/[^\s"']+/i],
  ['an IPv4 address literal', /\b(?:\d{1,3}\.){3}\d{1,3}\b/],
  ['a Tailscale IPv6 literal', /\bfd7a:[0-9a-f:]+/i],
  ['a bracketed IPv6 literal', /\[[0-9a-f]*:[0-9a-f:]+\]/i],
  ['an API key prefix', /\b(?:sk-[a-zA-Z0-9_-]{16,}|gh[pousr]_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}|AIza[0-9A-Za-z-_]{30,})\b/],
])

export function checkMemorySecrets(text) {
  const s = String(text ?? '')
  for (const [name, re] of MEMORY_SECRET_PATTERNS) {
    if (re.test(s)) return name
  }
  return credentialIn(s)
}

export function checkClaimPayloadSecrets({ claim, because, evidence = [], tags = [] }) {
  for (const value of [claim, because, ...(Array.isArray(evidence) ? evidence : [])]) {
    const hit = checkMemorySecrets(value)
    if (hit) return hit
  }
  for (const t of Array.isArray(tags) ? tags : []) {
    if (!Array.isArray(t)) continue
    for (const cell of t) {
      const hit = checkMemorySecrets(cell)
      if (hit) return hit
    }
  }
  return null
}

const tagValue = (ev, name) => (Array.isArray(ev?.tags) ? ev.tags : []).find(t => t?.[0] === name)?.[1]
const tagValues = (ev, name) => (Array.isArray(ev?.tags) ? ev.tags : []).filter(t => t?.[0] === name).map(t => t[1])

export function parseScope(scopeStr) {
  const s = String(scopeStr || '')
  if (s === 'hive:ops') return { type: 'hive:ops', scope: s }
  if (s === 'hive:canon') return { type: 'hive:canon', scope: s }
  if (s.startsWith('room:')) {
    const roomId = s.slice(5).toLowerCase()
    if (!UUID.test(roomId)) return null
    return { type: 'room', roomId, scope: `room:${roomId}` }
  }
  if (s.startsWith('self:')) {
    const pubkey = s.slice(5).toLowerCase()
    if (!HEX64.test(pubkey)) return null
    return { type: 'self', pubkey, scope: `self:${pubkey}` }
  }
  return null
}

export function formatFactKey(scopeStr, slug) {
  const parsed = parseScope(scopeStr)
  if (!parsed || !SLUG.test(String(slug || ''))) return null
  return `${MEMORY_D_PREFIX}${parsed.scope}:${slug}`
}

export function parseFactKey(dTag) {
  const d = String(dTag || '')
  if (!d.startsWith(MEMORY_D_PREFIX)) return null
  const rest = d.slice(MEMORY_D_PREFIX.length)
  for (const prefix of ['hive:ops:', 'hive:canon:']) {
    if (rest.startsWith(prefix)) {
      const scope = prefix.slice(0, -1)
      const slug = rest.slice(prefix.length)
      return SLUG.test(slug) ? { scope, slug, d } : null
    }
  }
  if (rest.startsWith('room:')) {
    const parts = rest.split(':')
    if (parts.length !== 3) return null
    const [, roomId, slug] = parts
    return UUID.test(roomId) && SLUG.test(slug) ? { scope: `room:${roomId}`, roomId, slug, d } : null
  }
  if (rest.startsWith('self:')) {
    const parts = rest.split(':')
    if (parts.length !== 3) return null
    const [, pubkey, slug] = parts
    return HEX64.test(pubkey) && SLUG.test(slug) ? { scope: `self:${pubkey}`, pubkey, slug, d } : null
  }
  return null
}

// NIP-01 replaceable tie-breaker: newer created_at wins; on same-second ties, lowest lexical event id wins.
export function nip01Newer(candidate, existing) {
  if (!existing) return true
  const dt = (candidate?.created_at || 0) - (existing?.created_at || 0)
  if (dt !== 0) return dt > 0
  return String(candidate?.id || '') < String(existing?.id || '')
}

// Validates wire structure, scope/route consistency, mandatory fields, and secret guard.
export function validateMemoryEvent(ev, {
  memoryGlobalChannelId = '',
  allowedKinds = [MEMORY_KIND, FALLBACK_MEMORY_KIND],
  verifySignature = true,
} = {}) {
  if (!ev || typeof ev !== 'object') return { ok: false, reason: 'event is not an object' }
  if (!allowedKinds.includes(ev.kind)) return { ok: false, reason: `unsupported kind ${ev.kind}` }
  const pubkey = String(ev.pubkey || '').toLowerCase()
  if (!HEX64.test(pubkey)) return { ok: false, reason: 'invalid pubkey' }
  if (!Number.isSafeInteger(ev.created_at) || ev.created_at <= 0) return { ok: false, reason: 'invalid created_at' }

  const d = tagValue(ev, 'd')
  if (!d || !String(d).startsWith(MEMORY_D_PREFIX)) return { ok: false, reason: 'missing or unprefixed d tag' }
  const parsedD = parseFactKey(d)
  if (!parsedD) return { ok: false, reason: 'malformed fact key in d tag' }

  const s = tagValue(ev, 's')
  if (s !== parsedD.scope) return { ok: false, reason: 's tag does not match d tag scope' }
  const parsedScope = parseScope(s)
  if (!parsedScope) return { ok: false, reason: 'invalid scope tag' }

  const h = tagValue(ev, 'h')
  if (parsedScope.type === 'room') {
    if (String(h || '').toLowerCase() !== parsedScope.roomId) {
      return { ok: false, reason: 'room claim h tag does not match room UUID in s and d' }
    }
  } else if (parsedScope.type === 'hive:ops' || parsedScope.type === 'hive:canon') {
    if (!UUID.test(String(memoryGlobalChannelId || '').toLowerCase())) {
      return { ok: false, reason: 'memory_global_channel_id is not configured' }
    }
    if (String(h || '').toLowerCase() !== String(memoryGlobalChannelId).toLowerCase()) {
      return { ok: false, reason: 'global claim h tag does not match memory_global_channel_id' }
    }
  } else if (parsedScope.type === 'self') {
    if (parsedScope.pubkey !== pubkey) {
      return { ok: false, reason: 'self claim scope pubkey does not match event pubkey' }
    }
    if (h != null) {
      return { ok: false, reason: 'Week 1 self claims stay local and must not carry an h tag' }
    }
  }

  let body
  try { body = JSON.parse(String(ev.content || '')) } catch { return { ok: false, reason: 'content is not valid JSON' } }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { ok: false, reason: 'content must be a JSON object' }

  const status = body.status === 'withdrawn' ? 'withdrawn' : body.status === 'active' ? 'active' : null
  if (!status) return { ok: false, reason: 'content.status must be "active" or "withdrawn"' }

  const because = typeof body.because === 'string' ? body.because.trim() : ''
  if (!because) return { ok: false, reason: 'content.because is required and must be non-empty' }

  const claim = typeof body.claim === 'string' ? body.claim.trim() : ''
  if (status === 'active' && !claim) return { ok: false, reason: 'content.claim is required for active claims' }

  const evidence = Array.isArray(body.evidence)
    ? body.evidence.filter(x => typeof x === 'string' && x.trim().length > 0).map(x => x.trim())
    : []
  if (status === 'active' && evidence.length === 0) {
    return { ok: false, reason: 'content.evidence must be a non-empty array of strings for active claims' }
  }

  const asOfGit = tagValue(ev, 'as_of_git') || null
  const asOfEvt = tagValue(ev, 'as_of_evt') || null
  if (status === 'active' && !asOfGit && !asOfEvt) {
    return { ok: false, reason: 'active claims require an as_of_git or as_of_evt tag' }
  }
  if (asOfEvt && !HEX64.test(String(asOfEvt).toLowerCase())) {
    return { ok: false, reason: 'as_of_evt must be a 64-hex event id' }
  }

  const expRaw = tagValue(ev, 'exp')
  let expiresAt = null
  if (expRaw != null) {
    if (!/^[0-9]{1,12}$/.test(String(expRaw))) return { ok: false, reason: 'malformed exp tag' }
    expiresAt = Number(expRaw)
    if (expiresAt > ev.created_at + MAX_TTL_SEC) {
      return { ok: false, reason: `exp exceeds maximum 30-day TTL (${MAX_TTL_SEC}s)` }
    }
  } else if (status === 'active' && (parsedScope.type === 'hive:ops' || parsedScope.type === 'room')) {
    return { ok: false, reason: 'operational and room claims require an exp tag' }
  }

  const secretHit = checkClaimPayloadSecrets({ claim, because, evidence, tags: ev.tags })
  if (secretHit) return { ok: false, reason: `secret guard blocked payload: ${secretHit}`, secret: secretHit }

  if (verifySignature) {
    let validSig = false
    try { validSig = verifyEvent(ev) } catch { validSig = false }
    if (!validSig) return { ok: false, reason: 'invalid event signature', invalidSignature: true }
  }

  return {
    ok: true,
    pubkey,
    d,
    slug: parsedD.slug,
    scope: parsedScope.scope,
    scopeType: parsedScope.type,
    roomId: parsedScope.roomId || null,
    channelId: h ? String(h).toLowerCase() : null,
    topic: tagValue(ev, 'topic') || parsedD.slug,
    asOfGit,
    asOfEvt: asOfEvt ? String(asOfEvt).toLowerCase() : null,
    expiresAt,
    supersedes: tagValues(ev, 'supersedes'),
    status,
    claim,
    because,
    evidence,
    createdAt: ev.created_at,
  }
}

// Builds an unsigned claim event template with monotonic created_at relative to any replaced claim.
export function buildClaimTemplate({
  pubkey,
  scope,
  slug,
  topic,
  claim,
  because,
  evidence,
  asOfGit,
  asOfEvt,
  ttlSec = DEFAULT_TTL_SEC,
  supersedes = [],
  memoryGlobalChannelId = '',
  kind = MEMORY_KIND,
  nowSec = Math.floor(Date.now() / 1000),
  priorCreatedAt = 0,
}) {
  const parsedScope = parseScope(scope)
  if (!parsedScope) throw new Error(`invalid scope: ${scope}`)
  if (!SLUG.test(String(slug || ''))) throw new Error(`invalid fact slug: ${slug}`)
  const d = formatFactKey(parsedScope.scope, slug)
  const createdAt = Math.max(nowSec, Number.isSafeInteger(priorCreatedAt) ? priorCreatedAt + 1 : 0)

  const effectiveTtl = ttlSec == null ? DEFAULT_TTL_SEC : Number(ttlSec)
  if (!Number.isInteger(effectiveTtl) || effectiveTtl <= 0 || effectiveTtl > MAX_TTL_SEC) {
    throw new Error(`ttlSec must be 1..${MAX_TTL_SEC}`)
  }
  const exp = createdAt + effectiveTtl

  const tags = [['d', d]]
  if (parsedScope.type === 'room') {
    tags.push(['h', parsedScope.roomId])
  } else if (parsedScope.type === 'hive:ops' || parsedScope.type === 'hive:canon') {
    if (!UUID.test(String(memoryGlobalChannelId || '').toLowerCase())) {
      throw new Error('memory_global_channel_id is required to write global claims')
    }
    tags.push(['h', String(memoryGlobalChannelId).toLowerCase()])
  }
  tags.push(['s', parsedScope.scope])
  tags.push(['topic', String(topic || slug)])
  if (asOfGit) tags.push(['as_of_git', String(asOfGit)])
  if (asOfEvt) tags.push(['as_of_evt', String(asOfEvt).toLowerCase()])
  tags.push(['exp', String(exp)])
  for (const sup of Array.isArray(supersedes) ? supersedes : []) {
    if (sup) tags.push(['supersedes', String(sup)])
  }

  const contentObj = {
    claim: String(claim ?? '').trim(),
    because: String(because ?? '').trim(),
    evidence: Array.isArray(evidence) ? evidence.map(x => String(x).trim()).filter(Boolean) : [],
    status: 'active',
  }
  const template = {
    kind,
    pubkey: String(pubkey || '').toLowerCase(),
    created_at: createdAt,
    tags,
    content: JSON.stringify(contentObj),
  }
  const check = validateMemoryEvent(template, { memoryGlobalChannelId, verifySignature: false })
  if (!check.ok) throw new Error(check.reason)
  return template
}

// Builds a withdrawal replacement event template + optional NIP-09 kind 5 deletion request template.
export function buildWithdrawalTemplate({
  pubkey,
  priorEvent,
  scope,
  slug,
  because,
  memoryGlobalChannelId = '',
  kind = MEMORY_KIND,
  nowSec = Math.floor(Date.now() / 1000),
}) {
  const priorCheck = priorEvent
    ? validateMemoryEvent(priorEvent, { memoryGlobalChannelId, verifySignature: false })
    : null
  const targetScope = priorCheck?.ok ? priorCheck.scope : scope
  const targetSlug = priorCheck?.ok ? priorCheck.slug : slug
  const parsedScope = parseScope(targetScope)
  if (!parsedScope) throw new Error(`invalid scope: ${targetScope}`)
  const d = formatFactKey(parsedScope.scope, targetSlug)
  if (!d) throw new Error(`invalid slug: ${targetSlug}`)

  // Strictly later created_at than the claim it withdraws so a same-second tombstone never loses a tie.
  const priorAt = priorEvent?.created_at || 0
  const createdAt = Math.max(nowSec, priorAt + 1)
  const priorExp = priorCheck?.expiresAt || (createdAt + DEFAULT_TTL_SEC)

  const tags = [['d', d]]
  if (parsedScope.type === 'room') {
    tags.push(['h', parsedScope.roomId])
  } else if (parsedScope.type === 'hive:ops' || parsedScope.type === 'hive:canon') {
    if (!UUID.test(String(memoryGlobalChannelId || '').toLowerCase())) {
      throw new Error('memory_global_channel_id is required to withdraw global claims')
    }
    tags.push(['h', String(memoryGlobalChannelId).toLowerCase()])
  }
  tags.push(['s', parsedScope.scope])
  tags.push(['topic', priorCheck?.topic || targetSlug])
  tags.push(['exp', String(Math.min(priorExp, createdAt + MAX_TTL_SEC))])

  const contentObj = {
    claim: '',
    because: String(because ?? '').trim(),
    evidence: priorCheck?.evidence || [],
    status: 'withdrawn',
  }
  const replacement = {
    kind: priorEvent?.kind || kind,
    pubkey: String(pubkey || priorEvent?.pubkey || '').toLowerCase(),
    created_at: createdAt,
    tags,
    content: JSON.stringify(contentObj),
  }
  const check = validateMemoryEvent(replacement, { memoryGlobalChannelId, verifySignature: false })
  if (!check.ok) throw new Error(check.reason)

  const nip09Delete = priorEvent?.id
    ? {
        kind: 5,
        pubkey: replacement.pubkey,
        created_at: createdAt,
        tags: [
          ['e', priorEvent.id],
          ['a', `${replacement.kind}:${replacement.pubkey}:${d}`],
          ['k', String(replacement.kind)],
        ],
        content: String(because ?? '').trim(),
      }
    : null

  return { replacement, nip09Delete }
}

// Two-phase targeted grant refresh (DESIGN_HIVE_MEMORY.md § "Authorization inputs and offline reads").
// Uses a single configured `ownerPubkey` (James), never a per-broker manifest `grantors` list.
export async function refreshMemoryGrants({
  writers = [],
  ownerPubkey = DEFAULT_MEMORY_OWNER,
  allowMemoryWriteCap = false,
  relays = [],
  queryFn,
  nowSec = Math.floor(Date.now() / 1000),
  limit = GRANT_LOOKUP_LIMIT,
}) {
  const owner = String(ownerPubkey || '').toLowerCase()
  const targetWriters = [...new Set(writers.map(w => String(w).toLowerCase()).filter(w => HEX64.test(w) && w !== owner))]
  const relayLabels = relays.map((url, idx) => relayLabel(url, idx))

  if (!relays.length || !HEX64.test(owner)) {
    return {
      complete: false,
      relaysAnswered: 0,
      relaysTotal: relays.length,
      disagreeingRelays: [],
      writers: new Map(),
      ended: new Map(),
      partialWriters: new Set(targetWriters),
      checkedAt: null,
    }
  }

  const phase1Targets = targetWriters.length ? targetWriters : [owner]
  const relayCompletedAll = new Map(relays.map((_, i) => [i, true]))
  const grantsByWriterPerRelay = new Map() // writer -> Map(relayIdx -> Set(grantId))
  const validGrants = new Map() // grantId -> event
  const allGrantEvents = new Map() // eventId -> event

  const lookupAnswered = res =>
    res && res.eose === true && !res.closed && Array.isArray(res.events) && res.events.length < limit

  // Phase 1: For each writer, ask every relay for kinds: [440], authors: [owner], #p: [writer]
  for (const writer of phase1Targets) {
    const perRelay = new Map()
    grantsByWriterPerRelay.set(writer, perRelay)
    await Promise.all(relays.map(async (url, idx) => {
      let res
      try {
        res = await queryFn(url, { kinds: [440], authors: [owner], '#p': [writer], limit })
      } catch {
        res = { events: [], eose: false }
      }
      if (!lookupAnswered(res)) {
        relayCompletedAll.set(idx, false)
        return
      }
      const ids = new Set()
      for (const ev of res.events) {
        if (!ev || ev.kind !== 440 || String(ev.pubkey || '').toLowerCase() !== owner) continue
        const pTag = tagValue(ev, 'p')
        if (String(pTag || '').toLowerCase() !== writer) continue
        let ok = false; try { ok = verifyEvent(ev) } catch { ok = false }
        if (!ok) continue
        ids.add(ev.id)
        validGrants.set(ev.id, ev)
        allGrantEvents.set(ev.id, ev)
      }
      perRelay.set(idx, ids)
    }))
  }

  // Phase 2: Ask every configured grant relay for revocations (kind 441) of the union of grant IDs,
  // including relays that did not return the grant in Phase 1.
  const unionGrantIds = [...validGrants.keys()]
  const revocationsPerRelay = new Map() // relayIdx -> Set(revocationEventId)
  const validRevocations = new Map() // revocationEventId -> event

  if (unionGrantIds.length > 0) {
    await Promise.all(relays.map(async (url, idx) => {
      let res
      try {
        res = await queryFn(url, { kinds: [441], authors: [owner], '#e': unionGrantIds, limit })
      } catch {
        res = { events: [], eose: false }
      }
      if (!lookupAnswered(res)) {
        relayCompletedAll.set(idx, false)
        return
      }
      const ids = new Set()
      for (const ev of res.events) {
        if (!ev || ev.kind !== 441 || String(ev.pubkey || '').toLowerCase() !== owner) continue
        const eTag = tagValue(ev, 'e')
        if (!unionGrantIds.includes(eTag)) continue
        let ok = false; try { ok = verifyEvent(ev) } catch { ok = false }
        if (!ok) continue
        ids.add(ev.id)
        validRevocations.set(ev.id, ev)
        allGrantEvents.set(ev.id, ev)
      }
      revocationsPerRelay.set(idx, ids)
    }))
  }

  // Detect disagreeing relays: an answered relay that omitted a valid 440 or 441 that another relay returned.
  const disagreeingSet = new Set()
  for (const [, perRelay] of grantsByWriterPerRelay) {
    const unionForWriter = new Set()
    for (const ids of perRelay.values()) for (const id of ids) unionForWriter.add(id)
    for (const [idx, ids] of perRelay.entries()) {
      for (const id of unionForWriter) {
        if (!ids.has(id)) disagreeingSet.add(relayLabels[idx])
      }
    }
  }
  if (unionGrantIds.length > 0) {
    const allRevIds = new Set(validRevocations.keys())
    for (const [idx, ids] of revocationsPerRelay.entries()) {
      for (const revId of allRevIds) {
        if (!ids.has(revId)) disagreeingSet.add(relayLabels[idx])
      }
    }
  }

  const relaysAnswered = [...relayCompletedAll.values()].filter(Boolean).length
  const complete = relaysAnswered === relays.length
  const folded = foldMemoryGrants([...allGrantEvents.values()], {
    owner,
    allowMemoryWrite: allowMemoryWriteCap,
    nowSec,
  })

  // If the refresh was partial, any writer that ended (`revoked` or `expired`) or had no grant found
  // might have a live re-grant on the relay that failed to answer.
  const partialWriters = new Set()
  if (!complete) {
    for (const writer of targetWriters) {
      if (!folded.writers.has(writer)) partialWriters.add(writer)
    }
  }

  return {
    complete,
    relaysAnswered,
    relaysTotal: relays.length,
    disagreeingRelays: [...disagreeingSet].sort(),
    writers: folded.writers,
    ended: folded.ended,
    partialWriters,
    checkedAt: complete ? nowSec : null,
  }
}

// Data-only envelope quarantine: memory records never carry an `authority` object and always set
// `trustedInstruction: false`.
export function toMemoryEnvelope(entry, {
  computedRank = null,
  verification = 'unverified',
  verificationReason = null,
  checkedAt = null,
  staleWarning = null,
} = {}) {
  return {
    record_type: 'memory-claim',
    authority: null,
    trustedInstruction: false,
    verification,
    verification_reason: verificationReason,
    checked_at: checkedAt,
    computed_rank: verification === 'accepted' ? computedRank : null,
    event_id: entry.event.id,
    author_pubkey: entry.pubkey,
    scope: entry.scope,
    d: entry.d,
    topic: entry.topic,
    claim: entry.claim,
    because: entry.because,
    evidence: entry.evidence,
    as_of_git: entry.asOfGit,
    as_of_evt: entry.asOfEvt,
    created_at: entry.createdAt,
    expires_at: entry.expiresAt,
    stale_warning: staleWarning || entry.staleWarning || null,
  }
}

export class MemoryStore {
  constructor({
    statePath,
    readerPubkey,
    // One single configured memory owner key (defaults to James `4010ac43...`), never a per-broker
    // manifest `grantors` list. Even if a caller passes a manifest `grantors` array, it is ignored
    // unless `ownerPubkey` is explicitly provided.
    ownerPubkey = DEFAULT_MEMORY_OWNER,
    memoryGlobalChannelId = '',
    subscribedRooms = [],
    authMaxAgeSec = DEFAULT_AUTH_MAX_AGE_SEC,
    // Defaults to false in Slice 1 until James approves the `memory-write` cap on #712.
    allowMemoryWriteCap = false,
  }) {
    this.statePath = statePath ? resolve(statePath) : null
    this.readerPubkey = String(readerPubkey || '').toLowerCase()
    const cleanOwner = String(ownerPubkey || '').toLowerCase()
    if (!HEX64.test(cleanOwner)) throw new Error('ownerPubkey must be a single 64-hex public key')
    this.ownerPubkey = cleanOwner
    this.memoryGlobalChannelId = String(memoryGlobalChannelId || '').toLowerCase()
    this.subscribedRooms = new Set(
      (Array.isArray(subscribedRooms) ? subscribedRooms : [])
        .map(r => String(r || '').toLowerCase())
        .filter(r => UUID.test(r))
    )
    this.authMaxAgeSec = authMaxAgeSec
    this.allowMemoryWriteCap = Boolean(allowMemoryWriteCap)

    // Map<compositeKey `${pubkey}:${d}`, StoredEntry>
    this.entries = new Map()
    // Channel sync watermarks: channelId -> { state, lastEoseAt, localCount, remoteCount, missingCount }
    this.channelSync = new Map()
    // Room member lists: roomId -> { members: Set<pubkey>, checkedAt: number }
    this.roomMembers = new Map()
    // In-memory grant state (never persisted to disk!)
    this.grantView = {
      grantsCheckedAt: null,
      lastRefreshComplete: false,
      relaysAnswered: 0,
      relaysTotal: 0,
      disagreeingRelays: [],
      writers: new Map(),
      ended: new Map(),
      partialWriters: new Set(),
    }

    if (this.statePath) this.load()
  }

  compositeKey(pubkey, d) {
    return `${String(pubkey).toLowerCase()}:${d}`
  }

  load() {
    if (!this.statePath || !existsSync(this.statePath)) return
    const st = lstatSync(this.statePath)
    if (!st.isFile() || st.isSymbolicLink()) throw new Error('memory_claims.json must be a regular non-symlink file')
    const raw = JSON.parse(readFileSync(this.statePath, 'utf8'))
    if (raw?.version !== 1 || !Array.isArray(raw.entries)) return
    for (const item of raw.entries) {
      if (!item?.event) continue
      this.ingestEvent(item.event, { persist: false, nowSec: item.ingestedAt || item.event.created_at })
    }
  }

  persist(nowSec = Math.floor(Date.now() / 1000)) {
    if (!this.statePath) return
    this.pruneTombstones(nowSec)
    mkdirSync(dirname(this.statePath), { recursive: true, mode: 0o700 })
    const payload = {
      version: 1,
      updated_at: nowSec,
      entries: [...this.entries.values()].map(e => ({
        event: e.event,
        tombstoneUntil: e.tombstoneUntil || null,
        withdrawnExp: e.withdrawnExp || null,
        ingestedAt: e.ingestedAt || nowSec,
      })),
    }
    const tmp = `${this.statePath}.${process.pid}.${Date.now()}.tmp`
    writeFileSync(tmp, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 })
    renameSync(tmp, this.statePath)
  }

  pruneTombstones(nowSec = Math.floor(Date.now() / 1000)) {
    for (const [k, entry] of this.entries.entries()) {
      if (entry.status === 'withdrawn' && entry.tombstoneUntil && nowSec > entry.tombstoneUntil) {
        this.entries.delete(k)
      }
    }
  }

  // Ingests a signed claim or withdrawal event into the local Map + atomic memory_claims.json.
  ingestEvent(ev, { persist = true, nowSec = Math.floor(Date.now() / 1000) } = {}) {
    const parsed = validateMemoryEvent(ev, {
      memoryGlobalChannelId: this.memoryGlobalChannelId,
      verifySignature: true,
    })
    if (!parsed.ok) return { accepted: false, reason: parsed.reason, invalidSignature: !!parsed.invalidSignature }

    const key = this.compositeKey(parsed.pubkey, parsed.d)
    const existing = this.entries.get(key)

    if (existing) {
      // While a durable tombstone is retained, ignore any event for (pubkey, d) that is not strictly newer.
      if (existing.status === 'withdrawn') {
        if ((ev.created_at || 0) <= (existing.createdAt || 0)) {
          return { accepted: false, reason: 'suppressed by durable withdrawal tombstone' }
        }
      } else if (!nip01Newer(ev, existing.event)) {
        return { accepted: false, reason: 'older than or lost NIP-01 tie to existing event' }
      }
    }

    const withdrawnExp = parsed.status === 'withdrawn'
      ? (existing?.expiresAt || parsed.expiresAt || (ev.created_at + DEFAULT_TTL_SEC))
      : null
    const tombstoneUntil = parsed.status === 'withdrawn'
      ? withdrawnExp + TOMBSTONE_GRACE_SEC
      : null

    if (parsed.roomId) this.subscribedRooms.add(parsed.roomId)

    const stored = {
      ...parsed,
      event: JSON.parse(JSON.stringify(ev)),
      withdrawnExp,
      tombstoneUntil,
      ingestedAt: nowSec,
    }
    this.entries.set(key, stored)
    if (persist) this.persist(nowSec)
    return { accepted: true, status: parsed.status, key, entry: stored }
  }

  // Updates per-channel sync watermark after a relay subscription EOSE or connection failure.
  // Detects both full and partial relay eviction by comparing remote event IDs against local active,
  // non-expired claims for that channel.
  recordChannelSync(channelId, { reachable = true, eose = false, remoteEvents = [], nowSec = Math.floor(Date.now() / 1000) } = {}) {
    const ch = String(channelId || '').toLowerCase()
    if (!ch) return null
    if (UUID.test(ch) && ch !== this.memoryGlobalChannelId) this.subscribedRooms.add(ch)

    const remoteIds = new Set()
    for (const ev of Array.isArray(remoteEvents) ? remoteEvents : []) {
      if (ev?.id) remoteIds.add(ev.id)
      this.ingestEvent(ev, { persist: false, nowSec })
    }
    if (remoteEvents?.length) this.persist(nowSec)

    const localActive = [...this.entries.values()].filter(e =>
      e.channelId === ch && e.status === 'active' && (!e.expiresAt || e.expiresAt > nowSec)
    )
    const localNonExpired = localActive.length

    const prev = this.channelSync.get(ch)
    if (!reachable || !eose) {
      const state = {
        state: 'RELAY_UNREACHABLE_SERVING_LOCAL',
        lastEoseAt: prev?.lastEoseAt || null,
        localCount: localNonExpired,
        remoteCount: null,
        missingCount: null,
      }
      this.channelSync.set(ch, state)
      return state
    }

    const remoteCount = Array.isArray(remoteEvents) ? remoteEvents.length : 0
    const missingFromRelay = localActive.filter(e => !remoteIds.has(e.event.id)).length
    let syncState = 'SYNCED_OK'
    if (missingFromRelay > 0) {
      syncState = 'RELAY_EVICTED_WARNING'
    } else if (remoteCount === 0 && localNonExpired === 0) {
      syncState = 'SYNCED_EMPTY'
    }

    const state = {
      state: syncState,
      lastEoseAt: nowSec,
      localCount: localNonExpired,
      remoteCount,
      missingCount: missingFromRelay,
    }
    this.channelSync.set(ch, state)
    return state
  }

  getChannelSync(channelId, nowSec = Math.floor(Date.now() / 1000)) {
    const ch = String(channelId || '').toLowerCase()
    const existing = this.channelSync.get(ch)
    if (existing) return existing
    const localNonExpired = [...this.entries.values()].filter(e =>
      e.channelId === ch && e.status === 'active' && (!e.expiresAt || e.expiresAt > nowSec)
    ).length
    return {
      state: 'RELAY_UNREACHABLE_SERVING_LOCAL',
      lastEoseAt: null,
      localCount: localNonExpired,
      remoteCount: null,
      missingCount: null,
    }
  }

  // Updates room membership from a relay-signed kind 39002 event (verifying signature, optional
  // relayPubkey, and NIP-01 created_at monotonicity so an older replay cannot replace a newer list)
  // or from an explicit member array.
  recordRoomMembers(roomIdOrEvent, membersOrOpts = [], { checkedAt = Math.floor(Date.now() / 1000), relayPubkey = null } = {}) {
    if (roomIdOrEvent && typeof roomIdOrEvent === 'object' && roomIdOrEvent.kind === 39002) {
      const ev = roomIdOrEvent
      const opts = membersOrOpts && typeof membersOrOpts === 'object' && !Array.isArray(membersOrOpts) ? membersOrOpts : { checkedAt, relayPubkey }
      let valid = false; try { valid = verifyEvent(ev) } catch { valid = false }
      if (!valid || !Number.isSafeInteger(ev.created_at)) throw new Error('kind 39002 room member list has an invalid signature')
      if (opts.relayPubkey && String(ev.pubkey || '').toLowerCase() !== String(opts.relayPubkey).toLowerCase()) {
        throw new Error('kind 39002 room member list was not signed by the expected relay key')
      }
      const id = String(tagValue(ev, 'd') || '').toLowerCase()
      if (!UUID.test(id)) throw new Error('kind 39002 d tag is not a valid room UUID')
      const prev = this.roomMembers.get(id)
      const evId = String(ev.id || '').toLowerCase()
      if (
        prev &&
        prev.eventCreatedAt !== undefined &&
        (ev.created_at < prev.eventCreatedAt ||
          (ev.created_at === prev.eventCreatedAt && evId >= String(prev.eventId || '').toLowerCase()))
      ) {
        return false
      }
      const members = tagValues(ev, 'p').map(m => String(m || '').toLowerCase()).filter(m => HEX64.test(m))
      this.subscribedRooms.add(id)
      this.roomMembers.set(id, {
        members: new Set(members),
        checkedAt: opts.checkedAt ?? Math.floor(Date.now() / 1000),
        eventCreatedAt: ev.created_at,
        eventId: evId,
      })
      return true
    }
    const id = String(roomIdOrEvent || '').toLowerCase()
    if (!UUID.test(id)) throw new Error(`invalid room UUID: ${roomIdOrEvent}`)
    const set = new Set((Array.isArray(membersOrOpts) ? membersOrOpts : []).map(m => String(m).toLowerCase()).filter(m => HEX64.test(m)))
    this.subscribedRooms.add(id)
    this.roomMembers.set(id, { members: set, checkedAt })
    return true
  }

  // Runs the two-phase targeted grant refresh and updates the in-memory grant view.
  async refreshGrants({ relays = [], queryFn, nowSec = Math.floor(Date.now() / 1000) }) {
    const candidateWriters = [...new Set(
      [...this.entries.values()]
        .filter(e => e.status === 'active' && (e.scopeType === 'hive:ops' || e.scopeType === 'hive:canon'))
        .map(e => e.pubkey)
    )]
    const res = await refreshMemoryGrants({
      writers: candidateWriters,
      ownerPubkey: this.ownerPubkey,
      allowMemoryWriteCap: this.allowMemoryWriteCap,
      relays,
      queryFn,
      nowSec,
    })

    // Only a complete refresh advances `grantsCheckedAt` or adds new positive writer rights.
    // On a partial refresh, keep only the writers/capabilities that were already held from the last
    // complete refresh and are not ended now; apply revocations and expiries seen by the partial
    // refresh immediately, but never add a new positive right from a partial refresh.
    const nextCheckedAt = res.complete ? res.checkedAt : this.grantView.grantsCheckedAt
    let nextWriters = res.writers
    let nextEnded = res.ended
    if (!res.complete) {
      nextWriters = new Map()
      for (const [writer, prevCaps] of this.grantView.writers.entries()) {
        const partialCaps = res.writers.get(writer)
        if (!partialCaps || res.ended.has(writer)) continue
        const kept = new Map()
        for (const [cap, info] of prevCaps.entries()) {
          if (partialCaps.get(cap)?.grantId === info.grantId) kept.set(cap, info)
        }
        if (kept.size > 0) nextWriters.set(writer, kept)
      }
      nextEnded = new Map([...this.grantView.ended, ...res.ended])
      for (const writer of nextWriters.keys()) nextEnded.delete(writer)
    }
    this.grantView = {
      grantsCheckedAt: nextCheckedAt,
      lastRefreshComplete: res.complete,
      relaysAnswered: res.relaysAnswered,
      relaysTotal: res.relaysTotal,
      disagreeingRelays: res.disagreeingRelays,
      writers: nextWriters,
      ended: nextEnded,
      partialWriters: res.partialWriters,
    }
    return this.grantView
  }

  // Evaluates a stored claim at read time: computes verification ('accepted' | 'unverified' | 'rejected')
  // and precedence rank (2, 3, or 4).
  evaluateClaim(entry, { nowSec = Math.floor(Date.now() / 1000), staleFiles = new Set(), readerPubkey = undefined } = {}) {
    const activeReaderPubkey = readerPubkey !== undefined ? String(readerPubkey || '').toLowerCase() : this.readerPubkey
    if (!entry || entry.status === 'withdrawn') {
      return { verification: 'withdrawn', verificationReason: 'withdrawn', computedRank: null, checkedAt: null }
    }
    if (entry.expiresAt != null && entry.expiresAt <= nowSec) {
      return { verification: 'expired', verificationReason: 'expired', computedRank: null, checkedAt: null }
    }

    // Check if cited evidence file was modified since as_of_git
    let staleWarning = null
    if (entry.asOfGit && Array.isArray(entry.evidence)) {
      for (const ref of entry.evidence) {
        if (staleFiles.has(ref) || staleFiles.has(`${entry.asOfGit}:${ref}`)) {
          staleWarning = `[STALE: evidence file changed since ${entry.asOfGit}]`
          break
        }
      }
    }

    if (entry.scopeType === 'self') {
      if (!activeReaderPubkey || entry.pubkey !== activeReaderPubkey) {
        return { verification: 'rejected', verificationReason: 'foreign-self-claim', computedRank: null, checkedAt: nowSec }
      }
      return { verification: 'accepted', verificationReason: null, computedRank: 4, checkedAt: nowSec, staleWarning }
    }

    if (entry.scopeType === 'room') {
      if (!activeReaderPubkey) {
        return { verification: 'rejected', verificationReason: 'reader-not-in-room', computedRank: null, checkedAt: nowSec, staleWarning }
      }
      const roomView = this.roomMembers.get(entry.roomId)
      if (!roomView || roomView.checkedAt == null) {
        return { verification: 'unverified', verificationReason: 'room-list-unavailable', computedRank: null, checkedAt: null, staleWarning }
      }
      if (!roomView.members.has(activeReaderPubkey)) {
        return { verification: 'rejected', verificationReason: 'reader-not-in-room', computedRank: null, checkedAt: roomView.checkedAt, staleWarning }
      }
      if (nowSec - roomView.checkedAt > this.authMaxAgeSec) {
        return { verification: 'unverified', verificationReason: 'room-auth-stale', computedRank: null, checkedAt: roomView.checkedAt, staleWarning }
      }
      if (!roomView.members.has(entry.pubkey)) {
        return { verification: 'rejected', verificationReason: 'author-not-in-room', computedRank: null, checkedAt: roomView.checkedAt, staleWarning }
      }
      return { verification: 'accepted', verificationReason: null, computedRank: 3, checkedAt: roomView.checkedAt, staleWarning }
    }

    const isOwner = entry.pubkey === this.ownerPubkey

    // Rank 2 (`hive:canon`): James's decision (waggle#712 at a2c1781f) restricts `hive:canon` to
    // the memory owner key alone, checked by signature alone with no grant-freshness gate.
    if (entry.scopeType === 'hive:canon') {
      if (isOwner) {
        return { verification: 'accepted', verificationReason: null, computedRank: 2, checkedAt: entry.createdAt, staleWarning }
      }
      return { verification: 'rejected', verificationReason: 'canon-owner-only', computedRank: null, checkedAt: nowSec, staleWarning }
    }

    // Rank 3 (`hive:ops`): Owner's own `hive:ops` claims also depend on signature alone and do not go stale on grant age.
    if (entry.scopeType === 'hive:ops') {
      if (isOwner) {
        return { verification: 'accepted', verificationReason: null, computedRank: 3, checkedAt: entry.createdAt, staleWarning }
      }

      const gv = this.grantView
      const checkedAt = gv.grantsCheckedAt
      const authFresh = checkedAt != null && (nowSec - checkedAt) <= this.authMaxAgeSec
      const heldCaps = gv.writers.get(entry.pubkey)
      const endedReason = gv.ended.get(entry.pubkey)

      // Positive revocation/expiry evidence from a complete refresh rejects immediately, even if auth is old.
      if (gv.lastRefreshComplete && endedReason && !heldCaps) {
        return {
          verification: 'rejected',
          verificationReason: endedReason === 'revoked' ? 'grant-revoked' : 'grant-expired',
          computedRank: null,
          checkedAt,
          staleWarning,
        }
      }

      // If a partial refresh saw a revocation/expiry for this writer, it is not accepted;
      // if another relay did not answer, it may hold a live re-grant, so mark unverified ('grant-missing').
      if (!gv.lastRefreshComplete && (endedReason || gv.partialWriters.has(entry.pubkey)) && !heldCaps) {
        return {
          verification: 'unverified',
          verificationReason: 'grant-missing',
          computedRank: null,
          checkedAt,
          staleWarning,
        }
      }

      const qualifiesOps = Boolean(heldCaps?.has('shadow')) || (this.allowMemoryWriteCap && Boolean(heldCaps?.has(MEMORY_WRITE_CAP)))
      if (!qualifiesOps) {
        return {
          verification: 'unverified',
          verificationReason: checkedAt == null ? 'grants-uninitialized' : 'grant-missing',
          computedRank: null,
          checkedAt,
          staleWarning,
        }
      }
      if (!authFresh) {
        return {
          verification: 'unverified',
          verificationReason: checkedAt == null ? 'grants-uninitialized' : 'grants-stale',
          computedRank: null,
          checkedAt,
          staleWarning,
        }
      }
      return { verification: 'accepted', verificationReason: null, computedRank: 3, checkedAt, staleWarning }
    }

    return { verification: 'rejected', verificationReason: 'unknown-scope', computedRank: null, checkedAt: null }
  }

  // Returns manual re-seed candidates: latest verified event per (pubkey, d), including withdrawals,
  // excluding self claims and expired active claims, and never touching grants.
  reseedCandidates(nowSec = Math.floor(Date.now() / 1000)) {
    this.pruneTombstones(nowSec)
    const out = []
    for (const entry of this.entries.values()) {
      if (entry.scopeType === 'self') continue
      if (entry.status === 'active' && entry.expiresAt != null && entry.expiresAt <= nowSec) continue
      let ok = false; try { ok = verifyEvent(entry.event) } catch { ok = false }
      if (!ok) continue
      out.push(entry.event)
    }
    return out.sort((a, b) => (a.created_at || 0) - (b.created_at || 0) || (a.id < b.id ? -1 : 1))
  }

  // Executes memory_query against the local in-memory Map with zero relay round-trip.
  query({
    scope = null,
    roomId = null,
    topic = null,
    d = null,
    text = null,
    limit = 50,
    cursor = 0,
    nowSec = Math.floor(Date.now() / 1000),
    staleFiles = new Set(),
    readerPubkey = undefined,
  } = {}) {
    const activeReaderPubkey = readerPubkey !== undefined ? String(readerPubkey || '').toLowerCase() : this.readerPubkey
    const startIdx = Number.isSafeInteger(Number(cursor)) && Number(cursor) >= 0 ? Number(cursor) : 0
    const pageLimit = Number.isSafeInteger(Number(limit)) && Number(limit) > 0 ? Number(limit) : 50
    const qText = text ? String(text).toLowerCase() : null

    const channelsToCheck = new Set()
    let missingRequiredChannelConfig = false
    if (scope === 'hive:ops' || scope === 'hive:canon' || !scope) {
      if (this.memoryGlobalChannelId) channelsToCheck.add(this.memoryGlobalChannelId)
      else missingRequiredChannelConfig = true
    }
    if (!scope && activeReaderPubkey) {
      for (const r of this.subscribedRooms) channelsToCheck.add(r)
      for (const r of this.roomMembers.keys()) channelsToCheck.add(r)
      for (const ch of this.channelSync.keys()) channelsToCheck.add(ch)
    }
    if (roomId) channelsToCheck.add(String(roomId).toLowerCase())
    if (scope && String(scope).startsWith('room:')) channelsToCheck.add(String(scope).slice(5).toLowerCase())

    const acceptedMatches = []
    let unverifiedCount = 0
    const unverifiedReasons = new Set()
    // Count conflicts over every accepted claim in scope BEFORE applying the text filter (`qText`),
    // so filtering by `text` never hides the fact that a returned claim is in conflict.
    const byFactKey = new Map()

    for (const entry of this.entries.values()) {
      if (entry.status === 'withdrawn') continue
      if (entry.expiresAt != null && entry.expiresAt <= nowSec) continue
      if (scope && entry.scope !== scope) continue
      if (roomId && entry.roomId !== String(roomId).toLowerCase()) continue
      if (topic && entry.topic !== topic) continue
      if (d && entry.d !== d) continue

      const verdict = this.evaluateClaim(entry, { nowSec, staleFiles, readerPubkey: activeReaderPubkey })
      if (entry.channelId && verdict.verification !== 'rejected') channelsToCheck.add(entry.channelId)
      if (verdict.verification === 'accepted') {
        if (!byFactKey.has(entry.d)) byFactKey.set(entry.d, new Set())
        byFactKey.get(entry.d).add(entry.claim)
      }

      if (qText) {
        const hay = `${entry.d} ${entry.topic} ${entry.claim} ${entry.because} ${(entry.evidence || []).join(' ')}`.toLowerCase()
        if (!hay.includes(qText)) continue
      }

      if (verdict.verification === 'accepted') {
        acceptedMatches.push({ entry, verdict })
      } else if (verdict.verification === 'unverified') {
        unverifiedCount++
        if (verdict.verificationReason) unverifiedReasons.add(verdict.verificationReason)
      }
    }

    acceptedMatches.sort((a, b) => {
      const aConflict = (byFactKey.get(a.entry.d)?.size || 0) > 1 ? 1 : 0
      const bConflict = (byFactKey.get(b.entry.d)?.size || 0) > 1 ? 1 : 0
      if (aConflict !== bConflict) return bConflict - aConflict
      if (a.verdict.computedRank !== b.verdict.computedRank) return a.verdict.computedRank - b.verdict.computedRank
      if (a.entry.createdAt !== b.entry.createdAt) return b.entry.createdAt - a.entry.createdAt
      return a.entry.event.id < b.entry.event.id ? -1 : 1
    })

    const totalMatched = acceptedMatches.length
    const sliced = acceptedMatches.slice(startIdx, startIdx + pageLimit)
    const records = sliced.map(({ entry, verdict }) => ({
      ...toMemoryEnvelope(entry, verdict),
      conflict: (byFactKey.get(entry.d)?.size || 0) > 1,
    }))
    const omitted = Math.max(0, totalMatched - (startIdx + records.length))
    const nextCursor = omitted > 0 ? String(startIdx + records.length) : null

    const isSelfScope = Boolean(scope && String(scope).startsWith('self:'))
    const channels = {}
    let allChannelsSynced = !missingRequiredChannelConfig && (isSelfScope || channelsToCheck.size > 0)
    for (const ch of channelsToCheck) {
      const st = this.getChannelSync(ch, nowSec)
      channels[ch] = st
      if (st.state !== 'SYNCED_OK' && st.state !== 'SYNCED_EMPTY') {
        allChannelsSynced = false
      }
    }

    let answer = 'found'
    let answerReason = null
    if (totalMatched === 0) {
      if (allChannelsSynced && unverifiedCount === 0) {
        answer = 'none'
      } else {
        answer = 'unknown'
        answerReason = unverifiedCount > 0
          ? `unverified:${[...unverifiedReasons].join(',') || 'unverified'}`
          : 'channel-not-synced'
      }
    }

    return {
      answer,
      answer_reason: answerReason,
      records,
      total_matched: totalMatched,
      returned: records.length,
      omitted,
      next_cursor: nextCursor,
      unverified: unverifiedCount,
      unverified_reasons: [...unverifiedReasons],
      channels,
      grants_checked_at: this.grantView.grantsCheckedAt,
      relays_answered: `${this.grantView.relaysAnswered}/${this.grantView.relaysTotal}`,
      disagreeing_relays: this.grantView.disagreeingRelays,
    }
  }

  // Builds the bounded 6,000-character Wake Digest (DESIGN_HIVE_MEMORY.md § "Bounded wake digest").
  // Every section (including unverified canon keys and the Unverified summary) has its own bounded
  // budget so nothing is ever silently cut off by a trailing slice.
  wake({
    roomId = null,
    maxChars = DEFAULT_WAKE_MAX_CHARS,
    gitBanner = null,
    staleFiles = new Set(),
    wakeDigestPath = null,
    nowSec = Math.floor(Date.now() / 1000),
    readerPubkey = undefined,
  } = {}) {
    const activeReaderPubkey = readerPubkey !== undefined ? String(readerPubkey || '').toLowerCase() : this.readerPubkey
    const budget = Number.isSafeInteger(maxChars) && maxChars >= 1000 ? maxChars : DEFAULT_WAKE_MAX_CHARS
    const headerBudget = Math.min(550, Math.floor(budget * 0.10))
    const unverifiedSectionBudget = Math.min(350, Math.floor(budget * 0.07))
    const canonBudget = Math.floor(budget * 0.25)
    const opsBudget = Math.floor(budget * 0.45)
    const selfBudget = Math.max(200, budget - headerBudget - unverifiedSectionBudget - canonBudget - opsBudget - 16)

    const canonAccepted = []
    const opsAccepted = []
    const selfAccepted = []
    const unverifiedEntries = []
    const unverifiedCanonKeys = []

    const cleanRoom = roomId ? String(roomId).toLowerCase() : null

    for (const entry of this.entries.values()) {
      if (entry.status === 'withdrawn') continue
      if (entry.expiresAt != null && entry.expiresAt <= nowSec) continue
      if (entry.scopeType === 'room' && cleanRoom && entry.roomId !== cleanRoom) continue

      const verdict = this.evaluateClaim(entry, { nowSec, staleFiles, readerPubkey: activeReaderPubkey })
      if (verdict.verification === 'accepted') {
        if (verdict.computedRank === 2) canonAccepted.push({ entry, verdict })
        else if (verdict.computedRank === 3) opsAccepted.push({ entry, verdict })
        else if (verdict.computedRank === 4) selfAccepted.push({ entry, verdict })
      } else if (verdict.verification === 'unverified') {
        if (entry.scopeType === 'hive:canon') {
          unverifiedCanonKeys.push({ d: entry.d, reason: verdict.verificationReason })
        } else {
          unverifiedEntries.push({ entry, verdict })
        }
      }
    }

    // Detect conflicts by identical fact key (`d` tag) with different claim text.
    const factKeyClaims = new Map()
    for (const item of [...canonAccepted, ...opsAccepted]) {
      if (!factKeyClaims.has(item.entry.d)) factKeyClaims.set(item.entry.d, new Set())
      factKeyClaims.get(item.entry.d).add(item.entry.claim)
    }
    const isConflict = d => (factKeyClaims.get(d)?.size || 0) > 1

    const sortClaims = list => list.sort((a, b) => {
      const ac = isConflict(a.entry.d) ? 1 : 0
      const bc = isConflict(b.entry.d) ? 1 : 0
      if (ac !== bc) return bc - ac
      if (a.entry.createdAt !== b.entry.createdAt) return b.entry.createdAt - a.entry.createdAt
      return a.entry.event.id < b.entry.event.id ? -1 : 1
    })
    sortClaims(canonAccepted)
    sortClaims(opsAccepted)
    sortClaims(selfAccepted)

    const globalSync = this.memoryGlobalChannelId
      ? this.getChannelSync(this.memoryGlobalChannelId, nowSec)
      : { state: 'GLOBAL_CHANNEL_UNCONFIGURED', lastEoseAt: null }
    const roomSync = cleanRoom ? this.getChannelSync(cleanRoom, nowSec) : null

    const headerLines = [
      '=== HIVE WAKE DIGEST (authority: null, trustedInstruction: false) ===',
      `global_channel: ${globalSync.state} (last_eose_at: ${globalSync.lastEoseAt ?? 'never'})`,
      ...(roomSync ? [`room_channel (${cleanRoom}): ${roomSync.state} (last_eose_at: ${roomSync.lastEoseAt ?? 'never'})`] : []),
      `grants_checked_at: ${this.grantView.grantsCheckedAt ?? 'never'} | relays_answered: ${this.grantView.relaysAnswered}/${this.grantView.relaysTotal}` +
        (this.grantView.disagreeingRelays.length ? ` | disagreeing_relays: ${this.grantView.disagreeingRelays.join(', ')}` : ''),
      ...(gitBanner ? [`git_check: ${gitBanner}`] : []),
    ]
    const headerBlock = headerLines.join('\n').slice(0, headerBudget)

    const formatItem = ({ entry, verdict }) => {
      const conflictTag = isConflict(entry.d) ? '[CONFLICT] ' : ''
      const staleTag = verdict.staleWarning ? `${verdict.staleWarning} ` : ''
      return `- ${conflictTag}${staleTag}[${entry.d}] (by ${entry.pubkey.slice(0, 8)}, as_of ${entry.asOfGit || entry.asOfEvt}): ${entry.claim} — Because: ${entry.because} [evidence: ${(entry.evidence || []).join(', ')}]`
    }

    const fitSection = (title, items, sectionBudget, scopeHint, extraFooter = '') => {
      const reserve = 85 + (extraFooter ? extraFooter.length + 1 : 0)
      const lines = [`\n## ${title}`]
      let used = lines[0].length + 1
      let shown = 0
      for (const item of items) {
        const line = formatItem(item)
        if (used + line.length + 1 + reserve > sectionBudget && shown > 0) break
        if (used + line.length + 1 + reserve > sectionBudget && shown === 0) {
          lines.push(line.slice(0, Math.max(40, sectionBudget - used - reserve)))
          shown++
          break
        }
        lines.push(line)
        used += line.length + 1
        shown++
      }
      if (items.length === 0) lines.push('(none)')
      const omitted = items.length - shown
      if (omitted > 0) {
        lines.push(`+${omitted} ${scopeHint} claims not shown; memory_query scope=${scopeHint}`)
      }
      if (extraFooter) lines.push(extraFooter)
      return { text: lines.join('\n'), shown, omitted }
    }

    let canonFooter = ''
    if (unverifiedCanonKeys.length > 0) {
      const maxCanonFooter = Math.min(240, Math.floor(canonBudget * 0.25))
      const shownKeys = []
      let len = 0
      for (const k of unverifiedCanonKeys) {
        const token = `${k.d} [${k.reason}]`
        if (len + token.length + 2 > maxCanonFooter - 90 && shownKeys.length > 0) break
        shownKeys.push(token)
        len += token.length + 2
      }
      const more = unverifiedCanonKeys.length - shownKeys.length
      canonFooter = `(${unverifiedCanonKeys.length} unverified hive:canon claim(s) withheld from Rank 2: ${shownKeys.join(', ')}${more > 0 ? `, +${more} more` : ''})`
    }

    const canonSec = fitSection('Rank 2: hive:canon', canonAccepted, canonBudget, 'hive:canon', canonFooter)
    const opsSec = fitSection('Rank 3: room & hive:ops', opsAccepted, opsBudget, 'hive:ops')
    const selfSec = fitSection('Rank 4: self scratchpad', selfAccepted, selfBudget, `self:${activeReaderPubkey || 'keyless'}`)

    let unverifiedText = ''
    const totalUnverified = unverifiedEntries.length + unverifiedCanonKeys.length
    if (totalUnverified > 0) {
      const byReason = new Map()
      for (const u of unverifiedEntries) {
        const r = u.verdict.verificationReason || 'unverified'
        byReason.set(r, (byReason.get(r) || 0) + 1)
      }
      for (const c of unverifiedCanonKeys) {
        const r = c.reason || 'unverified'
        byReason.set(r, (byReason.get(r) || 0) + 1)
      }
      const summary = [...byReason.entries()].map(([r, c]) => `${c} (${r})`).join(', ')
      const rawUnverified = `\n## Unverified claims (not ranked)\n${totalUnverified} claim(s) held back: ${summary}`
      unverifiedText = rawUnverified.length <= unverifiedSectionBudget
        ? rawUnverified
        : `${rawUnverified.slice(0, unverifiedSectionBudget - 12)}... (+more)`
    }

    const fullDigest = [headerBlock, canonSec.text, opsSec.text, selfSec.text, unverifiedText]
      .filter(Boolean)
      .join('\n')

    const targetPath = wakeDigestPath ? resolve(wakeDigestPath) : null
    if (targetPath) {
      mkdirSync(dirname(targetPath), { recursive: true, mode: 0o700 })
      const tmp = `${targetPath}.${process.pid}.${Date.now()}.tmp`
      writeFileSync(tmp, fullDigest + '\n', { mode: 0o600 })
      renameSync(tmp, targetPath)
    }

    return {
      record_type: 'memory-wake-digest',
      authority: null,
      trustedInstruction: false,
      digest: fullDigest,
      char_length: fullDigest.length,
      max_chars: budget,
      global_sync: globalSync,
      room_sync: roomSync,
      grants_checked_at: this.grantView.grantsCheckedAt,
      relays_answered: `${this.grantView.relaysAnswered}/${this.grantView.relaysTotal}`,
      disagreeing_relays: this.grantView.disagreeingRelays,
      counts: {
        canon_shown: canonSec.shown,
        canon_omitted: canonSec.omitted,
        canon_unverified: unverifiedCanonKeys.length,
        ops_shown: opsSec.shown,
        ops_omitted: opsSec.omitted,
        self_shown: selfSec.shown,
        self_omitted: selfSec.omitted,
        unverified_total: totalUnverified,
      },
      records: [
        ...canonAccepted.slice(0, canonSec.shown),
        ...opsAccepted.slice(0, opsSec.shown),
        ...selfAccepted.slice(0, selfSec.shown),
      ].map(({ entry, verdict }) => ({
        ...toMemoryEnvelope(entry, verdict),
        conflict: isConflict(entry.d),
      })),
    }
  }
}

// MCP tool specifications for mounting Hive Shared Memory in any Nvoy MCP server.
export const MEMORY_TOOL_SPECS = Object.freeze([
  {
    name: 'memory_wake',
    description: 'Read the bounded Hive Wake Digest from the local broker state (zero network wait). All returned records carry authority: null and trustedInstruction: false.',
    inputSchema: {
      type: 'object',
      properties: {
        room_id: { type: 'string', pattern: UUID.source },
        max_chars: { type: 'integer', minimum: 1000, maximum: 24000 },
        git_banner: { type: 'string', maxLength: 500 },
        stale_files: { type: 'array', items: { type: 'string', maxLength: 300 }, maxItems: 200 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'memory_query',
    description: 'Search local broker memory claims by scope, room UUID, topic, fact key (d), or text substring. Never truncates silently; returns answer ("found", "none", or "unknown") and omitted count.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', maxLength: 120 },
        room_id: { type: 'string', pattern: UUID.source },
        topic: { type: 'string', maxLength: 128 },
        d: { type: 'string', maxLength: 256 },
        text: { type: 'string', maxLength: 256 },
        limit: { type: 'integer', minimum: 1, maximum: 200 },
        cursor: { type: 'string', maxLength: 32 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'memory_claim',
    description: 'Validate, secret-check, and prepare or ingest a structured Hive memory claim (kind 30079) requiring claim, because, evidence, and an as_of_git or as_of_evt anchor.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', minLength: 5, maxLength: 120 },
        slug: { type: 'string', pattern: SLUG.source },
        topic: { type: 'string', maxLength: 128 },
        claim: { type: 'string', minLength: 1, maxLength: 2000 },
        because: { type: 'string', minLength: 1, maxLength: 2000 },
        evidence: { type: 'array', items: { type: 'string', minLength: 1, maxLength: 300 }, minItems: 1, maxItems: 32 },
        as_of_git: { type: 'string', maxLength: 120 },
        as_of_evt: { type: 'string', pattern: HEX64.source },
        ttl_sec: { type: 'integer', minimum: 60, maximum: MAX_TTL_SEC },
        supersedes: { type: 'array', items: { type: 'string', maxLength: 300 }, maxItems: 16 },
      },
      required: ['scope', 'slug', 'claim', 'because', 'evidence'],
      additionalProperties: false,
    },
  },
  {
    name: 'memory_withdraw',
    description: 'Build a durable withdrawal replacement event (status: "withdrawn") with a strictly later created_at plus a NIP-09 deletion request.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', minLength: 5, maxLength: 120 },
        slug: { type: 'string', pattern: SLUG.source },
        because: { type: 'string', minLength: 1, maxLength: 2000 },
      },
      required: ['scope', 'slug', 'because'],
      additionalProperties: false,
    },
  },
])
