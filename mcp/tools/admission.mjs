// admission.mjs — the pure rules that decide whether a message is work for an agent: the grant fold,
// the hop tag, NIP-40 expiry and who may task by DM. No node builtins and no I/O, so the hive manager
// page runs the same code the broker runs (waggle#613, docs/HIVE_MANAGER_SPEC.md C2). The fs-backed
// counters stay in agent_limits.mjs; invocation_policy.mjs and channel_task_carry.mjs build on this.

import { verifyEvent } from 'nostr-tools/pure'

export const TASK_CAPS = ['task', 'task+act', 'task-relay']
export const MEMORY_WRITE_CAP = 'memory-write'
export const HOP_TAG = 'nvoy-hop'
// The manifest's rule for a may_post.mention name (runtime_manifest.mjs), compared without case.
export const MENTION_NAME = /^[a-z0-9][a-z0-9._-]{0,31}$/i
const HEX64 = /^[0-9a-f]{64}$/

// null: no tag, so not broker-signed. A tag that is not one canonical non-negative integer is not
// something a broker wrote, and it counts as past every limit rather than as absent. The sentinel is
// finite on purpose: a carried admission crosses attention's JSON, where Infinity would become null.
export const MALFORMED_HOP = Number.MAX_SAFE_INTEGER
export function hopOf(ev) {
  const values = (Array.isArray(ev?.tags) ? ev.tags : []).filter(t => t?.[0] === HOP_TAG).map(t => t[1])
  if (!values.length) return null
  if (values.length !== 1 || !/^(0|[1-9][0-9]{0,5})$/.test(String(values[0]))) return MALFORMED_HOP
  return Number(values[0])
}
// A hop read back from JSON: absent is null, anything not a non-negative integer is malformed.
export const hopFromJson = value => value == null ? null : Number.isSafeInteger(value) && value >= 0 ? value : MALFORMED_HOP
export const nextHop = parentHop => (Number.isSafeInteger(parentHop) && parentHop >= 0 ? parentHop : 0) + 1
export const hopLimited = (hop, maxHops) => hop != null && hop >= maxHops

// NIP-40. A grant whose expiration has passed is treated exactly as a revoked one.
export function grantExpired(ev, nowSec = Math.floor(Date.now() / 1000)) {
  const tag = (Array.isArray(ev?.tags) ? ev.tags : []).find(t => t?.[0] === 'expiration')
  if (!tag) return false
  const at = Number(tag[1])
  // A malformed expiration cannot be honoured, and a grant that might have expired is not a grant.
  return !/^[0-9]{1,12}$/.test(String(tag[1])) || at <= nowSec
}

// Who may task this identity with a native message. In a channel: anyone holding a live task grant
// from a manifest grantor, as before. In a DM: the owner alone — the manifest's grantors, the same
// keys every grant descends from — and still on the owner's own live grant, so a revocation silences
// a DM exactly as it silences a channel. A grant held by anyone else, another agent included, is no
// way into a DM. James, 2026-10-21: "owner only I think - I don't want agents DM'ing each other".
export function nativeGrant({ author, dm, grants, grantors }) {
  if (dm && !grantors.includes(author)) return null
  const held = (Array.isArray(grants) ? grants : []).filter(g => g?.pubkey === author && grantors.includes(g.grantor))
  const grant = held.find(g => g.cap === 'task+act') || held.find(g => g.cap === 'task')
  return grant && HEX64.test(String(grant.grant_id || '')) ? grant : null
}

const tag = (ev, name) => (ev.tags || []).find(t => t[0] === name)

// foldGrants without node:crypto: the caller supplies scopeHash(subjectHex, saltHex), so a browser can
// fold with the same code the broker runs. grant_fold.mjs binds the node implementation.
export function foldGrantsWith(events, { me, grantors, scopeHash }) {
  const by = grantors.map(g => String(g).toLowerCase())
  const live = new Map(), voices = new Map(), ended = new Map(), named = new Map()
  let rejected = 0
  const drop = (id, why) => {
    for (const [pk, caps] of live) {
      for (const [cap, g] of caps) if (g.grantId === id) { caps.delete(cap); ended.set(pk, why) }
      if (!caps.size) live.delete(pk)
    }
    for (const [pk, s] of voices) if (s.grantId === id) { voices.delete(pk); ended.set(pk, why) }
    named.delete(id)
  }
  for (const ev of [...events].sort((a, b) => (a.created_at || 0) - (b.created_at || 0))) {
    const author = String(ev.pubkey || '').toLowerCase()
    if (!by.includes(author)) continue
    let ok = false; try { ok = verifyEvent(ev) } catch { ok = false }
    if (!ok) { rejected++; continue }
    if (ev.kind === 441) { const id = tag(ev, 'e')?.[1]; if (id) drop(id, 'revoked'); continue }
    if (ev.kind !== 440) continue
    const grantee = String(tag(ev, 'p')?.[1] || '').toLowerCase(), scope = tag(ev, 'da-scope'), cap = tag(ev, 'da-cap')?.[1]
    if (!grantee || !scope || !cap) continue
    if (cap === 'shadow') {
      if (scope[1] !== scopeHash(author, scope[2] || '') || grantee === author) continue
      voices.set(grantee, { grantId: ev.id, grantor: author })
    } else if (cap === 'mention') {
      const name = tag(ev, 'name')?.[1]
      if (!HEX64.test(grantee) || !MENTION_NAME.test(String(name ?? '')) || scope[1] !== scopeHash(me, scope[2] || '')) continue
      named.set(ev.id, { pubkey: grantee, name, grantId: ev.id, grantor: author, created_at: ev.created_at || 0 })
    } else {
      if (!TASK_CAPS.includes(cap) || scope[1] !== scopeHash(me, scope[2] || '')) continue
      if (!live.has(grantee)) live.set(grantee, new Map())
      live.get(grantee).set(cap, { grantId: ev.id, grantor: author, cap })
    }
    if (grantExpired(ev)) drop(ev.id, 'expired')
  }
  // Resolved after the fold, so a shadow older than its grantor's grant still sees it, and from the
  // grantors' own grants only, so a voice of a voice inherits nothing.
  const own = new Map([...live].map(([pk, caps]) => [pk, new Map(caps)]))
  for (const [voice, s] of voices) {
    for (const cap of (own.get(s.grantor) || new Map()).keys()) {
      if (!live.has(voice)) live.set(voice, new Map())
      if (!live.get(voice).has(cap)) live.get(voice).set(cap, { grantId: s.grantId, grantor: s.grantor, cap, shadow: true })
    }
  }
  for (const pk of live.keys()) ended.delete(pk)
  // Who this agent may mention, never who may task it: kept apart from `live`, and a voice inherits
  // none of it. Every live mention grant, in (created_at, id) order; agent_post.mjs merges them.
  const mentions = [...named.values()].sort((a, b) => a.created_at - b.created_at || (a.grantId < b.grantId ? -1 : 1))
  return { live, ended, rejected, mentions }
}

// Reader-independent grant fold for Hive Shared Memory (DESIGN_HIVE_MEMORY.md).
// Only `shadow` and `memory-write` grants count, both scoped to the GRANTOR's own key so every
// broker computes the exact same verdict regardless of its own identity (`me`).
// Task grants (`task`, `task+act`, `task-relay`) and `mention` grants are ignored completely:
// they neither grant memory write rights nor count as evidence when a memory grant is missing.
export function foldMemoryGrantsWith(events, { grantors, scopeHash, nowSec = Math.floor(Date.now() / 1000) }) {
  const by = (Array.isArray(grantors) ? grantors : []).map(g => String(g).toLowerCase())
  const activeById = new Map() // grantId -> { grantId, grantee, grantor, cap, created_at }
  const endedReasons = new Map() // grantee -> Set<'revoked' | 'expired'>
  let rejected = 0

  const markEnded = (grantee, why) => {
    if (!endedReasons.has(grantee)) endedReasons.set(grantee, new Set())
    endedReasons.get(grantee).add(why)
  }

  // First pass: collect all valid 440 memory-write / shadow grants from grantors.
  // Second pass: apply all valid 441 revocations and NIP-40 expirations.
  // Separating 440s and 441s guarantees same-second revocations and re-grants never depend on arrival order.
  const sorted = [...(Array.isArray(events) ? events : [])].sort((a, b) => {
    const dt = (a?.created_at || 0) - (b?.created_at || 0)
    if (dt !== 0) return dt
    return String(a?.id || '') < String(b?.id || '') ? -1 : String(a?.id || '') > String(b?.id || '') ? 1 : 0
  })

  const revocations = []
  for (const ev of sorted) {
    const author = String(ev?.pubkey || '').toLowerCase()
    if (!by.includes(author)) continue
    let ok = false; try { ok = verifyEvent(ev) } catch { ok = false }
    if (!ok) { rejected++; continue }
    if (ev.kind === 441) {
      revocations.push(ev)
      continue
    }
    if (ev.kind !== 440) continue
    const grantee = String(tag(ev, 'p')?.[1] || '').toLowerCase()
    const scope = tag(ev, 'da-scope')
    const cap = tag(ev, 'da-cap')?.[1]
    if (!HEX64.test(grantee) || !scope || !cap) continue
    if (cap !== 'shadow' && cap !== MEMORY_WRITE_CAP) continue
    // Both `shadow` and `memory-write` scope to the grantor's own key.
    if (scope[1] !== scopeHash(author, scope[2] || '') || (cap === 'shadow' && grantee === author)) continue
    if (grantExpired(ev, nowSec)) {
      markEnded(grantee, 'expired')
      continue
    }
    activeById.set(ev.id, { grantId: ev.id, grantee, grantor: author, cap, created_at: ev.created_at || 0 })
  }

  for (const rev of revocations) {
    const id = tag(rev, 'e')?.[1]
    const held = id ? activeById.get(id) : null
    if (held) {
      activeById.delete(id)
      markEnded(held.grantee, 'revoked')
    }
  }

  const writers = new Map() // grantee -> Map(cap -> { grantId, grantor, cap, created_at })
  for (const g of activeById.values()) {
    if (!writers.has(g.grantee)) writers.set(g.grantee, new Map())
    const caps = writers.get(g.grantee)
    const prev = caps.get(g.cap)
    if (!prev || g.created_at > prev.created_at || (g.created_at === prev.created_at && g.grantId > prev.grantId)) {
      caps.set(g.cap, { grantId: g.grantId, grantor: g.grantor, cap: g.cap, created_at: g.created_at })
    }
  }

  const ended = new Map()
  for (const [grantee, reasons] of endedReasons) {
    if (!writers.has(grantee)) ended.set(grantee, reasons.has('revoked') ? 'revoked' : 'expired')
  }
  return { writers, ended, rejected }
}
