// capgrants.mjs — the universal grant plane: every NIP-DA grant your key signed, from ANY app.
//
// Nvoy's own grants live in its private encrypted Grant Index (lib/nipxx.mjs loadGrantIndex) —
// bookkeeping only Nvoy writes. But Nvoy is meant to be the ONE place you see and administer every
// delegation you've made. Other apps in the NIP-DA family (waggle admits a key to a channel; more
// will come) publish their 440s as PLAIN PUBLIC events signed by your key. Nvoy never sees those
// through its own index.
//
// This module closes that gap the app-agnostic way: read every public kind-440/441 AUTHORED BY YOU
// off the relays, resolve revocations, and classify each by its tags — never by a per-app allowlist.
// A sixth app that ships tomorrow appears here automatically, as long as it signs a public 440.
//
// WHAT IT DELIBERATELY DOES NOT DO: it does not decrypt, it does not touch Nvoy's own scoped-data
// grants (those are wrapped, arrive through the index, and are skipped here so nothing double-counts),
// and it does not invent authority — it only reflects what your key has already signed in the open.

import { verifyEvent } from 'nostr-tools'

export const KIND = { grant: 440, revocation: 441 }

// Classify one 440 by its tags. The point is to be GENERIC: recognise the shapes we know, and give
// everything else an honest "unknown capability" row rather than dropping it. Dropping an unknown
// grant would make this plane lie by omission — the opposite of "show ALL".
export function classifyGrant(ev) {
  const tag = (k) => ev.tags.find(t => t[0] === k)
  const grantee = tag('p')?.[1] || null

  // Nvoy's OWN data/credential grant — an `a` tag pointing at a 30440 data set. These already reach
  // the console through the private index (and are normally 1059-wrapped, not public), so if one
  // surfaces here we mark it 'data' and let the caller skip it. No double-counting.
  const aTag = tag('a')
  if (aTag && /(^|:)30440:/.test(aTag[1] || '')) {
    return { type: 'data', grantee, label: 'Data delegation', cap: null, scopeHash: null }
  }

  // The waggle-family CAPABILITY shape: a da-cap (what) + da-scope (over what, salted-hashed so the
  // subject stays private). This is any app that grants a capability rather than delivering data.
  const capTag = tag('da-cap')
  if (capTag) {
    const cap = capTag[1] || 'grant'
    const scope = tag('da-scope')
    // Human labels for the caps we know; anything else renders as its raw cap, still legible.
    const LABELS = { admit: 'Channel admission', 'admit+read': 'Channel admission + read', task: 'Tasking authority', 'task+act': 'Tasking + act', 'task-relay': 'Task relay carrier' }
    return { type: 'capability', grantee, label: LABELS[cap] || `Capability: ${cap}`, cap, scopeHash: scope?.[1] || null }
  }

  // Anything else with a grantee is still a grant we should surface — we just don't have a bespoke
  // renderer for it. Honest "unknown" beats silent drop.
  if (grantee) return { type: 'other', grantee, label: 'Grant', cap: null, scopeHash: null }
  return null
}

// A capability grant, in the SAME row shape deriveDelegations() produces, so it renders on the one
// plane with everything else. `external: true` marks it as read-from-relays (not from Nvoy's index),
// which the revoke path keys on: an external grant is revoked by a plain 441, never a scope rotation.
function toRow(ev, cls, revokedIds) {
  return {
    scope: ev.id,                          // the 440 event id — the handle a 441 e-tags to revoke
    scopeName: cls.label,
    agent: cls.grantee,
    v: null,
    status: revokedIds.has(ev.id) ? 'revoked' : 'active',
    terms: null,
    purpose: cls.type === 'capability' && cls.cap ? cls.cap : null,
    grantedAt: ev.created_at,
    expiresAt: null,
    // extensions the ledger uses to render/administer external grants without touching Nvoy's own:
    external: true,
    app: cls.type,                         // 'capability' | 'other'
    capId: ev.id,
    scopeHash: cls.scopeHash,
  }
}

/**
 * Read every public grant YOUR key signed, classify, resolve revocations, return rows.
 *
 * @param relay        an object with query({kinds, authors, limit}) -> Promise<event[]>
 * @param delegatorPub your hex pubkey
 * @returns { rows, skippedData, unverified }  — rows are newest-first; counts are REPORTED, never
 *          swallowed, so "nothing here" can be told apart from "couldn't read" (the house rule).
 */
export async function readCapabilityGrants(relay, delegatorPub) {
  const events = await relay.query({ kinds: [KIND.grant, KIND.revocation], authors: [delegatorPub], limit: 1000 })
  const byId = new Map()
  let unverified = 0
  for (const ev of events || []) {
    if (ev.pubkey !== delegatorPub) continue          // authored by you, not merely mentioning you
    if (!verifyEvent(ev)) { unverified++; continue }   // a grant is only authority if its sig holds
    byId.set(ev.id, ev)
  }
  // Revocations: a 441 e-tagging a 440 you signed retires it. Only your own 441s count.
  const revokedIds = new Set()
  for (const ev of byId.values()) {
    if (ev.kind !== KIND.revocation) continue
    for (const t of ev.tags) if (t[0] === 'e' && t[1]) revokedIds.add(t[1])
  }
  const rows = []
  let skippedData = 0
  for (const ev of byId.values()) {
    if (ev.kind !== KIND.grant) continue
    const cls = classifyGrant(ev)
    if (!cls) continue
    if (cls.type === 'data') { skippedData++; continue }   // Nvoy's own — shown via the index already
    rows.push(toRow(ev, cls, revokedIds))
  }
  rows.sort((a, b) => (b.grantedAt ?? 0) - (a.grantedAt ?? 0))
  return { rows, skippedData, unverified }
}

/**
 * Build the 441 that revokes an external grant. A plain public revocation e-tagging the 440 — the
 * SAME mechanism every one of these apps' bridges already honours. Never a scope rotation (there is
 * no scope key to rotate; an external grant carries no data). Returns the unsigned template; the
 * caller signs it with the delegator's signer and publishes, exactly like Nvoy's own actions.
 */
export function buildExternalRevocation(capId, createdAt) {
  return { kind: KIND.revocation, created_at: createdAt, tags: [['e', capId]], content: '' }
}
