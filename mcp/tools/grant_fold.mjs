// grant_fold.mjs — the one reading of kind 440/441 that the broker (attention.mjs), the wake watcher
// and the status page all apply, so who may task an agent cannot differ between the code that admits,
// the code that wakes and the page that shows it.
//
// Order is created_at; only verified events by a grantor count; a 441 drops the grant it names, and
// a NIP-40 expiry drops a grant exactly as a 441 would. A grant is kept per capability, so one key may
// hold `task` and the carrier-only `task-relay` side by side.
//
// A `shadow` grant makes a key a grantor's voice. It is a 440 by grantor G with `p` = the voice and a
// da-scope whose subject is G itself, so a grantor can shadow only its own key. On this broker the
// voice holds whatever live task grants G itself holds here, under the shadow's grant id: one 441
// against the shadow silences the voice on every broker, and G's own grants are untouched. A voice
// inherits only G's own grants, never another voice's, so shadows do not chain; and since only a
// grantor's events are read, nothing a voice signs is ever a grant. A voice is not a grantor: it stays
// under the hourly per-sender brake, and a Buzz DM still admits only the owner (nativeGrant).

import { createHash } from 'node:crypto'
import { verifyEvent } from 'nostr-tools/pure'
import { grantExpired } from './agent_limits.mjs'

export const TASK_CAPS = ['task', 'task+act', 'task-relay']

// The scope is a salted hash of the AGENT a grant is about (for a shadow, of the grantor itself), so
// a grant for one agent cannot be replayed against another and the agent id does not ride in clear.
export const scopeHash = (agentHex, saltHex) => createHash('sha256').update(Buffer.concat([
  Buffer.from('waggle/da-scope/v1'), Buffer.from([0]), Buffer.from(String(agentHex)), Buffer.from(saltHex || '', 'hex'),
])).digest('hex')

const tag = (ev, name) => (ev.tags || []).find(t => t[0] === name)

// Returns live: grantee -> Map(cap -> { grantId, grantor, cap, shadow? }), ended: grantee -> 'revoked' |
// 'expired' for a key whose every grant ended, and rejected: how many grantor events failed to verify.
export function foldGrants(events, { me, grantors }) {
  const by = grantors.map(g => String(g).toLowerCase())
  const live = new Map(), voices = new Map(), ended = new Map()
  let rejected = 0
  const drop = (id, why) => {
    for (const [pk, caps] of live) {
      for (const [cap, g] of caps) if (g.grantId === id) { caps.delete(cap); ended.set(pk, why) }
      if (!caps.size) live.delete(pk)
    }
    for (const [pk, s] of voices) if (s.grantId === id) { voices.delete(pk); ended.set(pk, why) }
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
  return { live, ended, rejected }
}
