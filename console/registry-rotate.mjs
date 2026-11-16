// registry-rotate.mjs — rotating the registry projection's key without stranding it (nvoy#363).
//
// DOM-free, so the failure paths are testable. A rotation is publish-then-grant: the moment the new
// 30440 lands it REPLACES the old generation on the relay, and the new scope key exists only in memory.
// Everything fallible after that point — a survivor's grant, an optional revocation notice, saving the
// Grant Index itself — used to be able to throw before the key was recorded, leaving a published
// generation nobody (including the operator) could read, reported as "nothing changed".
//
// The order here is: publish → RECORD the key and generation → grant survivors → record who actually
// got it. A failure part-way is reported as partial, with who is still waiting, and the ones waiting
// are left re-grantable through the ordinary "Grant read" (same key, same generation).

import { rotateWithTerms } from './nvoygrant.mjs'
import { REGISTRY_PROJECTION_FIELD } from './registry.mjs'

const b64 = (bytes) => btoa(String.fromCharCode(...bytes))

/**
 * Write the new generation and key into the index in place. `holders` are the runtimes KNOWN to hold
 * this generation. `verified` is set only when given; rotateProjection always gives it (false), because
 * no rotation has been read back at the moment it is recorded — a stale `true` from the previous
 * generation would claim readability nobody has checked.
 */
export function recordRotation(index, { scopeId, scopeName, generation, scopeKey, holders, payload, at, verified }) {
  const entry = { scope: scopeId, scope_name: scopeName, v: generation, key: b64(scopeKey), grantees: [...holders] }
  const issued = Array.isArray(index.issued) ? index.issued : []
  index.issued = [...issued.filter(e => e?.scope !== scopeId), entry]
  const rec = index[REGISTRY_PROJECTION_FIELD]
  index[REGISTRY_PROJECTION_FIELD] = {
    ...(rec || {}), scopeId, scopeName, generation, at, payload,
    ...(verified === undefined ? {} : { verified }),
  }
}

/**
 * Rotate and record. Resolves { status: 'complete' | 'partial', generation, scopeKey, regranted, pending }.
 * Throws only when NOTHING was published (the old generation is still live and the index untouched);
 * once the new generation is out, failures are reported as 'partial', never thrown away.
 *
 * `save` persists the index; it is awaited BEFORE any grant so the key survives a grant failure, and
 * tried again at the end so a transient save failure on the first try is not the last word.
 */
export async function rotateProjection({ relay, signer, index, scopeId, scopeName, from, payload, survivors, relayHint = '', save, now, verified = false }) {
  const keep = (rotation, holders) => recordRotation(index, {
    scopeId, scopeName, generation: rotation.generation, scopeKey: rotation.scopeKey, holders, payload, at: now(), verified,
  })
  try {
    const out = await rotateWithTerms(relay, signer, {
      scopeId, generation: from, payload, scopeName, survivors, relayHint,
      onPublished: async (r) => { keep(r, []); await save() },
    })
    keep(out, survivors.map(s => s.pub))
    // The rotation is complete and out. A failing final save is a PERSISTENCE problem, not a failed
    // rotation: it must not surface as an error ("nothing changed") for a generation that is live. The
    // key was already saved before the first grant, so this only records who holds it.
    let saved = true
    try { await save() } catch { saved = false }
    return { status: 'complete', generation: out.generation, scopeKey: out.scopeKey, regranted: survivors.map(s => s.pub), pending: [], saved }
  } catch (error) {
    const r = error.rotation
    if (!r) throw error                      // nothing was published: the old generation stands
    keep(r, r.regranted)
    let saved = true
    try { await save() } catch { saved = false }
    return {
      status: 'partial', generation: r.generation, scopeKey: r.scopeKey, regranted: r.regranted, pending: r.pending,
      saved, reason: error.message,
    }
  }
}
