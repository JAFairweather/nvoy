// registry-actions.mjs — the registry panel's write actions, DOM-free so their failure paths can be tested.
//
// Every action here has an IRREVERSIBLE step (a signed event the relays now hold) followed by
// bookkeeping that can fail. The rule for all of them: once the irreversible step has happened, nothing
// that follows may be reported as "nothing changed", the in-memory index keeps the repair state, and the
// outcome says exactly what is live and what is not saved.
//
// Each returns { outcome, message, ... } and never throws for a failure after its irreversible step.

import { fetchScope } from '../lib/nipxx.mjs'
import { grantWithTerms, sendRevocationNotice } from './nvoygrant.mjs'
import { appendLedger, grantedEvent, revokedEvent } from './ledgerlog.mjs'
import { REGISTRY_PROJECTION_FIELD, REGISTRY_SCOPE, granteesOf } from './registry.mjs'
import { rotateProjection } from './registry-rotate.mjs'

const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0))
const issuedFor = (index, scopeId) => (index.issued ?? []).find(e => e?.scope === scopeId) ?? null

/**
 * Read the scope back with its recorded key and, only if it reads, record `verified: true`.
 * The flag is true in memory only while it is saved: if the save fails the flag goes back to false, so
 * the record stays RE-VERIFIABLE (planProjectionPublish plans 'reverify' for unverified + unchanged, and
 * 'none' for verified + unchanged — a verified flag that was never saved would disable the very retry
 * the operator is told to use).
 */
export async function confirmReadBack(ctx, { scopeId, generation, scopeKey }) {
  let back
  try { back = await fetchScope(ctx.relay, { publisher: ctx.me, scopeId, generation, scopeKey }) }
  catch (error) { return { readable: false, status: `error: ${error.message}`, saved: true } }
  if (back.status !== 'ok') return { readable: false, status: back.status, saved: true }
  const rec = ctx.index[REGISTRY_PROJECTION_FIELD]
  if (rec) rec.verified = true
  try { await ctx.save(); return { readable: true, status: 'ok', saved: true } }
  catch { if (rec) rec.verified = false; return { readable: true, status: 'ok', saved: false } }
}

/** Check read-back: signs nothing, rotates nothing, re-grants no one. */
export async function reverifyProjection(ctx, plan) {
  const issued = issuedFor(ctx.index, plan.scopeId)
  if (!issued?.key) return { outcome: 'refused', message: 'nothing changed: the projection key is not in your issued list.' }
  const r = await confirmReadBack(ctx, { scopeId: plan.scopeId, generation: plan.generation, scopeKey: unb64(issued.key) })
  if (!r.readable) {
    return { outcome: 'unreadable', message: `v${plan.generation} still does not read back (${r.status}). Nothing was signed; check again once the relay has it.` }
  }
  if (!r.saved) {
    return { outcome: 'verified-unsaved', message: `v${plan.generation} reads back, but the Grant Index could not be saved, so it is NOT recorded as verified. `
      + 'Nothing was signed; check read-back again to retry the save.' }
  }
  return { outcome: 'verified', message: `v${plan.generation} reads back — verified. Nothing was signed.` }
}

/** Grant read at the CURRENT generation and key (same value, no rotation). */
export async function grantRead(ctx, pub, scopeId) {
  const issued = issuedFor(ctx.index, scopeId)
  if (!issued) return { outcome: 'refused', message: 'nothing changed: the projection scope is not in your issued list, so its key cannot be recovered.' }
  const terms = ctx.terms()
  try {
    await grantWithTerms(ctx.relay, ctx.signer, pub, {
      scopeId: issued.scope, generation: issued.v, scopeKey: unb64(issued.key), scopeName: REGISTRY_SCOPE,
      relayHint: ctx.relayHint, terms,
    })
  } catch (error) {
    return { outcome: 'failed', message: `nothing changed: ${error.message}` }
  }
  // The gift wrap is out: the runtime holds the grant whether or not our bookkeeping survives.
  issued.grantees = [...granteesOf(issued), pub]
  ctx.index.nvoy_ledger = appendLedger(ctx.index, grantedEvent({
    scope: issued.scope, agent: pub, v: issued.v, terms: { nvoy: 1, ...terms }, name: REGISTRY_SCOPE,
  }))
  try { await ctx.save() } catch (error) {
    return { outcome: 'granted-unsaved', saved: false, message: `${ctx.name(pub)} was granted read (v${issued.v}) — the grant is out — but the Grant Index could not be saved `
      + `(${error.message}). Keep this page open and retry; do not grant again.` }
  }
  return { outcome: 'granted', saved: true, message: `${ctx.name(pub)} can now read v${issued.v}.` }
}

/** Revoke a holder: rotate past them, re-grant the rest, courtesy notice last. */
export async function revokeRead(ctx, pub, scopeId, payload) {
  const issued = issuedFor(ctx.index, scopeId)
  if (!issued) return { outcome: 'refused', message: 'nothing changed: the projection scope is not in your issued list.' }
  const survivors = granteesOf(issued).filter(p => p !== pub)
  let rot
  try {
    rot = await rotateProjection({
      relay: ctx.relay, signer: ctx.signer, index: ctx.index, scopeId: issued.scope, scopeName: REGISTRY_SCOPE,
      from: Number(issued.v), payload, relayHint: ctx.relayHint, now: ctx.now,
      survivors: survivors.map(p => ({ pub: p, terms: ctx.terms() })), save: ctx.save,
    })
  } catch (error) {
    return { outcome: 'failed', message: `nothing changed: ${error.message}` }       // nothing was published
  }
  let noticed = false
  try {
    await sendRevocationNotice(ctx.relay, ctx.signer, pub, { scopeId: issued.scope, reason: 'the registry projection read was revoked' })
    noticed = true
  } catch { /* a courtesy: the revocation itself is the rotation and is already recorded */ }
  ctx.index.nvoy_ledger = appendLedger(ctx.index, revokedEvent({
    scope: issued.scope, agent: pub, v: rot.generation, reason: 'the registry projection read was revoked', notice: noticed ? true : null,
  }))
  let persisted = rot.saved
  try { await ctx.save(); persisted = true } catch { persisted = false }
  const head = rot.status === 'partial'
    ? `${ctx.name(pub)} is revoked (v${rot.generation}), but only ${rot.regranted.length} of ${survivors.length} remaining holder(s) were re-delivered `
      + `(${rot.reason}). Still waiting: ${rot.pending.map(ctx.name).join(', ')} — use Grant read.`
    : `${ctx.name(pub)} is revoked (v${rot.generation}).` + (noticed ? '' : ' The courtesy notice could not be sent; the revocation stands.')
  return {
    outcome: rot.status === 'partial' ? 'revoked-partial' : 'revoked', saved: persisted, rotation: rot,
    message: head + ' The new generation is unverified — press Check read-back.'
      + (persisted ? '' : ` WARNING: v${rot.generation} is live but the Grant Index could not be saved — keep this page open and retry.`),
  }
}
