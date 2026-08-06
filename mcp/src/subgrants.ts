// subgrants.ts — the only supported re-delegation path.
//
// A sub-grant is NEVER a re-wrap of a parent key.  The sub-issuer authors a
// new encrypted scope under a new key, with an attenuated payload chosen from
// the material it was allowed to read.  This gives each leaf independent
// revocation and makes `redelegate` a concrete gate rather than an audit note.

import { finalizeEvent, generateSecretKey, getEventHash, nip44 } from 'nostr-tools'
import { boundOf, admitsAnother } from './redelegate-bound.js'
// @ts-ignore — vendored .mjs has no declarations
import { KIND_DATA_SET, KIND_GRANT, fetchScope, loadGrantIndex, newScopeKey, publishScope, saveGrantIndex, toIssuedEntry, type RelayLike } from '../lib/nipxx.mjs'
import type { Identity, Signer } from './identity.js'
import { grantStatus, type HeldGrant } from './grants.js'

const now = () => Math.floor(Date.now() / 1000)
const fuzz = () => now() - Math.floor(Math.random() * 2 * 24 * 60 * 60)
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))
const opaqueScopeId = () =>
  [...crypto.getRandomValues(new Uint8Array(12))].map(b => 'abcdefghijklmnopqrstuvwxyz234567'[b % 32]).join('')

export interface DerivedTerms {
  purpose: string
  expires_at?: number
  /** A child is a leaf by default.  A further hop needs an explicit true. */
  redelegate?: boolean
  no_persist?: boolean
  reply_scope_requested?: boolean
  auto_relinquish?: boolean
  contact?: string
}

export class RedelegationForbidden extends Error {
  constructor(message: string) { super(message); this.name = 'RedelegationForbidden' }
}

/** The sub-issuer's encrypted-to-self, relay-resident parent→child ledger.
 * It intentionally contains no parent scope key and, after a cascade, no usable child key.
 * Keeping this in the existing Grant Index gives restart recovery without an additional disk
 * registry or a new public linkage between delegator and leaf. */
interface DerivedChild {
  parent: { publisher: string; scope: string; generation: number }
  child: { scope: string; generation: number; grantee: string; scope_name: string }
  state: 'active' | 'revoked'
  issued_at: number
  revoked_at?: number
}

const lineage = (index: Record<string, unknown>): DerivedChild[] =>
  Array.isArray(index.nvoy_derived_children) ? index.nvoy_derived_children.filter((x): x is DerivedChild => {
    const v = x as DerivedChild
    return !!v && (v.state === 'active' || v.state === 'revoked') && /^[0-9a-f]{64}$/i.test(v.parent?.publisher || '') &&
      typeof v.parent?.scope === 'string' && Number.isInteger(v.parent?.generation) && typeof v.child?.scope === 'string' &&
      Number.isInteger(v.child?.generation) && /^[0-9a-f]{64}$/i.test(v.child?.grantee || '')
  }) : []

const saveLineage = async (relay: RelayLike, identity: Identity, index: Record<string, unknown>, rows: DerivedChild[]) => {
  index.nvoy_derived_children = rows.slice(-500)
  await saveGrantIndex(relay, identity.signer, index as { issued: unknown[]; received: unknown[] })
}

/** NIP-59 wrap through the signer's four primitive operations.  This is what
 * makes a Bunker-held identity a first-class sub-issuer: no local nsec or raw
 * key is needed. */
async function giftWrap(signer: Signer, recipient: string, rumor: Record<string, unknown>) {
  const withId = { ...rumor, id: getEventHash(rumor as any) }
  const seal = await signer.signEvent({
    kind: 13, created_at: fuzz(), tags: [],
    content: await signer.nip44Encrypt(recipient, JSON.stringify(withId)),
  })
  const ephemeral = generateSecretKey()
  return finalizeEvent({
    kind: 1059, created_at: fuzz(), tags: [['p', recipient]],
    content: nip44.v2.encrypt(JSON.stringify(seal), nip44.v2.utils.getConversationKey(ephemeral, recipient)),
  }, ephemeral)
}

function validate(parent: HeldGrant, terms: DerivedTerms) {
  // This function is also an exported boundary, not merely an implementation
  // detail behind the MCP handler.  Never rely on a caller's earlier status
  // check: expiry and local relinquishment must stop a direct caller before it
  // publishes even an attenuated child.
  if (grantStatus(parent) !== 'active')
    throw new RedelegationForbidden('the parent grant is not active')
  if (parent.terms?.redelegate !== true) throw new RedelegationForbidden('the parent grant does not permit re-delegation')
  // A derived scope is necessarily encrypted data stored on relays.  Turning
  // a no_persist parent into one would defeat the parent term at its source.
  if (parent.terms?.no_persist) throw new RedelegationForbidden('a no_persist parent grant cannot be re-delegated into a stored derived scope')
  if (!terms.purpose?.trim()) throw new RedelegationForbidden('a derived grant needs a purpose')
  const parentExpiry = parent.terms?.expires_at ?? parent.expiration
  if (parentExpiry !== undefined && (terms.expires_at === undefined || terms.expires_at > parentExpiry))
    throw new RedelegationForbidden('a derived grant must expire no later than its parent')
}

/** Create a new scope and wrap its *new* key to one leaf.  This exported
 * boundary re-checks both local status and the parent data-set immediately
 * before publishing, so callers cannot turn a cached/relinquished/rotated
 * parent into a child. */
export async function issueDerivedGrant(
  relay: RelayLike,
  identity: Identity,
  parent: HeldGrant,
  recipient: string,
  payload: Record<string, unknown>,
  scopeName: string,
  terms: DerivedTerms,
) {
  validate(parent, terms)

  // THE RE-DELEGATION BUDGET, CHECKED BEFORE ANYTHING IS PUBLISHED (#111).
  //
  // Ordering is the whole point: a budget checked after `publishScope` is decoration, because the child
  // scope is already on the relays and the data has already been spread. So the lineage is read here, and
  // the write below stays where it is — deliberately after publication, so a stored active row always
  // names a real leaf.
  //
  // This reads the index a second time rather than reusing the later load. That load is deliberately
  // FRESH so concurrent writers merge instead of clobbering, and moving it up here to save a round trip
  // would trade a correctness property for one request.
  const boundRead = boundOf(parent.terms)
  if (!boundRead.ok) throw new RedelegationForbidden(boundRead.why)
  {
    const idx = await loadGrantIndex(relay, identity.signer) as Record<string, unknown>
    const mine = lineage(idx).filter(r =>
      r.parent.publisher === parent.publisher && r.parent.scope === parent.scopeId)
    const room = admitsAnother(boundRead.bound, mine, recipient)
    if (!room.ok) throw new RedelegationForbidden(room.why)
  }

  const fresh = await fetchScope(relay, parent)
  if (fresh.status !== 'ok')
    throw new RedelegationForbidden('the parent grant is no longer freshly readable')
  if (!scopeName.startsWith('derived:')) throw new RedelegationForbidden("derived scope names must begin 'derived:'")
  const scopeId = opaqueScopeId()
  const scopeKey = newScopeKey()
  const childTerms = { ...terms, purpose: terms.purpose.trim(), redelegate: terms.redelegate === true }
  await publishScope(relay, identity.signer, { scopeId, generation: 1, scopeKey, payload })
  const pubkey = await identity.signer.getPublicKey()
  const rumor = {
    pubkey, kind: KIND_GRANT, created_at: now(),
    tags: [['a', `${KIND_DATA_SET}:${pubkey}:${scopeId}`], ['v', '1']],
    content: JSON.stringify({ scope_key: b64(scopeKey), scope_name: scopeName, nvoy: { nvoy: 1, ...childTerms } }),
  }
  const wrap = await giftWrap(identity.signer, recipient, rumor)
  await relay.publish(wrap)
  // Persist parent→child lineage in the sub-issuer's own encrypted Grant Index.  This is
  // deliberately after the child has been published: a stored active row always names a real
  // leaf. If this write fails we fail loudly rather than claiming a cascade-capable grant.
  const index = await loadGrantIndex(relay, identity.signer) as Record<string, unknown>
  const issued = Array.isArray(index.issued) ? index.issued : []
  issued.push(toIssuedEntry({ scopeId, scopeName, generation: 1, scopeKey }, [recipient]))
  index.issued = issued
  const rows = lineage(index)
  rows.push({ parent: { publisher: parent.publisher, scope: parent.scopeId, generation: parent.generation },
    child: { scope: scopeId, generation: 1, grantee: recipient, scope_name: scopeName }, state: 'active', issued_at: now() })
  await saveLineage(relay, identity, index, rows)
  // The live index has its own encrypted copy. Do not retain a second usable reference in this
  // one-shot helper.
  scopeKey.fill(0)
  return { scopeId, generation: 1, scopeName, parent: { publisher: parent.publisher, scopeId: parent.scopeId, generation: parent.generation } }
}

/**
 * Cascade an observed parent revocation through every locally issued descendant.  A new random
 * generation with an empty payload cryptographically severs a leaf's old key; the optional 441
 * tells a live leaf immediately.  The encrypted lineage row becomes a tombstone, so restarting
 * this runtime cannot forget the severance or resurrect a child key.
 */
export async function cascadeDerivedRevocation(
  relay: RelayLike,
  identity: Identity,
  revoked: Pick<HeldGrant, 'publisher' | 'scopeId' | 'generation'>,
): Promise<{ cascaded: number }> {
  const issuer = await identity.signer.getPublicKey()
  const index = await loadGrantIndex(relay, identity.signer) as Record<string, unknown>
  const rows = lineage(index)
  const issued = Array.isArray(index.issued) ? index.issued : []
  let cascaded = 0
  const revokeChildren = async (publisher: string, scope: string, generation: number): Promise<void> => {
    for (const row of rows.filter(r => r.state === 'active' && r.parent.publisher === publisher && r.parent.scope === scope && r.parent.generation <= generation)) {
      const entry = issued.find((e: any) => e?.scope === row.child.scope)
      // Missing issued material is already non-recoverable. Tombstone the lineage nevertheless
      // so a restart does not keep attempting a keyless cascade.
      if (entry) {
        const nextKey = newScopeKey(), nextGeneration = Number(entry.v || row.child.generation) + 1
        try {
          await publishScope(relay, identity.signer, { scopeId: row.child.scope, generation: nextGeneration, scopeKey: nextKey, payload: {} })
          const notice = { pubkey: issuer, kind: 441, created_at: now(),
            tags: [['a', `${KIND_DATA_SET}:${issuer}:${row.child.scope}`], ['v', String(row.child.generation)]],
            content: JSON.stringify({ reason: 'ancestor grant revoked' }) }
          await relay.publish(await giftWrap(identity.signer, row.child.grantee, notice))
        } finally { nextKey.fill(0) }
        const at = issued.indexOf(entry); if (at >= 0) issued.splice(at, 1)
      }
      row.state = 'revoked'; row.revoked_at = now(); cascaded++
      // A leaf allowed to re-delegate may have locally issued further descendants.  They are
      // tracked in this same encrypted index under this issuer's pubkey.
      await revokeChildren(issuer, row.child.scope, row.child.generation)
    }
  }
  await revokeChildren(revoked.publisher, revoked.scopeId, revoked.generation)
  if (cascaded) { index.issued = issued; await saveLineage(relay, identity, index, rows) }
  return { cascaded }
}
