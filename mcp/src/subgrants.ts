// subgrants.ts — the only supported re-delegation path.
//
// A sub-grant is NEVER a re-wrap of a parent key.  The sub-issuer authors a
// new encrypted scope under a new key, with an attenuated payload chosen from
// the material it was allowed to read.  This gives each leaf independent
// revocation and makes `redelegate` a concrete gate rather than an audit note.

import { finalizeEvent, generateSecretKey, getEventHash, nip44 } from 'nostr-tools'
// @ts-ignore — vendored .mjs has no declarations
import { KIND_DATA_SET, KIND_GRANT, newScopeKey, publishScope, type RelayLike } from '../lib/nipxx.mjs'
import type { Identity, Signer } from './identity.js'
import type { HeldGrant } from './grants.js'

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
  if (parent.terms?.redelegate !== true) throw new RedelegationForbidden('the parent grant does not permit re-delegation')
  // A derived scope is necessarily encrypted data stored on relays.  Turning
  // a no_persist parent into one would defeat the parent term at its source.
  if (parent.terms?.no_persist) throw new RedelegationForbidden('a no_persist parent grant cannot be re-delegated into a stored derived scope')
  if (!terms.purpose?.trim()) throw new RedelegationForbidden('a derived grant needs a purpose')
  const parentExpiry = parent.terms?.expires_at ?? parent.expiration
  if (parentExpiry !== undefined && (terms.expires_at === undefined || terms.expires_at > parentExpiry))
    throw new RedelegationForbidden('a derived grant must expire no later than its parent')
}

/** Create a new scope and wrap its *new* key to one leaf.  The caller must
 * fresh-read the parent immediately beforehand; this routine deliberately
 * receives the HeldGrant only for terms/expiry enforcement, never its key. */
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
  // The sub-issuer has its own key. Do not retain it in this one-shot helper;
  // durable lineage/sweep state is deliberately a separate runtime concern.
  scopeKey.fill(0)
  return { scopeId, generation: 1, scopeName, parent: { publisher: parent.publisher, scopeId: parent.scopeId, generation: parent.generation } }
}
