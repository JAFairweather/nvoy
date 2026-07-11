// vendored from JAFairweather/nostr-scoped-data-grants @ 681a462 — do not edit; npm run sync-lib
// nipxx.mjs — Permissioned Private Data Sharing (Scoped Data Grants)
// Reference implementation. No dependencies beyond nostr-tools.
//
// Event kinds (placeholders pending assignment):
//   30440  Scoped Data Set   (addressable; content symmetrically encrypted under a scope key)
//     440  Data Grant        (unsigned rumor, delivered via NIP-59 gift wrap)
//   10440  Grant Index       (replaceable; NIP-44 encrypted to self)
//
// Every flow takes a `relay`: any object with publish(event) and query(filter).
// Sync or async both satisfy it — `await` passes plain values through — so the
// in-memory relay (relay.mjs) and the SimplePool adapter (liverelay.mjs) drive
// this single implementation of the wire format.

import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, nip44, verifyEvent } from 'nostr-tools'

export const KIND_DATA_SET = 30440
export const KIND_GRANT = 440
export const KIND_GRANT_INDEX = 10440

// ---------------------------------------------------------------- scope keys

// Web-platform primitives only (crypto, btoa/atob) — this file runs
// unchanged in Node ≥ 20 and in the browser.

// ------------------------------------------------------------------ signers
//
// Every keyholder parameter accepts either a raw 32-byte secret key or a
// *signer*: { getPublicKey(), signEvent(event), nip44Encrypt(pub, pt),
// nip44Decrypt(pub, ct) } — all async. A NIP-07 browser extension maps onto
// this interface directly, so clients never need the raw key in-page.

export function localSigner(sk) {
  const pub = getPublicKey(sk)
  const conv = (pk) => nip44.v2.utils.getConversationKey(sk, pk)
  return {
    getPublicKey: async () => pub,
    signEvent: async (event) => finalizeEvent(event, sk),
    nip44Encrypt: async (pk, plaintext) => nip44.v2.encrypt(plaintext, conv(pk)),
    nip44Decrypt: async (pk, ciphertext) => nip44.v2.decrypt(ciphertext, conv(pk)),
  }
}

const asSigner = (s) => s instanceof Uint8Array ? localSigner(s) : s

// NIP-59, from signer primitives (nostr-tools' nip59 needs the raw key).
// Timestamps are fuzzed up to two days into the past, per the NIP.
const fuzz = () => now() - Math.floor(Math.random() * 2 * 24 * 60 * 60)

async function giftWrap(signer, recipientPub, rumor) {
  rumor.id = getEventHash(rumor)
  const seal = await signer.signEvent({
    kind: 13, created_at: fuzz(), tags: [],
    content: await signer.nip44Encrypt(recipientPub, JSON.stringify(rumor)),
  })
  const ephemeral = generateSecretKey()
  return finalizeEvent({
    kind: 1059, created_at: fuzz(), tags: [['p', recipientPub]],
    content: nip44.v2.encrypt(JSON.stringify(seal),
      nip44.v2.utils.getConversationKey(ephemeral, recipientPub)),
  }, ephemeral)
}

async function giftUnwrap(signer, wrap) {
  const seal = JSON.parse(await signer.nip44Decrypt(wrap.pubkey, wrap.content))
  if (seal.kind !== 13 || !verifyEvent(seal)) throw new Error('bad seal')
  const rumor = JSON.parse(await signer.nip44Decrypt(seal.pubkey, seal.content))
  if (rumor.pubkey !== seal.pubkey) throw new Error('seal/rumor pubkey mismatch')
  return rumor
}

/** A scope key is a random 32-byte symmetric key. */
export const newScopeKey = () => crypto.getRandomValues(new Uint8Array(32))

const b64 = (bytes) => btoa(String.fromCharCode(...bytes))
const unb64 = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0))

// NIP-44 v2 payload format, with the raw scope key used directly as the
// conversation key (no ECDH step). Reuses NIP-44's authenticated encryption,
// versioning, and — importantly for relay-visible size — its padding scheme.
const symEncrypt = (obj, scopeKey) => nip44.v2.encrypt(JSON.stringify(obj), scopeKey)
const symDecrypt = (ciphertext, scopeKey) => JSON.parse(nip44.v2.decrypt(ciphertext, scopeKey))

// ---------------------------------------------------------------- publisher

/**
 * Publish (or replace) a Scoped Data Set.
 * `scopeId` should be opaque — semantic names in `d` tags leak disclosure
 * structure to relays. The human-readable name lives inside the ciphertext.
 * Returns the signed event plus whatever receipt the relay's publish
 * produces (e.g. ack counts from LiveRelay).
 */
export async function publishScope(relay, publisherSecret, { scopeId, generation, scopeKey, payload }) {
  const ts = now()
  const event = await asSigner(publisherSecret).signEvent({
    kind: KIND_DATA_SET,
    created_at: ts,
    tags: [['d', scopeId], ['v', String(generation)]],
    content: symEncrypt({ ...payload, updated_at: ts }, scopeKey),
  })
  const receipt = await relay.publish(event)
  return { event, ...receipt }
}

/**
 * Issue a Data Grant: deliver a scope key to a grantee.
 * The grant is an unsigned rumor, sealed and gift-wrapped per NIP-59 — the
 * relay sees only an ephemeral pubkey delivering an opaque blob to the
 * grantee. The grant graph is precisely what this protocol protects.
 */
export async function grant(relay, publisherSecret, granteePubkey,
                            { scopeId, generation, scopeKey, scopeName, relayHint = '' }) {
  const signer = asSigner(publisherSecret)
  const publisherPub = await signer.getPublicKey()
  const rumor = {
    pubkey: publisherPub,
    kind: KIND_GRANT,
    created_at: now(),
    tags: [
      ['a', `${KIND_DATA_SET}:${publisherPub}:${scopeId}`, relayHint],
      ['v', String(generation)],
    ],
    content: JSON.stringify({ scope_key: b64(scopeKey), scope_name: scopeName }),
  }
  const wrap = await giftWrap(signer, granteePubkey, rumor)
  const receipt = await relay.publish(wrap)
  return { wrap, ...receipt }
}

/**
 * Revoke a grantee from a scope: rotate the key, republish the data under the
 * new key, and re-grant only the survivors. The revoked party keeps whatever
 * plaintext they already decrypted (unavoidable, and honest to say so) but is
 * cut off from all future updates.
 */
export async function rotateScope(relay, publisherSecret,
                                  { scopeId, generation, payload, scopeName, survivors }) {
  const scopeKey = newScopeKey()
  const next = generation + 1
  await publishScope(relay, publisherSecret, { scopeId, generation: next, scopeKey, payload })
  for (const pubkey of survivors)
    await grant(relay, publisherSecret, pubkey, { scopeId, generation: next, scopeKey, scopeName })
  return { scopeKey, generation: next }
}

/**
 * Delete a scope. On NIP-01 relays, replacement is destruction: the
 * tombstone (empty payload, fresh key granted to no one, bumped generation)
 * removes the previous ciphertext from every conforming relay. The NIP-09
 * kind-5 then asks relays to drop the tombstone too (advisory). Grantees see
 * generation supersession — indistinguishable from revocation, deliberately.
 */
export async function deleteScope(relay, publisherSecret, { scopeId, generation }) {
  const signer = asSigner(publisherSecret)
  await publishScope(relay, signer, {
    scopeId, generation: generation + 1, scopeKey: newScopeKey(), payload: {},
  })
  const event = await signer.signEvent({
    kind: 5,
    created_at: now(),
    tags: [
      ['a', `${KIND_DATA_SET}:${await signer.getPublicKey()}:${scopeId}`],
      ['k', String(KIND_DATA_SET)],
    ],
    content: '',
  })
  const receipt = await relay.publish(event)
  return { event, ...receipt }
}

// ---------------------------------------------------------------- grantee

/** Collect and unwrap all grants addressed to this keyholder. */
export async function receiveGrants(relay, granteeSecret) {
  const signer = asSigner(granteeSecret)
  const granteePub = await signer.getPublicKey()
  const wraps = await relay.query({ kinds: [1059], '#p': [granteePub] })
  const grants = []
  for (const wrap of wraps) {
    let rumor
    try { rumor = await giftUnwrap(signer, wrap) } catch { continue }
    if (rumor.kind !== KIND_GRANT) continue
    const [, address, relayHint] = rumor.tags.find(t => t[0] === 'a')
    const [kind, publisher, scopeId] = address.split(':')
    const { scope_key, scope_name } = JSON.parse(rumor.content)
    grants.push({
      publisher, scopeId, scopeName: scope_name, relayHint,
      generation: Number(rumor.tags.find(t => t[0] === 'v')?.[1] ?? 0),
      scopeKey: unb64(scope_key),
      issuedAt: rumor.created_at,
    })
  }
  return grants
}

/** Keep only the newest grant per (publisher, scope) — key rotations supersede. */
export function latestGrants(grants) {
  const best = new Map()
  for (const g of grants) {
    const k = `${g.publisher}:${g.scopeId}`
    if (!best.has(k) || g.generation > best.get(k).generation) best.set(k, g)
  }
  return [...best.values()]
}

/**
 * Dereference a grant: fetch the current Scoped Data Set and decrypt it.
 * This is what makes the address book *live* — the grantee always reads the
 * publisher's authoritative current event, never a snapshot.
 * Returns { status: 'ok', data } or { status: 'stale' } if the scope key has
 * been rotated past this grant (i.e. access to future updates was revoked).
 */
export async function fetchScope(relay, grantRecord) {
  const [event] = await relay.query({
    kinds: [KIND_DATA_SET], authors: [grantRecord.publisher], '#d': [grantRecord.scopeId],
  })
  if (!event) return { status: 'missing' }
  const generation = Number(event.tags.find(t => t[0] === 'v')?.[1] ?? 0)
  if (generation > grantRecord.generation) return { status: 'stale', generation }
  try {
    return { status: 'ok', generation, data: symDecrypt(event.content, grantRecord.scopeKey) }
  } catch {
    return { status: 'stale', generation } // MAC failure — wrong (rotated) key
  }
}

/**
 * A grantee's whole address book: unwrap grants, keep the newest per scope,
 * dereference each. Three lines — this IS the client.
 */
export async function addressBook(relay, granteeSecret) {
  const grants = latestGrants(await receiveGrants(relay, granteeSecret))
  return Promise.all(grants.map(async g => ({ ...g, ...await fetchScope(relay, g) })))
}

// ---------------------------------------------------------- grant index

// NIP-44 to self: conversation key derived from one's own keypair, as in
// NIP-51 private items. The index carries all key material and must never
// exist unencrypted on a relay.

/**
 * Load the user's Grant Index. `issued` is the publisher's authoritative
 * record (everything a rotation needs); `received` is the grantee's private
 * address book — both recoverable from the nsec alone.
 */
export async function loadGrantIndex(relay, secret) {
  const signer = asSigner(secret)
  const pub = await signer.getPublicKey()
  const [event] = await relay.query({ kinds: [KIND_GRANT_INDEX], authors: [pub] })
  return event
    ? JSON.parse(await signer.nip44Decrypt(pub, event.content))
    : { issued: [], received: [] }
}

/** Encrypt and (re)publish the Grant Index. Replaceable — newest wins. */
export async function saveGrantIndex(relay, secret, index) {
  const signer = asSigner(secret)
  const event = await signer.signEvent({
    kind: KIND_GRANT_INDEX,
    created_at: now(),
    tags: [],
    content: await signer.nip44Encrypt(await signer.getPublicKey(), JSON.stringify(index)),
  })
  const receipt = await relay.publish(event)
  return { event, ...receipt }
}

// Index entries use the spec's wire field names; these adapters convert to
// and from the in-memory grant/scope records the rest of the lib speaks.
export const toReceivedEntry = (g, petname, relays = []) => ({
  a: `${KIND_DATA_SET}:${g.publisher}:${g.scopeId}`, v: g.generation,
  key: b64(g.scopeKey), petname, relays,
})
export const fromReceivedEntry = (e) => {
  const [, publisher, scopeId] = e.a.split(':')
  return { publisher, scopeId, generation: e.v, scopeKey: unb64(e.key), petname: e.petname }
}
export const toIssuedEntry = ({ scopeId, scopeName, generation, scopeKey }, grantees) => ({
  scope: scopeId, scope_name: scopeName, v: generation, key: b64(scopeKey), grantees,
})
export const fromIssuedEntry = (e) => ({
  scopeId: e.scope, scopeName: e.scope_name, generation: e.v,
  scopeKey: unb64(e.key), grantees: e.grantees,
})

// Monotonic: two publishes of the same replaceable/addressable event within
// one second would otherwise tie on created_at and lose NIP-01 replacement
// ("replaced: have newer event"). Strictly increasing timestamps fix the
// class; the ≤1s future drift under rapid publishing is harmless.
let lastTs = 0
const now = () => (lastTs = Math.max(Math.floor(Date.now() / 1000), lastTs + 1))
