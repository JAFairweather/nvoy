// nvoygrant.mjs — the delegator-side helper Nvoy adds on top of the frozen
// protocol lib: issue a 440 grant whose content carries an nvoy terms object
// (spec §4) alongside the standard scope_key/scope_name fields.
//
// The vendored lib's grant() builds its content from scope_key/scope_name
// only, so this mirrors its rumor exactly and adds the terms, gift-wrapping
// via nostr-tools nip59 (same NIP-59 construction the lib uses internally).
// A vanilla NIP-DA client ignores the extra key entirely.

import { getPublicKey } from 'nostr-tools'
import { wrapEvent } from 'nostr-tools/nip59'
import { KIND_DATA_SET, KIND_GRANT } from '../lib/nipxx.mjs'

const b64 = (bytes) => btoa(String.fromCharCode(...bytes))

/**
 * Issue a grant with nvoy terms. `terms` per spec §4:
 * { nvoy: 1, purpose, expires_at, no_persist, redelegate,
 *   reply_scope_requested, contact, auto_relinquish }
 * Omit `terms` for a vanilla grant.
 */
export async function grantWithTerms(relay, delegatorSecret, granteePubkey,
                                     { scopeId, generation, scopeKey, scopeName, relayHint = '', terms }) {
  const pub = getPublicKey(delegatorSecret)
  const content = { scope_key: b64(scopeKey), scope_name: scopeName }
  if (terms) content.nvoy = { nvoy: 1, ...terms }
  const rumor = {
    pubkey: pub,
    kind: KIND_GRANT,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['a', `${KIND_DATA_SET}:${pub}:${scopeId}`, relayHint],
      ['v', String(generation)],
    ],
    content: JSON.stringify(content),
  }
  const wrap = wrapEvent(rumor, delegatorSecret, granteePubkey)
  const receipt = await relay.publish(wrap)
  return { wrap, ...receipt }
}

// Demo payload only — never real personal data in tests.
export const TRAVEL_PREFERENCES = {
  name: 'Travel preferences',
  fields: {
    seat: 'aisle',
    airlines: ['Air Canada', 'United'],
    hotel_brands: ['Marriott', 'Hilton'],
    budget_per_night_usd: 250,
    home_airport: 'YYZ',
    loyalty: [{ program: 'Aeroplan', number: 'DEMO-000000' }],
    dietary: 'vegetarian',
    note: 'Prefers morning departures; no red-eyes.',
  },
}

/** Opaque scope id — semantic names in `d` tags leak disclosure structure. */
export const opaqueScopeId = () =>
  [...crypto.getRandomValues(new Uint8Array(6))].map(b => 'abcdefghijklmnopqrstuvwxyz234567'[b % 32]).join('')
