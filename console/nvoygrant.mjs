// nvoygrant.mjs (console) — the delegator-side protocol helpers, signer-based.
//
// This is the browser port of test/nvoygrant.mjs: same wire shape exactly
// (grant content = { scope_key, scope_name, nvoy: { nvoy: 1, ...terms } },
// the nested carrier mcp/src/terms.ts parses), but built on the lib's signer
// interface instead of a raw secret key, so a NIP-07 extension can issue
// grants without the nsec ever entering the page. The gift wrap mirrors the
// vendored lib's internal giftWrap byte-for-byte in construction: kind-13
// seal signed by the delegator, kind-1059 wrap under an ephemeral key,
// timestamps fuzzed up to two days into the past per NIP-59.
//
// DOM-free on purpose — test/ledger.mjs drives this exact module in Node
// and cross-checks it against the compiled MCP server modules.

import { finalizeEvent, generateSecretKey, getEventHash, nip44 } from 'nostr-tools'
import { KIND_DATA_SET, KIND_GRANT, newScopeKey, publishScope, localSigner } from '../lib/nipxx.mjs'

/** Grant Revocation notice — placeholder pending assignment, like its siblings. */
export const KIND_REVOCATION = 441

const b64 = (bytes) => btoa(String.fromCharCode(...bytes))
const now = () => Math.floor(Date.now() / 1000)
const fuzz = () => now() - Math.floor(Math.random() * 2 * 24 * 60 * 60)
const asSigner = (s) => s instanceof Uint8Array ? localSigner(s) : s

/** NIP-59 gift wrap from signer primitives (mirrors lib/nipxx.mjs giftWrap). */
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

/**
 * Issue a grant carrying nvoy terms (spec §4). `terms` fields: purpose,
 * expires_at, no_persist, redelegate, reply_scope_requested, contact,
 * auto_relinquish. Omit `terms` for a vanilla NIP-DA grant — vanilla
 * clients ignore the extra key either way.
 */
export async function grantWithTerms(relay, delegator, granteePubkey,
                                     { scopeId, generation, scopeKey, scopeName, relayHint = '', terms }) {
  const signer = asSigner(delegator)
  const pub = await signer.getPublicKey()
  const content = { scope_key: b64(scopeKey), scope_name: scopeName }
  if (terms) content.nvoy = { nvoy: 1, ...terms }
  const rumor = {
    pubkey: pub,
    kind: KIND_GRANT,
    created_at: now(),
    tags: [
      ['a', `${KIND_DATA_SET}:${pub}:${scopeId}`, relayHint],
      ['v', String(generation)],
    ],
    content: JSON.stringify(content),
  }
  const wrap = await giftWrap(signer, granteePubkey, rumor)
  const receipt = await relay.publish(wrap)
  return { wrap, ...receipt }
}

/**
 * Send a kind-441 revocation notice (optional courtesy), gift-wrapped to the
 * revoked party. Silent revocation is a delegator's right — simply never
 * call this.
 */
export async function sendRevocationNotice(relay, delegator, granteePubkey, { scopeId, reason }) {
  const signer = asSigner(delegator)
  const pub = await signer.getPublicKey()
  const rumor = {
    pubkey: pub,
    kind: KIND_REVOCATION,
    created_at: now(),
    tags: [['a', `${KIND_DATA_SET}:${pub}:${scopeId}`]],
    content: reason ? JSON.stringify({ reason }) : '',
  }
  const wrap = await giftWrap(signer, granteePubkey, rumor)
  const receipt = await relay.publish(wrap)
  return { wrap, ...receipt }
}

/**
 * Rotate a scope, preserving each survivor's terms. The lib's rotateScope
 * re-grants vanilla (it predates terms); this variant re-grants every
 * survivor with the terms they were originally delegated under — a rotation
 * is a key event, not a renegotiation.
 * `survivors`: [{ pub, terms }] — terms null/undefined re-grants vanilla.
 */
export async function rotateWithTerms(relay, delegator, { scopeId, generation, payload, scopeName, survivors, relayHint = '' }) {
  const scopeKey = newScopeKey()
  const next = generation + 1
  await publishScope(relay, delegator, { scopeId, generation: next, scopeKey, payload })
  for (const s of survivors)
    await grantWithTerms(relay, delegator, s.pub, {
      scopeId, generation: next, scopeKey, scopeName, relayHint, terms: s.terms ?? undefined,
    })
  return { scopeKey, generation: next }
}

/** Opaque scope id — semantic names in `d` tags leak disclosure structure. */
export const opaqueScopeId = () =>
  [...crypto.getRandomValues(new Uint8Array(6))].map(b => 'abcdefghijklmnopqrstuvwxyz234567'[b % 32]).join('')

// ------------------------------------------------------------- templates
//
// Demo payloads only — never real personal data; .invalid emails, fake
// addresses. Each template = a payload plus a default purpose line for the
// terms form. The `name` field inside the payload is the human-readable
// scope name (the `d` tag stays opaque).

export const TEMPLATES = {
  'travel-prefs': {
    label: 'Travel preferences',
    purpose: 'Plan travel within stated preferences',
    payload: {
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
    },
  },
  'project-brief': {
    label: 'Project brief',
    purpose: 'Draft status reports and vendor communications for this project',
    payload: {
      name: 'Project brief',
      fields: {
        project: 'Aurora line retrofit',
        objective: 'Cut station changeover time 30% by Q4',
        deadline: '2026-10-31',
        stakeholders: ['ops lead <ops@example.invalid>', 'controls eng <ce@example.invalid>'],
        budget_usd: 120000,
        constraints: ['no downtime on line 2', 'existing PLC fleet stays'],
        status_notes: 'Vendor quotes due Friday; safety review booked.',
      },
    },
  },
  'property-ops': {
    label: 'Property operations',
    purpose: 'Coordinate maintenance and tenant requests within the stated window',
    payload: {
      name: 'Property operations',
      fields: {
        property: '12 Example Court, Unit 4 (demo)',
        tenants: [{ unit: '4', contact: 'tenant@example.invalid' }],
        service_contacts: [{ trade: 'HVAC', phone: '+1 555 0100' }, { trade: 'plumbing', phone: '+1 555 0101' }],
        maintenance_window: 'weekdays 09:00–16:00',
        notes: 'Furnace filter monthly; salt the walk after snow.',
      },
    },
  },
  'pipeline-extract': {
    label: 'Pipeline extract',
    purpose: 'Prepare follow-ups for open proposals in this extract',
    payload: {
      name: 'Pipeline extract',
      fields: {
        crm: 'demo-crm',
        stage: 'proposal',
        rows: [
          { company: 'Acme Widgets (demo)', value_usd: 42000, next_step: 'send revised SOW' },
          { company: 'Globex (demo)', value_usd: 18500, next_step: 'book technical call' },
        ],
        extracted_at: '2026-07-10',
      },
    },
  },
}
