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

import { finalizeEvent, generateSecretKey, getEventHash, nip19, nip44, verifyEvent } from 'nostr-tools'
import { KIND_DATA_SET, KIND_GRANT, newScopeKey, publishScope, localSigner } from '../lib/nipxx.mjs'

/** Grant Revocation notice — placeholder pending assignment, like its siblings. */
export const KIND_REVOCATION = 441

/** App-level rumor kind for Nvoy notices (access requests, relinquishes) —
 *  only ever inside 1059 gift wraps, never naked on a relay. Must match
 *  mcp/src/notices.ts. */
export const KIND_NVOY_MSG = 24440

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

// ------------------------------------------------------------ receiving side
//
// The console is a grantee too: agents grant their outbox scopes back (§6.5)
// and send access requests / relinquish notices (§6.2, §6.6) — all inside
// gift wraps addressed to the delegator. Signer-based unwrap, mirroring the
// lib's giftUnwrap checks exactly (kind-13 seal, verifyEvent, rumor.pubkey
// === seal.pubkey — nostr-tools' own nip59.unwrapEvent skips both).

/** Unwrap every gift wrap addressed to this signer; keep authenticated
 *  rumors of the wanted kinds. Malformed wraps are skipped, never fatal.
 *
 *  Paginated (nvoy#9): gift-wrap `created_at` is fuzzed up to two days into
 *  the past, so a FRESH wrap can sort below dozens of older ones — and a
 *  single un-limited query gets a relay's default newest-N cap, silently
 *  dropping it. Walk with `until` until a page yields nothing new (dedup by
 *  id), under a sane ceiling. No `since`: grants must reach arbitrarily back.
 *
 *  `stats` (optional, caller-owned) reports what pagination and decryption
 *  actually saw: { wraps, undecryptable }. Wraps addressed to us that our
 *  signer could not open (extension prompt declined, bulk-decrypt rate limit)
 *  are counted, not hidden — an empty inbox and an unopenable one must not
 *  look the same (nvoy#9 mechanism 2). */
export async function unwrapRumors(relay, signer, kinds, stats = {}) {
  const me = await signer.getPublicKey()
  const PAGE = 500, MAX_PAGES = 20
  const wraps = [], seen = new Set()
  let until
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await relay.query({ kinds: [1059], '#p': [me], limit: PAGE, ...(until ? { until } : {}) })
    const fresh = page.filter(w => w && w.id && !seen.has(w.id))
    for (const w of fresh) { seen.add(w.id); wraps.push(w) }
    if (!fresh.length) break                     // exhausted (or the relay repeated itself)
    until = Math.min(...fresh.map(w => w.created_at)) - 1
  }
  stats.wraps = wraps.length
  stats.undecryptable = 0
  const rumors = []
  for (const wrap of wraps) {
    try {
      const seal = JSON.parse(await signer.nip44Decrypt(wrap.pubkey, wrap.content))
      if (seal.kind !== 13 || !verifyEvent(seal)) continue          // unauthenticated seal
      const rumor = JSON.parse(await signer.nip44Decrypt(seal.pubkey, seal.content))
      if (rumor.pubkey !== seal.pubkey) continue                    // sender impersonation
      if (kinds.includes(rumor.kind)) rumors.push(rumor)
    } catch { stats.undecryptable++; continue }
  }
  return rumors
}

/** Tolerant §4 terms reader — the JS mirror of mcp/src/terms.ts parseTerms.
 *  Absent/malformed terms degrade to null (a vanilla grant), never an error. */
export function parseTerms(content) {
  if (typeof content !== 'object' || content === null || Array.isArray(content)) return null
  let carrier
  if (typeof content.nvoy === 'object' && content.nvoy !== null && !Array.isArray(content.nvoy)) carrier = content.nvoy
  else if (typeof content.nvoy === 'number') carrier = content
  else return null
  const take = (key, type) => (typeof carrier[key] === type ? carrier[key] : undefined)
  const terms = {
    nvoy: typeof carrier.nvoy === 'number' ? carrier.nvoy : 1,
    purpose: take('purpose', 'string'),
    expires_at: take('expires_at', 'number'),
    no_persist: take('no_persist', 'boolean'),
    redelegate: take('redelegate', 'boolean'),
    reply_scope_requested: take('reply_scope_requested', 'boolean'),
    contact: take('contact', 'string'),
    auto_relinquish: take('auto_relinquish', 'boolean'),
  }
  for (const k of Object.keys(terms)) if (terms[k] === undefined) delete terms[k]
  return terms
}

const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0))

/** Grants received by this signer, terms-aware (the lib's receiveGrants
 *  predates terms and drops them). Used for agent outbox scopes (§6.5). */
export async function receiveGrantsWithTerms(relay, signer, stats = {}) {
  const rumors = await unwrapRumors(relay, signer, [KIND_GRANT], stats)
  const grants = []
  for (const rumor of rumors) {
    try {
      const aTag = rumor.tags.find(t => t[0] === 'a')
      const [kind, publisher, scopeId] = String(aTag[1]).split(':')
      if (Number(kind) !== KIND_DATA_SET || publisher !== rumor.pubkey) continue
      const content = JSON.parse(rumor.content)
      grants.push({
        publisher, scopeId,
        scopeName: typeof content.scope_name === 'string' ? content.scope_name : undefined,
        relayHint: aTag[2] || undefined,
        generation: Number(rumor.tags.find(t => t[0] === 'v')?.[1] ?? 0),
        scopeKey: unb64(content.scope_key),
        issuedAt: rumor.created_at,
        terms: parseTerms(content),
      })
    } catch { continue }
  }
  return grants
}

/** Nvoy notices addressed to this signer, split by type:
 *  { accessRequests: [{ id, from, purpose, at }],
 *    relinquishes:   [{ id, from, scope, reason, destroyed_at, at }] }.
 *  Newest first within each list; malformed notices are skipped. */
export async function receiveNotices(relay, signer, stats = {}) {
  const rumors = await unwrapRumors(relay, signer, [KIND_NVOY_MSG], stats)
  const accessRequests = [], relinquishes = []
  for (const rumor of rumors) {
    try {
      const body = JSON.parse(rumor.content)
      if (body.type === 'access_request' && typeof body.purpose === 'string') {
        // scope_name / enc_value are the credential-migration extension: a
        // runtime proposing a named credential and carrying its current value,
        // NIP-44-encrypted to us. Vanilla requests omit both — they stay
        // undefined and the approve flow behaves exactly as it did before.
        // owner_npub (credential-migration extension): the identity the runtime
        // proposes as the GRANTEE — the credential's owner — which is NOT the
        // requester (the runtime raises the request on the owner's behalf). Vanilla
        // requests omit it and the requester stays the default grantee, as before.
        let owner
        if (typeof body.owner_npub === 'string') {
          try { const d = nip19.decode(body.owner_npub); if (d.type === 'npub') owner = d.data } catch { /* ignore malformed */ }
        }
        accessRequests.push({
          id: rumor.id, from: rumor.pubkey, purpose: body.purpose, at: rumor.created_at,
          ...(typeof body.scope_name === 'string' ? { scope_name: body.scope_name } : {}),
          ...(typeof body.enc_value === 'string' ? { enc_value: body.enc_value } : {}),
          ...(owner ? { owner } : {}),
        })
      } else if (body.type === 'relinquish' && typeof body.d === 'string') {
        relinquishes.push({
          id: rumor.id, from: rumor.pubkey, scope: body.d,
          reason: typeof body.reason === 'string' ? body.reason : null,
          destroyed_at: typeof body.destroyed_at === 'number' ? body.destroyed_at : rumor.created_at,
          at: rumor.created_at,
        })
      }
    } catch { continue }
  }
  const newest = (a, b) => b.at - a.at
  return { accessRequests: accessRequests.sort(newest), relinquishes: relinquishes.sort(newest) }
}

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
