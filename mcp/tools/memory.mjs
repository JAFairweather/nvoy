// memory.mjs — Hive Shared Memory library: fact keys, the signed claim schema, the secret guard,
// claim and withdrawal builders, and the MCP tool specs (PLANS/HIVE_MEMORY_PRIVATE_STORE.md).
//
// Core invariants enforced here:
//   1. Every memory is a Nostr event (kind 30078 or 30079) signed by its author. The private store
//      (hive_memory_store.mjs) verifies it on ingest and keeps it whole; no relay ever holds one.
//   2. Memory is data, never instruction. Every record returned carries `authority: null` and
//      `trustedInstruction: false`.
//   3. An active hive:ops or room claim is either Class A (an `exp` within 30 days, no `retention`
//      tag) or Class B (`["retention", "decision"]`, no `exp`). hive:canon may omit `exp`.

import { verifyEvent } from 'nostr-tools/pure'
import { credentialIn } from './outbound_secrets.mjs'

export const MEMORY_KIND = 30079
export const FALLBACK_MEMORY_KIND = 30078
export const MEMORY_D_PREFIX = 'hive-memory:'
export const DEFAULT_TTL_SEC = 14 * 86400
export const MAX_TTL_SEC = 30 * 86400
export const DEFAULT_WAKE_MAX_CHARS = 4000
export const DECISION_RETENTION = 'decision'
export const WORKFLOW_TTL_SEC = 86400
export const MAX_WORKFLOW_TTL_SEC = 2 * 86400
export const WAKE_INDEX_LIMIT = 8

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const SLUG = /^[a-z0-9][a-z0-9._-]{0,127}$/
const TOPIC = /^[a-z0-9][a-z0-9-]{0,39}$/
// A PR review, handoff, lock or WIP checkpoint: worth a day, not the 14 a status claim gets (Phase 2, Gate 7).
const WORKFLOW_SLUG = /-(?:review|review-status|owner|wip|handoff|status)$/
// Topics seen on day one of the live store that name an existing project another way (Phase 2, Gate 8).
const TOPIC_ALIASES = Object.freeze({
  'primer': 'illustrated-primer', 'illustrated_primer': 'illustrated-primer', 'illustrated primer': 'illustrated-primer',
  'rabidrabbit': 'r1', 'rabid-rabbit': 'r1',
  'active hive priorities (canon)': 'hive-canon', 'canon': 'hive-canon',
  'where dj codex runs': 'herd-infra', 'armada': 'herd-infra',
  'viewer-test': 'hive-memory',
})

export const isWorkflowSlug = slug => WORKFLOW_SLUG.test(String(slug || ''))

// The canonical project topic: an alias mapped, then lowercase kebab-case of at most 40 characters; null if it is not one.
export function normalizeMemoryTopic(topic) {
  const raw = String(topic ?? '').trim()
  const mapped = TOPIC_ALIASES[raw.toLowerCase()] ?? raw
  return TOPIC.test(mapped) ? mapped : null
}

// Write-time rules for a new claim (Phase 2, Gates 7 and 8), checked when a claim is built and when it is submitted,
// never against stored rows, so claims written before them stay valid. Returns the topic to store.
export function memoryWritePolicy(v) {
  const topic = normalizeMemoryTopic(v.topic)
  if (v.status !== 'active') return { ok: true, topic: topic ?? v.topic }
  if (!topic) {
    return { ok: false, code: 'HIVE_MEMORY_INVALID_TOPIC', reason: `topic "${String(v.topic).slice(0, 60)}" is not a project slug (lowercase kebab-case, at most 40 characters, e.g. nvoy, herd-infra, hive-memory, r1)` }
  }
  if (isWorkflowSlug(v.slug) && v.scopeType !== 'hive:canon') {
    if (v.expiresAt == null) return { ok: false, code: 'HIVE_MEMORY_INVALID_EVENT', reason: 'a workflow checkpoint (slug ending -review, -status, -owner, -wip or -handoff) cannot be a durable decision' }
    if (v.expiresAt > v.createdAt + MAX_WORKFLOW_TTL_SEC) {
      return { ok: false, code: 'HIVE_MEMORY_INVALID_EVENT', reason: `a workflow checkpoint expires within 48 hours (${MAX_WORKFLOW_TTL_SEC}s)` }
    }
  }
  return { ok: true, topic }
}

// Memory-specific secret patterns required by DESIGN_HIVE_MEMORY.md in addition to outbound_secrets.mjs.
// 64-character hex strings (pubkeys, event IDs, git SHAs) and npub1/nevent1 are explicitly permitted.
// Bracketed IPv6 requires at least one colon so ordinary bracketed hex words like "[dead]" or "[add]" pass.
const MEMORY_SECRET_PATTERNS = Object.freeze([
  ['a Nostr secret key', /\bnsec1[02-9ac-hj-np-z]{20,}\b/i],
  ['an encrypted Nostr key', /\bncryptsec1[02-9ac-hj-np-z]{20,}\b/i],
  ['a bunker URI', /\bbunker:\/\/[^\s"']+/i],
  ['a nostrconnect URI', /\bnostrconnect:\/\/[^\s"']+/i],
  ['a relay WebSocket URL', /\bwss?:\/\/[^\s"']+/i],
  ['an IPv4 address literal', /\b(?:\d{1,3}\.){3}\d{1,3}\b/],
  ['a Tailscale IPv6 literal', /\bfd7a:[0-9a-f:]+/i],
  ['a bracketed IPv6 literal', /\[[0-9a-f]*:[0-9a-f:]+\]/i],
  ['an API key prefix', /\b(?:sk-[a-zA-Z0-9_-]{16,}|gh[pousr]_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}|AIza[0-9A-Za-z-_]{30,})\b/],
])

export function checkMemorySecrets(text) {
  const s = String(text ?? '')
  for (const [name, re] of MEMORY_SECRET_PATTERNS) {
    if (re.test(s)) return name
  }
  return credentialIn(s)
}

export function checkClaimPayloadSecrets({ claim, because, evidence = [], tags = [] }) {
  for (const value of [claim, because, ...(Array.isArray(evidence) ? evidence : [])]) {
    const hit = checkMemorySecrets(value)
    if (hit) return hit
  }
  for (const t of Array.isArray(tags) ? tags : []) {
    if (!Array.isArray(t)) continue
    for (const cell of t) {
      const hit = checkMemorySecrets(cell)
      if (hit) return hit
    }
  }
  return null
}

const tagValue = (ev, name) => (Array.isArray(ev?.tags) ? ev.tags : []).find(t => t?.[0] === name)?.[1]
const tagValues = (ev, name) => (Array.isArray(ev?.tags) ? ev.tags : []).filter(t => t?.[0] === name).map(t => t[1])

export function parseScope(scopeStr) {
  const s = String(scopeStr || '')
  if (s === 'hive:ops') return { type: 'hive:ops', scope: s }
  if (s === 'hive:canon') return { type: 'hive:canon', scope: s }
  if (s.startsWith('room:')) {
    const roomId = s.slice(5).toLowerCase()
    if (!UUID.test(roomId)) return null
    return { type: 'room', roomId, scope: `room:${roomId}` }
  }
  if (s.startsWith('self:')) {
    const pubkey = s.slice(5).toLowerCase()
    if (!HEX64.test(pubkey)) return null
    return { type: 'self', pubkey, scope: `self:${pubkey}` }
  }
  return null
}

export function formatFactKey(scopeStr, slug) {
  const parsed = parseScope(scopeStr)
  if (!parsed || !SLUG.test(String(slug || ''))) return null
  return `${MEMORY_D_PREFIX}${parsed.scope}:${slug}`
}

export function parseFactKey(dTag) {
  const d = String(dTag || '')
  if (!d.startsWith(MEMORY_D_PREFIX)) return null
  const rest = d.slice(MEMORY_D_PREFIX.length)
  for (const prefix of ['hive:ops:', 'hive:canon:']) {
    if (rest.startsWith(prefix)) {
      const scope = prefix.slice(0, -1)
      const slug = rest.slice(prefix.length)
      return SLUG.test(slug) ? { scope, slug, d } : null
    }
  }
  if (rest.startsWith('room:')) {
    const parts = rest.split(':')
    if (parts.length !== 3) return null
    const [, roomId, slug] = parts
    return UUID.test(roomId) && SLUG.test(slug) ? { scope: `room:${roomId}`, roomId, slug, d } : null
  }
  if (rest.startsWith('self:')) {
    const parts = rest.split(':')
    if (parts.length !== 3) return null
    const [, pubkey, slug] = parts
    return HEX64.test(pubkey) && SLUG.test(slug) ? { scope: `self:${pubkey}`, pubkey, slug, d } : null
  }
  return null
}

// NIP-01 replaceable tie-breaker: newer created_at wins; on same-second ties, lowest lexical event id wins.
export function nip01Newer(candidate, existing) {
  if (!existing) return true
  const dt = (candidate?.created_at || 0) - (existing?.created_at || 0)
  if (dt !== 0) return dt > 0
  return String(candidate?.id || '') < String(existing?.id || '')
}

// Validates wire structure, scope/route consistency, mandatory fields, retention class, and secret guard.
export function validateMemoryEvent(ev, {
  memoryGlobalChannelId = '',
  allowedKinds = [MEMORY_KIND, FALLBACK_MEMORY_KIND],
  verifySignature = true,
} = {}) {
  if (!ev || typeof ev !== 'object') return { ok: false, reason: 'event is not an object' }
  if (!allowedKinds.includes(ev.kind)) return { ok: false, reason: `unsupported kind ${ev.kind}` }
  const pubkey = String(ev.pubkey || '').toLowerCase()
  if (!HEX64.test(pubkey)) return { ok: false, reason: 'invalid pubkey' }
  if (!Number.isSafeInteger(ev.created_at) || ev.created_at <= 0) return { ok: false, reason: 'invalid created_at' }

  const d = tagValue(ev, 'd')
  if (!d || !String(d).startsWith(MEMORY_D_PREFIX)) return { ok: false, reason: 'missing or unprefixed d tag' }
  const parsedD = parseFactKey(d)
  if (!parsedD) return { ok: false, reason: 'malformed fact key in d tag' }

  const s = tagValue(ev, 's')
  if (s !== parsedD.scope) return { ok: false, reason: 's tag does not match d tag scope' }
  const parsedScope = parseScope(s)
  if (!parsedScope) return { ok: false, reason: 'invalid scope tag' }

  const h = tagValue(ev, 'h')
  if (parsedScope.type === 'room') {
    if (String(h || '').toLowerCase() !== parsedScope.roomId) {
      return { ok: false, reason: 'room claim h tag does not match room UUID in s and d' }
    }
  } else if (parsedScope.type === 'hive:ops' || parsedScope.type === 'hive:canon') {
    if (!UUID.test(String(memoryGlobalChannelId || '').toLowerCase())) {
      return { ok: false, reason: 'memory_global_channel_id is not configured' }
    }
    if (String(h || '').toLowerCase() !== String(memoryGlobalChannelId).toLowerCase()) {
      return { ok: false, reason: 'global claim h tag does not match memory_global_channel_id' }
    }
  } else if (parsedScope.type === 'self') {
    if (parsedScope.pubkey !== pubkey) {
      return { ok: false, reason: 'self claim scope pubkey does not match event pubkey' }
    }
    if (h != null) {
      return { ok: false, reason: 'self claims must not carry an h tag' }
    }
  }

  let body
  try { body = JSON.parse(String(ev.content || '')) } catch { return { ok: false, reason: 'content is not valid JSON' } }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { ok: false, reason: 'content must be a JSON object' }

  const status = body.status === 'withdrawn' ? 'withdrawn' : body.status === 'active' ? 'active' : null
  if (!status) return { ok: false, reason: 'content.status must be "active" or "withdrawn"' }

  const because = typeof body.because === 'string' ? body.because.trim() : ''
  if (!because) return { ok: false, reason: 'content.because is required and must be non-empty' }

  const claim = typeof body.claim === 'string' ? body.claim.trim() : ''
  if (status === 'active' && !claim) return { ok: false, reason: 'content.claim is required for active claims' }

  const evidence = Array.isArray(body.evidence)
    ? body.evidence.filter(x => typeof x === 'string' && x.trim().length > 0).map(x => x.trim())
    : []
  if (status === 'active' && evidence.length === 0) {
    return { ok: false, reason: 'content.evidence must be a non-empty array of strings for active claims' }
  }

  const asOfGit = tagValue(ev, 'as_of_git') || null
  const asOfEvt = tagValue(ev, 'as_of_evt') || null
  if (status === 'active' && !asOfGit && !asOfEvt) {
    return { ok: false, reason: 'active claims require an as_of_git or as_of_evt tag' }
  }
  if (asOfEvt && !HEX64.test(String(asOfEvt).toLowerCase())) {
    return { ok: false, reason: 'as_of_evt must be a 64-hex event id' }
  }

  const expTags = tagValues(ev, 'exp')
  const retentionTags = tagValues(ev, 'retention')
  if (expTags.length > 1) return { ok: false, reason: 'more than one exp tag' }
  if (retentionTags.length > 1) return { ok: false, reason: 'more than one retention tag' }
  let expiresAt = null
  if (expTags.length) {
    if (!/^[0-9]{1,12}$/.test(String(expTags[0]))) return { ok: false, reason: 'malformed exp tag' }
    expiresAt = Number(expTags[0])
    if (expiresAt <= ev.created_at) return { ok: false, reason: 'exp must be later than created_at' }
    if (expiresAt > ev.created_at + MAX_TTL_SEC) {
      return { ok: false, reason: `exp exceeds maximum 30-day TTL (${MAX_TTL_SEC}s)` }
    }
  }
  const decision = retentionTags.length === 1
  if (decision && retentionTags[0] !== DECISION_RETENTION) return { ok: false, reason: 'retention tag must be "decision"' }
  if (decision && expiresAt != null) return { ok: false, reason: 'a claim carries either an exp tag or a retention decision tag, not both' }
  if (status === 'active' && (parsedScope.type === 'hive:ops' || parsedScope.type === 'room') && !decision && expiresAt == null) {
    return { ok: false, reason: 'operational and room claims require an exp tag or a retention decision tag' }
  }

  const secretHit = checkClaimPayloadSecrets({ claim, because, evidence, tags: ev.tags })
  if (secretHit) return { ok: false, reason: `secret guard blocked payload: ${secretHit}`, secret: secretHit }

  if (verifySignature) {
    let validSig = false
    try { validSig = verifyEvent(ev) } catch { validSig = false }
    if (!validSig) return { ok: false, reason: 'invalid event signature', invalidSignature: true }
  }

  return {
    ok: true,
    pubkey,
    d,
    slug: parsedD.slug,
    scope: parsedScope.scope,
    scopeType: parsedScope.type,
    roomId: parsedScope.roomId || null,
    channelId: h ? String(h).toLowerCase() : null,
    topic: tagValue(ev, 'topic') || parsedD.slug,
    asOfGit,
    asOfEvt: asOfEvt ? String(asOfEvt).toLowerCase() : null,
    expiresAt,
    retention: expiresAt == null ? 'decision' : 'ephemeral',
    supersedes: tagValues(ev, 'supersedes'),
    status,
    claim,
    because,
    evidence,
    createdAt: ev.created_at,
  }
}

function routeTags(parsedScope, memoryGlobalChannelId, verb) {
  if (parsedScope.type === 'room') return [['h', parsedScope.roomId]]
  if (parsedScope.type === 'hive:ops' || parsedScope.type === 'hive:canon') {
    if (!UUID.test(String(memoryGlobalChannelId || '').toLowerCase())) {
      throw new Error(`memory_global_channel_id is required to ${verb} global claims`)
    }
    return [['h', String(memoryGlobalChannelId).toLowerCase()]]
  }
  return []
}

// Builds an unsigned claim event template with monotonic created_at relative to any replaced claim.
// ttlSec 0 is a Class B durable decision (no exp); 1..MAX_TTL_SEC is a Class A expiring claim. A workflow
// checkpoint slug defaults to WORKFLOW_TTL_SEC and is capped at MAX_WORKFLOW_TTL_SEC.
export function buildClaimTemplate({
  pubkey,
  scope,
  slug,
  topic,
  claim,
  because,
  evidence,
  asOfGit,
  asOfEvt,
  ttlSec = null,
  supersedes = [],
  memoryGlobalChannelId = '',
  kind = MEMORY_KIND,
  nowSec = Math.floor(Date.now() / 1000),
  priorCreatedAt = 0,
}) {
  const parsedScope = parseScope(scope)
  if (!parsedScope) throw new Error(`invalid scope: ${scope}`)
  if (!SLUG.test(String(slug || ''))) throw new Error(`invalid fact slug: ${slug}`)
  const d = formatFactKey(parsedScope.scope, slug)
  const createdAt = Math.max(nowSec, Number.isSafeInteger(priorCreatedAt) ? priorCreatedAt + 1 : 0)

  const workflow = isWorkflowSlug(slug) && parsedScope.type !== 'hive:canon'
  let effectiveTtl = ttlSec == null ? (workflow ? WORKFLOW_TTL_SEC : DEFAULT_TTL_SEC) : Number(ttlSec)
  if (!Number.isInteger(effectiveTtl) || effectiveTtl < 0 || effectiveTtl > MAX_TTL_SEC) {
    throw new Error(`ttlSec must be 0 (a durable decision) or 1..${MAX_TTL_SEC}`)
  }
  if (workflow && effectiveTtl === 0) throw new Error(`${slug} is a workflow checkpoint (slug ending -review, -status, -owner, -wip or -handoff) and cannot be a durable decision`)
  if (workflow) effectiveTtl = Math.min(effectiveTtl, MAX_WORKFLOW_TTL_SEC)
  const cleanTopic = normalizeMemoryTopic(topic || slug)
  if (!cleanTopic) throw new Error(`topic "${String(topic || slug).slice(0, 60)}" is not a project slug (lowercase kebab-case, at most 40 characters); set topic, e.g. nvoy or herd-infra`)

  const tags = [['d', d], ...routeTags(parsedScope, memoryGlobalChannelId, 'write')]
  tags.push(['s', parsedScope.scope])
  tags.push(['topic', cleanTopic])
  if (asOfGit) tags.push(['as_of_git', String(asOfGit)])
  if (asOfEvt) tags.push(['as_of_evt', String(asOfEvt).toLowerCase()])
  tags.push(effectiveTtl === 0 ? ['retention', DECISION_RETENTION] : ['exp', String(createdAt + effectiveTtl)])
  for (const sup of Array.isArray(supersedes) ? supersedes : []) {
    if (sup) tags.push(['supersedes', String(sup)])
  }

  const contentObj = {
    claim: String(claim ?? '').trim(),
    because: String(because ?? '').trim(),
    evidence: Array.isArray(evidence) ? evidence.map(x => String(x).trim()).filter(Boolean) : [],
    status: 'active',
  }
  const template = {
    kind,
    pubkey: String(pubkey || '').toLowerCase(),
    created_at: createdAt,
    tags,
    content: JSON.stringify(contentObj),
  }
  const check = validateMemoryEvent(template, { memoryGlobalChannelId, verifySignature: false })
  if (!check.ok) throw new Error(check.reason)
  const policy = memoryWritePolicy(check)
  if (!policy.ok) throw new Error(policy.reason)
  return template
}

// Builds a withdrawal replacement event template: status "withdrawn", strictly later than the claim
// it withdraws, no exp (the tombstone lasts until the 90-day purge) and no NIP-09 deletion.
export function buildWithdrawalTemplate({
  pubkey,
  priorEvent,
  scope,
  slug,
  because,
  memoryGlobalChannelId = '',
  kind = MEMORY_KIND,
  nowSec = Math.floor(Date.now() / 1000),
}) {
  const priorCheck = priorEvent
    ? validateMemoryEvent(priorEvent, { memoryGlobalChannelId, verifySignature: false })
    : null
  const targetScope = priorCheck?.ok ? priorCheck.scope : scope
  const targetSlug = priorCheck?.ok ? priorCheck.slug : slug
  const parsedScope = parseScope(targetScope)
  if (!parsedScope) throw new Error(`invalid scope: ${targetScope}`)
  const d = formatFactKey(parsedScope.scope, targetSlug)
  if (!d) throw new Error(`invalid slug: ${targetSlug}`)

  // Strictly later created_at than the claim it withdraws so a same-second tombstone never loses a tie.
  const createdAt = Math.max(nowSec, (priorEvent?.created_at || 0) + 1)
  const tags = [['d', d], ...routeTags(parsedScope, memoryGlobalChannelId, 'withdraw')]
  tags.push(['s', parsedScope.scope])
  tags.push(['topic', priorCheck?.topic || targetSlug])

  const contentObj = {
    claim: '',
    because: String(because ?? '').trim(),
    evidence: priorCheck?.evidence || [],
    status: 'withdrawn',
  }
  const replacement = {
    kind: priorEvent?.kind || kind,
    pubkey: String(pubkey || priorEvent?.pubkey || '').toLowerCase(),
    created_at: createdAt,
    tags,
    content: JSON.stringify(contentObj),
  }
  const check = validateMemoryEvent(replacement, { memoryGlobalChannelId, verifySignature: false })
  if (!check.ok) throw new Error(check.reason)
  return { replacement }
}

export const MAX_QUERY_LIMIT = 100
export const DEFAULT_QUERY_LIMIT = 50
export const MAX_LINK_HOPS = 3

// MCP tool specifications for mounting Hive Shared Memory in any Nvoy MCP server.
export const MEMORY_TOOL_SPECS = Object.freeze([
  {
    name: 'memory_wake',
    description: 'Read the bounded Hive Wake Digest from the private hive-memory store: every hive:canon claim in full, then at most 8 one-line index cards and a topic directory, held to max_chars UTF-8 bytes (default 4000) apart from canon. All returned records carry authority: null and trustedInstruction: false.',
    inputSchema: {
      type: 'object',
      properties: {
        room_id: { type: 'string', pattern: UUID.source },
        max_chars: { type: 'integer', minimum: 1000, maximum: 24000 },
        git_banner: { type: 'string', maxLength: 500 },
        stale_files: { type: 'array', items: { type: 'string', maxLength: 300 }, maxItems: 200 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'memory_query',
    description: 'Search Hive memory claims by scope, room UUID, topic, fact key (d), author, time, link or text substring. Returns compact index cards (format "index") unless you name one fact key d or ask for format "full". Never truncates silently; returns answer ("found", "none", or "unknown" when the store is not ready) and omitted count.',
    inputSchema: {
      type: 'object',
      properties: {
        format: { type: 'string', enum: ['index', 'full'], description: 'index: event_id, d, topic, author, age and a claim preview per record. full: the whole claim with because, evidence and anchors. Default full when d is given, index otherwise.' },
        scope: { type: 'string', maxLength: 120 },
        room_id: { type: 'string', pattern: UUID.source },
        topic: { type: 'string', maxLength: 128 },
        d: { type: 'string', maxLength: 256 },
        author: { type: 'string', pattern: HEX64.source },
        since: { type: 'integer', minimum: 0 },
        until: { type: 'integer', minimum: 0 },
        text: { type: 'string', maxLength: 256 },
        linked_to: { type: 'string', maxLength: 300 },
        supersedes_of: { type: 'string', pattern: HEX64.source },
        include_history: { type: 'boolean' },
        limit: { type: 'integer', minimum: 1, maximum: MAX_QUERY_LIMIT },
        cursor: { type: 'string', maxLength: 32 },
        stale_files: { type: 'array', items: { type: 'string', maxLength: 300 }, maxItems: 200 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'memory_claim',
    description: 'Validate, secret-check, and prepare a structured Hive memory claim requiring claim, because, evidence, and an as_of_git or as_of_evt anchor. ttl_sec 0 records a durable decision with no expiry.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', minLength: 5, maxLength: 120, description: 'room:<uuid>, hive:ops, hive:canon or self:<pubkey>. Agents may write room:<uuid> only.' },
        slug: { type: 'string', pattern: SLUG.source, description: 'Stable fact identifier within the scope (d = hive-memory:<scope>:<slug>). Reuse it to supersede or withdraw an earlier claim; <topic>-<fact> reads well.' },
        topic: { type: 'string', maxLength: 128, description: 'The project or subsystem slug, lowercase kebab-case of at most 40 characters (e.g. nvoy, herd-infra, hive-memory, buzz, r1, illustrated-primer), so readers can filter by project.' },
        claim: { type: 'string', minLength: 1, maxLength: 2000, description: 'One self-contained fact or decision. No secrets, personal details or chat narration.' },
        because: { type: 'string', minLength: 1, maxLength: 2000, description: 'Why it holds: who decided it and why.' },
        evidence: { type: 'array', items: { type: 'string', minLength: 1, maxLength: 300 }, minItems: 1, maxItems: 32,
          description: 'Concrete citations: a commit, PR, file path, test run or message id (e.g. nvoy@974d3b4:mcp/tools/memory.mjs).' },
        as_of_git: { type: 'string', maxLength: 120, description: 'Git anchor <repo>@<sha> (a full 40-hex sha is best); a claim older than HEAD is flagged stale. This or as_of_evt is required.' },
        as_of_evt: { type: 'string', pattern: HEX64.source, description: '64-hex event id anchor, such as the message where the decision was made. This or as_of_git is required.' },
        ttl_sec: { type: 'integer', minimum: 0, maximum: MAX_TTL_SEC,
          description: `Retention class. 1..${MAX_TTL_SEC} (default ${DEFAULT_TTL_SEC}, 14 days; at most 30 days): Class A status that expires (exp tag). A workflow checkpoint, a slug ending -review, -status, -owner, -wip or -handoff, defaults to ${WORKFLOW_TTL_SEC} (24 h) and is capped at 48 h. 0: Class B durable decision that stays active until withdrawn or superseded (retention decision tag, no exp).` },
        supersedes: { type: 'array', items: { type: 'string', maxLength: 300 }, maxItems: 16,
          description: 'Event ids of earlier claims in the same scope (yours or another author\'s) that this claim replaces; stored as supersedes links.' },
      },
      required: ['scope', 'slug', 'claim', 'because', 'evidence'],
      additionalProperties: false,
    },
  },
  {
    name: 'memory_withdraw',
    description: 'Build a withdrawal replacement event (status: "withdrawn") with a strictly later created_at than the claim it withdraws.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', minLength: 5, maxLength: 120, description: 'The scope of the claim to withdraw. Agents may write room:<uuid> only.' },
        slug: { type: 'string', pattern: SLUG.source, description: 'The slug of your claim to withdraw.' },
        because: { type: 'string', minLength: 1, maxLength: 2000, description: 'Why it is being withdrawn: no longer true, resolved, or wrong.' },
      },
      required: ['scope', 'slug', 'because'],
      additionalProperties: false,
    },
  },
  {
    name: 'memory_lookup_prior',
    description: 'Writer sockets only: the minimum metadata of this writer\'s current event at a fact key, to build a monotonic replacement or withdrawal.',
    inputSchema: {
      type: 'object',
      properties: { d: { type: 'string', maxLength: 256 } },
      required: ['d'],
      additionalProperties: false,
    },
  },
  {
    name: 'memory_submit',
    description: 'Writer sockets only: store one signed memory event, replacing expected_prior_id (null when there is none).',
    inputSchema: {
      type: 'object',
      properties: {
        event: { type: 'object' },
        expected_prior_id: { anyOf: [{ type: 'string', pattern: HEX64.source }, { type: 'null' }] },
      },
      required: ['event', 'expected_prior_id'],
      additionalProperties: false,
    },
  },
])
