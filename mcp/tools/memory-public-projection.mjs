// memory-public-projection.mjs — Offline allowlisted static Public Cortex projection (Frontier E1).
//
// Invariants (docs/frontier-review/PLAN.md E1 & Hive decision-hive-memory-buzz-cortex-publication-boundary):
//   1. Strictly offline and read-only: opens an offline SQLite snapshot with `{ readOnly: true }`, imports
//      no networking, IPC or child-process modules, and refuses live store, socket and publication paths.
//   2. Strictly aggregate-only explicit allowlist: only scopes listed in `allowlist.scopes` are read
//      (`self:<pubkey>` is always refused, and `room:<uuid>` scopes require an explicit public label so
//      room UUIDs never appear in output). Topics are restricted to `allowlist.topics`. When optional
//      `allowlist.claims` is supplied, only those allowlisted fact keys contribute to aggregate counts.
//      Claim prose, raw IDs/slugs, identities, paths and network details are never emitted.
//   3. Two-layer fail-closed secret & boundary guard: every candidate event must pass full Nostr signature
//      and schema verification (`validateMemoryEvent` + `checkClaimPayloadSecrets`) AND match its stored
//      SQLite metadata columns (so unsigned SQLite columns can never relabel signed event topics or counts),
//      and the entire output object + static HTML must pass `publicProjectionFindings` before a byte is
//      written via exclusive non-symlink-following atomic temp files.

import { randomBytes } from 'node:crypto'
import {
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import {
  DECISION_RETENTION,
  FALLBACK_MEMORY_KIND,
  MEMORY_KIND,
  checkMemorySecrets,
  normalizeMemoryTopic,
  parseFactKey,
  parseScope,
  validateMemoryEvent,
} from './memory.mjs'
import { sanitiserFindings } from './status_snapshot.mjs'

export const PROJECTION_VERSION = 1

export const WITHHELD_PUBLIC_FIELDS = Object.freeze([
  'claim_prose',
  'event_ids',
  'fact_keys_and_slugs',
  'author_identities',
  'room_uuids',
  'unallowlisted_scopes',
  'because_and_evidence',
  'filesystem_paths',
  'network_addresses_and_hosts',
])

// Live store, daemon socket, config and live web-root directories this offline tool must never touch.
export const FORBIDDEN_LIVE_PREFIXES = Object.freeze([
  '/var/lib/hive-memory',
  '/run/hive-memory',
  '/etc/hive-memory',
  '/opt/hive-memory',
  '/srv/apps',
])

const PUBLIC_LABEL = /^[a-z0-9][a-z0-9-]{0,39}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const URI_SCHEME = /^[a-z][a-z0-9+.-]*:/i

const BOUNDARY_PATTERNS = Object.freeze([
  ['a Nostr public or event identifier', /(?<![a-z0-9])(?:npub|nprofile|nevent|note|naddr)1[02-9ac-hj-np-z]{20,}/i],
  ['a raw Hive memory fact key', /\bhive-memory:[a-z0-9:._-]+/i],
  ['a raw UUID', /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i],
  ['a full 64-hex key or id', /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/i],
  ['an IPv4 address', /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/],
  ['an IPv6 address', /\[[0-9a-f:.]*:[0-9a-f:.]*\]|(?<![0-9a-z:])(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}(?![0-9a-z:])|(?<![0-9a-z:])[0-9a-f]{0,4}::(?:[0-9a-f]{1,4})?(?![0-9a-z])/i],
  ['a filesystem path', /(?<![A-Za-z0-9_<:/])\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*|(?<![A-Za-z0-9])~\/|(?<![A-Za-z0-9.])\.\.?\/[A-Za-z0-9._-]+|\b[A-Za-z]:\\[A-Za-z0-9._\\-]+/],
  ['a network URI or hostname', /\b[a-z][a-z0-9+.-]*:\/\/\S+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b|\b(?:herd-cloud|nvoy-fleet|waggle-box|pointbeachlab[a-z0-9-]*|localhost)\b|\b[a-z][a-z0-9-]{1,62}:\d{2,5}(?![0-9a-z%])/i],
])

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v)
const tagValue = (ev, name) => (Array.isArray(ev?.tags) ? ev.tags : []).find(t => t?.[0] === name)?.[1]

function underForbiddenPrefix(p) {
  const norm = resolve(p)
  return FORBIDDEN_LIVE_PREFIXES.find(prefix => norm === prefix || norm.startsWith(`${prefix}/`)) || null
}

function nearestExistingRealpath(targetPath) {
  let cur = resolve(targetPath)
  while (true) {
    try {
      return realpathSync(cur)
    } catch {
      const parent = dirname(cur)
      if (parent === cur) return cur
      cur = parent
    }
  }
}

function rejectLiveOrRemotePath(rawPath, label) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    throw new Error(`${label} is required`)
  }
  const trimmed = rawPath.trim()
  if (URI_SCHEME.test(trimmed) && !isAbsolute(trimmed)) {
    throw new Error(`${label} must be a local filesystem path, not a URI`)
  }
  const resolved = resolve(trimmed)
  const lexHit = underForbiddenPrefix(resolved)
  if (lexHit) {
    throw new Error(`${label} refuses forbidden live or published path under ${lexHit}`)
  }
  const realBase = nearestExistingRealpath(resolved)
  const realHit = underForbiddenPrefix(realBase)
  if (realHit) {
    throw new Error(`${label} resolves under forbidden live or published path ${realHit}`)
  }
  return resolved
}

export function assertOfflineProjectionPaths({ dbPath, outDir, allowlistPath = null }) {
  const resolvedDb = rejectLiveOrRemotePath(dbPath, '--db')
  let dbStat
  try {
    dbStat = lstatSync(resolvedDb)
  } catch {
    throw new Error('--db snapshot file does not exist')
  }
  if (dbStat.isSymbolicLink() || !dbStat.isFile()) {
    throw new Error('--db must be a regular non-symlink SQLite snapshot file')
  }
  const realDb = realpathSync(resolvedDb)
  const realDbHit = underForbiddenPrefix(realDb)
  if (realDbHit) {
    throw new Error(`--db resolves under forbidden live path ${realDbHit}`)
  }

  let resolvedAllowlist = null
  if (allowlistPath != null) {
    resolvedAllowlist = rejectLiveOrRemotePath(allowlistPath, '--allowlist')
    let allowStat
    try {
      allowStat = lstatSync(resolvedAllowlist)
    } catch {
      throw new Error('--allowlist file does not exist')
    }
    if (allowStat.isSymbolicLink() || !allowStat.isFile()) {
      throw new Error('--allowlist must be a regular non-symlink JSON file')
    }
  }

  const resolvedOut = rejectLiveOrRemotePath(outDir, '--out')
  try {
    const outStat = lstatSync(resolvedOut)
    if (outStat.isSymbolicLink() || !outStat.isDirectory()) {
      throw new Error('--out must be a non-symlink directory')
    }
  } catch (e) {
    if (e.code !== 'ENOENT') throw e
  }

  return { dbPath: realDb, outDir: resolvedOut, allowlistPath: resolvedAllowlist }
}

// Returns the category name of the first credential or publication-boundary hit, or null. Never the value.
export function publicBoundaryHit(text) {
  const s = String(text ?? '')
  const secret = checkMemorySecrets(s)
  if (secret) return secret
  for (const [what, re] of BOUNDARY_PATTERNS) {
    if (re.test(s)) return what
  }
  return null
}

export function publicProjectionFindings(value) {
  const findings = [...sanitiserFindings(value)]
  const seen = new Set(findings.map(f => `${f.path}:${f.what}`))
  const add = (path, what) => {
    const key = `${path}:${what}`
    if (!seen.has(key)) {
      seen.add(key)
      findings.push({ path, what })
    }
  }
  const walk = (v, path) => {
    if (typeof v === 'string') {
      const hit = publicBoundaryHit(v)
      if (hit) add(path, hit)
      return
    }
    if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, `${path}[${i}]`))
      return
    }
    if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) {
        const keyHit = publicBoundaryHit(k)
        if (keyHit) add(`${path}.${k} (key)`, keyHit)
        walk(x, `${path}.${k}`)
      }
    }
  }
  walk(value, '$')
  return findings
}

export function validateProjectionAllowlist(raw) {
  if (!isObj(raw)) throw new Error('projection allowlist must be a JSON object')
  const allowedKeys = new Set(['scopes', 'topics', 'claims', 'memory_global_channel_id'])
  const unknown = Object.keys(raw).filter(k => !allowedKeys.has(k))
  if (unknown.length) throw new Error(`unknown allowlist key (${unknown.length} unexpected key(s))`)

  if (!Array.isArray(raw.scopes) || raw.scopes.length === 0) {
    throw new Error('allowlist.scopes must be a non-empty array')
  }
  const scopeMap = new Map()
  const publicLabels = new Set()
  for (const entry of raw.scopes) {
    if (typeof entry === 'string') {
      const parsed = parseScope(entry)
      if (!parsed) throw new Error('allowlist.scopes contains an invalid scope')
      if (parsed.type === 'self') throw new Error('personal self scopes may never be projected publicly')
      if (parsed.type === 'room') {
        throw new Error('room scopes require { scope, label } so raw room UUIDs never appear in public output')
      }
      if (scopeMap.has(parsed.scope)) throw new Error(`duplicate scope in allowlist: ${parsed.scope}`)
      scopeMap.set(parsed.scope, { scope: parsed.scope, publicLabel: parsed.scope, type: parsed.type })
      publicLabels.add(parsed.scope)
      continue
    }
    if (isObj(entry)) {
      const extra = Object.keys(entry).filter(k => k !== 'scope' && k !== 'label')
      if (extra.length) throw new Error('room scope allowlist entry takes only scope and label')
      const parsed = parseScope(entry.scope)
      if (!parsed || parsed.type !== 'room') {
        throw new Error('object scope allowlist entry must name a valid room:<uuid> scope')
      }
      const label = String(entry.label ?? '').trim()
      if (!PUBLIC_LABEL.test(label) || publicBoundaryHit(label)) {
        throw new Error('room scope public label must be safe lowercase kebab-case (1..40 chars)')
      }
      const publicLabel = `room:${label}`
      if (scopeMap.has(parsed.scope)) throw new Error('duplicate room scope in allowlist')
      if (publicLabels.has(publicLabel)) throw new Error(`duplicate public scope label: ${publicLabel}`)
      scopeMap.set(parsed.scope, { scope: parsed.scope, publicLabel, type: 'room' })
      publicLabels.add(publicLabel)
      continue
    }
    throw new Error('invalid entry in allowlist.scopes')
  }

  if (!Array.isArray(raw.topics)) {
    throw new Error('allowlist.topics must be an array of canonical project topics')
  }
  const topics = []
  const topicSet = new Set()
  for (let idx = 0; idx < raw.topics.length; idx++) {
    const item = raw.topics[idx]
    if (typeof item !== 'string') throw new Error('allowlist.topics entries must be strings')
    const trimmed = item.trim()
    const norm = normalizeMemoryTopic(trimmed)
    if (!norm || norm !== trimmed || publicBoundaryHit(norm)) {
      throw new Error(`allowlist.topics entry at index ${idx} is not a safe canonical topic slug`)
    }
    if (topicSet.has(norm)) throw new Error(`duplicate topic in allowlist: ${norm}`)
    topicSet.add(norm)
    topics.push(norm)
  }

  const hasClaimFilter = raw.claims !== undefined
  const chosenClaims = new Set()
  if (hasClaimFilter) {
    if (!Array.isArray(raw.claims)) throw new Error('allowlist.claims must be an array of fact keys')
    for (const d of raw.claims) {
      if (typeof d !== 'string') throw new Error('allowlist.claims entries must be strings')
      const parsed = parseFactKey(d)
      if (!parsed) throw new Error('allowlist.claims contains a malformed fact key')
      if (!scopeMap.has(parsed.scope)) {
        throw new Error('allowlist.claims cannot select a fact key outside allowlist.scopes')
      }
      if (chosenClaims.has(parsed.d)) throw new Error('duplicate fact key in allowlist.claims')
      chosenClaims.add(parsed.d)
    }
  }

  let memoryGlobalChannelId = null
  if (raw.memory_global_channel_id !== undefined) {
    const ch = String(raw.memory_global_channel_id || '').toLowerCase()
    if (!UUID.test(ch)) throw new Error('allowlist.memory_global_channel_id must be a lowercase UUID')
    memoryGlobalChannelId = ch
  }

  return Object.freeze({
    scopeMap,
    topics: Object.freeze(topics),
    topicSet,
    hasClaimFilter,
    chosenClaims,
    memoryGlobalChannelId,
  })
}

export function coarseIsoMinute(nowSec = Math.floor(Date.now() / 1000)) {
  const sec = Number.isFinite(nowSec) && nowSec > 0 ? Math.floor(nowSec) : Math.floor(Date.now() / 1000)
  const minuteMs = Math.floor(sec / 60) * 60 * 1000
  return new Date(minuteMs).toISOString().replace(/\.\d{3}Z$/, 'Z')
}

export function withheldProjectionNotice(generatedAt, findingCount) {
  return {
    version: PROJECTION_VERSION,
    generated_at: generatedAt,
    coarse_state: 'withheld',
    withheld: true,
    reason: `this public projection failed its own boundary sanitiser (${findingCount} finding(s)), so none of it was written`,
  }
}

export function finalisePublicProjection(candidate) {
  const generatedAt = typeof candidate?.generated_at === 'string' && !publicBoundaryHit(candidate.generated_at)
    ? candidate.generated_at
    : coarseIsoMinute()
  const findings = publicProjectionFindings(candidate)
  if (findings.length > 0) {
    return { projection: withheldProjectionNotice(generatedAt, findings.length), findings }
  }
  return { projection: candidate, findings: [] }
}

export function buildPublicProjectionFromDb(db, rawAllowlist, { nowSec = Math.floor(Date.now() / 1000) } = {}) {
  const allowlist = validateProjectionAllowlist(rawAllowlist)
  const effectiveNow = Number.isSafeInteger(nowSec) && nowSec > 0 ? nowSec : Math.floor(Date.now() / 1000)
  const generatedAt = coarseIsoMinute(effectiveNow)

  const scopeStats = new Map()
  for (const info of allowlist.scopeMap.values()) {
    scopeStats.set(info.publicLabel, {
      scope: info.publicLabel,
      active_claims: 0,
      durable_decisions: 0,
      ephemeral_claims: 0,
    })
  }
  const topicStats = new Map()
  for (const t of allowlist.topics) {
    topicStats.set(t, {
      topic: t,
      active_claims: 0,
      durable_decisions: 0,
    })
  }

  const rows = db.prepare(`
    SELECT id, pubkey, kind, created_at, d, scope, scope_type, room_id, topic, status, retention, exp, raw_json, is_current
    FROM events
    WHERE is_current = 1
    ORDER BY scope ASC, d ASC, id ASC
  `).all()

  let activeClaims = 0
  let durableDecisions = 0
  let ephemeralClaims = 0
  let curatedSyntheses = 0
  let withheldClaims = 0
  let unlistedTopicClaims = 0
  let inferredGlobalChannelId = allowlist.memoryGlobalChannelId

  for (const row of rows) {
    if (!row || row.is_current !== 1) continue

    let ev = null
    let parseOk = false
    try {
      ev = JSON.parse(String(row.raw_json || ''))
      parseOk = isObj(ev)
    } catch {
      parseOk = false
    }

    const evScope = parseOk && typeof tagValue(ev, 's') === 'string' ? tagValue(ev, 's') : ''
    const rowScopeAllowed = allowlist.scopeMap.has(row.scope)
    const evScopeAllowed = Boolean(evScope && allowlist.scopeMap.has(evScope))

    // Strictly ignore rows whose stored scope AND signed scope are both outside allowlist.scopes (zero side-channels).
    if (!rowScopeAllowed && !evScopeAllowed) continue

    // If raw_json is malformed or stored scope diverges from signed event scope, quarantine into withheld_claims.
    if (!parseOk || !rowScopeAllowed || !evScopeAllowed || row.scope !== evScope) {
      withheldClaims += 1
      continue
    }
    const scopeInfo = allowlist.scopeMap.get(evScope)

    if (checkMemorySecrets(row.topic) || checkMemorySecrets(row.d)) {
      withheldClaims += 1
      continue
    }

    if (String(ev.id || '').toLowerCase() !== String(row.id || '').toLowerCase() ||
        String(ev.pubkey || '').toLowerCase() !== String(row.pubkey || '').toLowerCase() ||
        Number(row.kind) !== ev.kind ||
        tagValue(ev, 'd') !== row.d) {
      withheldClaims += 1
      continue
    }

    let candidateGlobalCh = inferredGlobalChannelId || ''
    let eventGlobalH = null
    if (scopeInfo.type === 'hive:canon' || scopeInfo.type === 'hive:ops') {
      const h = String(tagValue(ev, 'h') || '').toLowerCase()
      if (!UUID.test(h)) {
        withheldClaims += 1
        continue
      }
      if (candidateGlobalCh && h !== candidateGlobalCh) {
        withheldClaims += 1
        continue
      }
      eventGlobalH = h
      if (!candidateGlobalCh) candidateGlobalCh = h
    }

    const v = validateMemoryEvent(ev, {
      memoryGlobalChannelId: candidateGlobalCh,
      allowedKinds: [MEMORY_KIND, FALLBACK_MEMORY_KIND],
      verifySignature: true,
    })
    if (!v.ok) {
      withheldClaims += 1
      continue
    }

    // Verify stored SQLite metadata columns against the cryptographically verified Nostr event so unsigned
    // columns can never relabel signed topics, retention classes, expiry or status.
    const expectedStoredTopic = normalizeMemoryTopic(v.topic) ?? v.topic
    const rowExp = row.exp == null ? null : Number(row.exp)
    if (Number(row.created_at) !== v.createdAt ||
        row.scope !== v.scope ||
        row.scope_type !== v.scopeType ||
        (row.room_id ?? null) !== (v.roomId ?? null) ||
        row.topic !== expectedStoredTopic ||
        row.status !== v.status ||
        row.retention !== v.retention ||
        rowExp !== (v.expiresAt ?? null)) {
      withheldClaims += 1
      continue
    }

    // Pin inferred global channel only AFTER cryptographic signature and SQLite-column verification pass.
    if (eventGlobalH && !inferredGlobalChannelId) {
      inferredGlobalChannelId = eventGlobalH
    }

    if (v.status !== 'active') continue
    if (v.expiresAt != null && v.expiresAt <= effectiveNow) continue

    // Optional allowlist.claims filters which allowlisted claims contribute to aggregate counts; prose is never emitted.
    if (allowlist.hasClaimFilter && !allowlist.chosenClaims.has(v.d)) continue

    // Derive canonical topic strictly from the verified signed event, never from unsigned SQLite metadata.
    const normTopic = normalizeMemoryTopic(v.topic)
    const curatedTopic = normTopic && allowlist.topicSet.has(normTopic) ? normTopic : null

    const isDecision = v.retention === DECISION_RETENTION
    activeClaims += 1
    if (isDecision) durableDecisions += 1
    else ephemeralClaims += 1
    if (v.merkleSources) curatedSyntheses += 1

    const sStat = scopeStats.get(scopeInfo.publicLabel)
    sStat.active_claims += 1
    if (isDecision) sStat.durable_decisions += 1
    else sStat.ephemeral_claims += 1

    if (curatedTopic) {
      const tStat = topicStats.get(curatedTopic)
      tStat.active_claims += 1
      if (isDecision) tStat.durable_decisions += 1
    } else {
      unlistedTopicClaims += 1
    }
  }

  const candidate = {
    version: PROJECTION_VERSION,
    generated_at: generatedAt,
    coarse_state: activeClaims > 0 ? 'ready' : 'empty',
    withheld: false,
    counts: {
      active_claims: activeClaims,
      durable_decisions: durableDecisions,
      ephemeral_claims: ephemeralClaims,
      curated_syntheses: curatedSyntheses,
      unlisted_topic_claims: unlistedTopicClaims,
      withheld_claims: withheldClaims,
    },
    scopes: [...scopeStats.values()],
    topics: [...topicStats.values()],
    withheld_fields: [...WITHHELD_PUBLIC_FIELDS],
  }

  return finalisePublicProjection(candidate)
}

const escHtml = s => String(s ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;')

export function renderPublicProjectionHtml(projection) {
  const state = escHtml(projection?.coarse_state || 'withheld')
  const generatedAt = escHtml(projection?.generated_at || '')
  const csp = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; script-src 'none'; form-action 'none'; base-uri 'none'"

  if (!projection || projection.withheld === true) {
    const reason = escHtml(projection?.reason || 'Projection withheld by boundary sanitiser.')
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Public Cortex Projection — Withheld</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 48rem; margin: 2rem auto; padding: 0 1rem; color: #1f2937; background: #f9fafb; }
  .notice { border: 2px solid #dc2626; background: #fef2f2; color: #991b1b; padding: 1rem 1.25rem; border-radius: 0.5rem; }
</style>
</head>
<body>
  <h1>Public Cortex Projection</h1>
  <p>Generated: <code>${generatedAt}</code> · State: <strong>${state}</strong></p>
  <div class="notice">${reason}</div>
</body>
</html>
`
  }

  const c = projection.counts || {}
  const scopeRows = (Array.isArray(projection.scopes) ? projection.scopes : []).map(s =>
    `<tr><td><code>${escHtml(s.scope)}</code></td><td>${Number(s.active_claims) || 0}</td><td>${Number(s.durable_decisions) || 0}</td><td>${Number(s.ephemeral_claims) || 0}</td></tr>`
  ).join('\n      ')
  const topicRows = (Array.isArray(projection.topics) ? projection.topics : []).map(t =>
    `<tr><td><code>${escHtml(t.topic)}</code></td><td>${Number(t.active_claims) || 0}</td><td>${Number(t.durable_decisions) || 0}</td></tr>`
  ).join('\n      ')
  const withheldList = (Array.isArray(projection.withheld_fields) ? projection.withheld_fields : [])
    .map(f => `<code>${escHtml(f)}</code>`).join(', ')

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Public Cortex Projection</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 54rem; margin: 2rem auto; padding: 0 1rem; color: #111827; background: #f9fafb; line-height: 1.5; }
  h1, h2 { color: #111827; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.75rem; margin: 1rem 0 1.5rem; }
  .card { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 0.5rem; padding: 0.75rem 1rem; }
  .card strong { display: block; font-size: 1.4rem; }
  table { width: 100%; border-collapse: collapse; background: #ffffff; margin-bottom: 1.5rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e5e7eb; }
  .foot { font-size: 0.875rem; color: #4b5563; border-top: 1px solid #e5e7eb; padding-top: 1rem; margin-top: 2rem; }
</style>
</head>
<body>
  <h1>Public Cortex Projection</h1>
  <p>Offline read-only static snapshot · Generated: <code>${generatedAt}</code> · Coarse state: <strong>${state}</strong></p>
  <div class="grid">
    <div class="card"><span>Active claims</span><strong>${Number(c.active_claims) || 0}</strong></div>
    <div class="card"><span>Durable decisions</span><strong>${Number(c.durable_decisions) || 0}</strong></div>
    <div class="card"><span>Ephemeral claims</span><strong>${Number(c.ephemeral_claims) || 0}</strong></div>
    <div class="card"><span>Curated syntheses</span><strong>${Number(c.curated_syntheses) || 0}</strong></div>
  </div>
  <h2>Allowlisted Scopes</h2>
  <table>
    <thead><tr><th>Scope</th><th>Active</th><th>Decisions</th><th>Ephemeral</th></tr></thead>
    <tbody>
      ${scopeRows}
    </tbody>
  </table>
  <h2>Curated Topics</h2>
  <table>
    <thead><tr><th>Topic</th><th>Active</th><th>Decisions</th></tr></thead>
    <tbody>
      ${topicRows}
    </tbody>
  </table>
  <p class="foot">Excluded by publication boundary: ${withheldList}.</p>
</body>
</html>
`
}

function writeAtomically(targetPath, content) {
  let targetStat = null
  try {
    targetStat = lstatSync(targetPath)
  } catch (e) {
    if (e.code !== 'ENOENT') throw e
  }
  if (targetStat && (targetStat.isSymbolicLink() || !targetStat.isFile())) {
    throw new Error('refusing to overwrite non-regular file or symlink in --out')
  }

  const tmp = `${targetPath}.${process.pid}.${randomBytes(16).toString('hex')}.tmp`
  const openFlags = constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW || 0)
  const fd = openSync(tmp, openFlags, 0o644)
  let closed = false
  try {
    writeFileSync(fd, Buffer.from(String(content), 'utf8'))
    fsyncSync(fd)
    closeSync(fd)
    closed = true

    let recheck = null
    try {
      recheck = lstatSync(targetPath)
    } catch (e) {
      if (e.code !== 'ENOENT') throw e
    }
    if (recheck && (recheck.isSymbolicLink() || !recheck.isFile())) {
      throw new Error('refusing to overwrite non-regular file or symlink in --out')
    }
    renameSync(tmp, targetPath)
  } catch (e) {
    if (!closed) {
      try { closeSync(fd) } catch {}
    }
    try { unlinkSync(tmp) } catch {}
    throw e
  }
}

export function projectOfflinePublicCortex({ dbPath, allowlist, outDir, nowSec }) {
  const checked = assertOfflineProjectionPaths({ dbPath, outDir })
  const validatedAllowlist = validateProjectionAllowlist(allowlist)

  const db = new DatabaseSync(checked.dbPath, { readOnly: true })
  let built
  try {
    built = buildPublicProjectionFromDb(db, allowlist, { nowSec })
  } finally {
    db.close()
  }

  let projection = built.projection
  let findings = built.findings
  let html = renderPublicProjectionHtml(projection)
  const htmlFindings = publicProjectionFindings(html)
  if (htmlFindings.length > 0 && !projection.withheld) {
    findings = [...findings, ...htmlFindings.map(f => ({ path: `$html${f.path === '$' ? '' : f.path}`, what: f.what }))]
    projection = withheldProjectionNotice(projection.generated_at, findings.length)
    html = renderPublicProjectionHtml(projection)
  }

  mkdirSync(checked.outDir, { recursive: true })
  const outStat = lstatSync(checked.outDir)
  if (outStat.isSymbolicLink() || !outStat.isDirectory()) {
    throw new Error('--out must be a regular non-symlink directory')
  }
  const realOut = realpathSync(checked.outDir)
  const realOutHit = underForbiddenPrefix(realOut)
  if (realOutHit) {
    throw new Error(`--out resolves under forbidden live or published path ${realOutHit}`)
  }

  const jsonPath = join(realOut, 'cortex-public.json')
  const htmlPath = join(realOut, 'index.html')
  for (const p of [jsonPath, htmlPath]) {
    try {
      if (lstatSync(p).isSymbolicLink()) throw new Error('refusing to overwrite symlink in --out')
    } catch (e) {
      if (e.code !== 'ENOENT') throw e
    }
  }

  writeAtomically(jsonPath, `${JSON.stringify(projection, null, 2)}\n`)
  writeAtomically(htmlPath, html)

  return {
    projection,
    findings,
    jsonPath,
    htmlPath,
    allowedScopes: [...validatedAllowlist.scopeMap.values()].map(s => s.publicLabel),
  }
}

export function loadAllowlistFile(allowlistPath) {
  const st = lstatSync(allowlistPath)
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error('--allowlist must be a regular non-symlink JSON file')
  }
  if (st.size > 1024 * 1024) {
    throw new Error('--allowlist exceeds 1 MiB limit')
  }
  let raw
  try {
    raw = JSON.parse(readFileSync(allowlistPath, 'utf8'))
  } catch {
    throw new Error('invalid JSON in --allowlist')
  }
  validateProjectionAllowlist(raw)
  return raw
}
