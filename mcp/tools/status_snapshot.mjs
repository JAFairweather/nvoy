// The status page's judgements (status S1), kept pure so a test can hold them: what a container
// log says an agent did, what a set of grants lets each identity do, and what may leave the box.
// nvoy-status.mjs gathers the facts; this decides the colours.
//
// The rule from both 10-16 and 10-19: a component is green only when it does its job, never because
// its process is up. Every check here measures a function (a login signed, a grant is readable, a
// heard mention got a verdict); container state is shown but never decides a colour on its own.

import { createHash } from 'node:crypto'
import { verifyEvent } from 'nostr-tools/pure'
import { grantExpired } from './agent_limits.mjs'

const RANK = { grey: 0, green: 1, amber: 2, red: 3 }
const MIN = 60 * 1000, HOUR = 60 * MIN

// The worst colour that was measured. Grey (not measured) never hides a red and never shows green.
export const worst = colours => colours.filter(c => c !== 'grey')
  .reduce((acc, c) => (RANK[c] > RANK[acc] ? c : acc), 'grey')

const check = (key, label, colour, reason) => ({ key, label, colour, reason })
const clock = ms => new Date(ms).toISOString().slice(11, 16) + 'Z'
const ago = (now, ms) => {
  const s = Math.max(0, Math.round((now - ms) / 1000))
  return s < 120 ? `${s}s ago` : s < 7200 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`
}

// `docker logs --timestamps`: an RFC 3339 stamp with nanoseconds, a space, then the line.
export function parseLog(text) {
  const out = []
  for (const raw of String(text || '').split('\n')) {
    const m = raw.match(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z (.*)$/)
    if (!m) continue
    const at = Date.parse(`${m[1]}.${(m[2] || '0').padEnd(3, '0').slice(0, 3)}Z`)
    if (Number.isFinite(at)) out.push({ at, msg: m[3] })
  }
  return out
}

// --- Per agent: the message funnel ---------------------------------------------------------------

const ID12 = '([0-9a-f]{12})…'
const MARKED = new RegExp(`^buzz-wake: mention ${ID12} in [0-9a-f]{8} marked`)
const ADMITTED = new RegExp(`instance-broker(?:-native)?: ${ID12} admitted from ([0-9a-f]{8})`)
const DATA_ONLY = new RegExp(`instance-broker(?:-native)?: ${ID12} .*heard as data only \\[(no-grant-suspect|no-grant)`)
const HELD = new RegExp(`^instance-broker-daemon: ${ID12} held for retry`)
const REPLIED = new RegExp(`^instance-broker-daemon: \\S+ reply ${ID12} enacted|^instance-broker-post: posted`)

// What the broker did with each mention the watcher heard. Ids are matched on their 12-hex prefix,
// which both logs print; nothing of a line's text is carried out, only counts and times.
export function funnel({ watcher = [], broker = [], now = Date.now(), since = now - 24 * HOUR }) {
  const heard = new Map()
  for (const { at, msg } of watcher) { const m = msg.match(MARKED); if (m && at >= since && !heard.has(m[1])) heard.set(m[1], at) }
  const verdict = new Map()
  let admitted = 0, dataOnly = 0, suspect = 0, replies = 0, lastSuspect = 0, lastAdmitted = 0
  for (const { at, msg } of broker) {
    if (at < since) continue
    let m
    if ((m = msg.match(ADMITTED))) { verdict.set(m[1], 'admitted'); admitted++; lastAdmitted = Math.max(lastAdmitted, at) }
    else if ((m = msg.match(DATA_ONLY))) {
      verdict.set(m[1], 'data-only'); dataOnly++
      if (m[2] === 'no-grant-suspect') { suspect++; lastSuspect = Math.max(lastSuspect, at) }
    } else if ((m = msg.match(HELD))) { if (!verdict.has(m[1])) verdict.set(m[1], 'held') }
    else if (REPLIED.test(msg)) replies++
  }
  let pending = 0, held = 0, oldestPending = 0
  for (const [id, at] of heard) {
    const v = verdict.get(id)
    if (v === 'admitted' || v === 'data-only') continue
    if (v === 'held') held++
    pending++
    if (!oldestPending || at < oldestPending) oldestPending = at
  }
  return { heard: heard.size, admitted, data_only: dataOnly, suspect, held, pending, replies,
    oldest_pending_at: oldestPending ? new Date(oldestPending).toISOString() : null,
    lastSuspect, lastAdmitted }
}

function funnelCheck(f, now) {
  const counts = `${f.heard} heard → ${f.admitted} admitted, ${f.data_only} data only, ${f.replies} replies (24h)`
  if (f.suspect && f.lastSuspect > f.lastAdmitted) {
    return check('funnel', 'Funnel', 'red', `a grantor's mention was dropped as "no grant" while the relays looked evicted (${ago(now, f.lastSuspect)}); ${counts}`)
  }
  if (f.pending && now - Date.parse(f.oldest_pending_at) > 5 * MIN) {
    return check('funnel', 'Funnel', 'red', `${f.pending} heard mention(s) with no verdict, oldest ${ago(now, Date.parse(f.oldest_pending_at))}; ${counts}`)
  }
  if (f.held) return check('funnel', 'Funnel', 'amber', `${f.held} mention(s) held for retry; ${counts}`)
  if (!f.heard && !f.admitted) return check('funnel', 'Funnel', 'grey', 'no mention heard in 24h, so the funnel was not exercised')
  return check('funnel', 'Funnel', 'green', counts)
}

// Ears, login rate and signing, from the watcher's own lines. A login that reached `listening`
// was signed by the broker's AUTH oracle, so signing is inferred from logins here; an active
// challenge against the oracle is a later check.
function earsChecks(watcher, now, running) {
  const buzz = watcher.filter(l => l.msg.startsWith('buzz-wake: '))
  const last = re => buzz.reduce((acc, l) => (re.test(l.msg) ? l : acc), null)
  const listen = last(/ listening on /), fail = last(/ login failed /), drop = last(/ — reconnecting in /)
  const checks = []
  if (!running) checks.push(check('ears', 'Ears', 'red', 'the watcher container is not running'))
  else if (!listen) checks.push(check('ears', 'Ears', 'red', 'the watcher has not reached "listening" since it started'))
  else if (fail && fail.at > listen.at && now - fail.at < 5 * MIN) checks.push(check('ears', 'Ears', 'red', `login failed ${ago(now, fail.at)}, and no login has succeeded since`))
  else if (drop && drop.at > listen.at && now - drop.at > MIN) checks.push(check('ears', 'Ears', 'red', `disconnected ${ago(now, drop.at)} and not listening again`))
  else checks.push(check('ears', 'Ears', 'green', `listening since ${clock(listen.at)}`))

  const logins = buzz.filter(l => now - l.at < HOUR && / (listening on|login failed) /.test(l.msg)).length
  checks.push(check('logins', 'Login rate', logins > 600 ? 'red' : logins > 60 ? 'amber' : 'green', `${logins} login attempts in the last hour`))

  if (!listen && !fail) checks.push(check('signing', 'Signing', 'grey', 'no login attempted yet'))
  else if (fail && (!listen || fail.at > listen.at) && /AUTH|sign|timed? ?out/i.test(fail.msg)) {
    checks.push(check('signing', 'Signing', 'red', `the last login could not be signed (${ago(now, fail.at)})`))
  } else if (listen) checks.push(check('signing', 'Signing', 'green', `the last login was signed (${clock(listen.at)}); inferred from the watcher`))
  else checks.push(check('signing', 'Signing', 'amber', 'logins are failing for a reason other than signing'))
  return checks
}

// One agent's checks. `containers` is [{ role, running, startedAt, restarts }], `channels` the
// number of live channel processes for this instance, `grant` the agent's column of the grant grid.
export function agentChecks({ manifest, watcher = [], broker = [], containers = [], channels = 0, grant, now = Date.now() }) {
  const byRole = Object.fromEntries(containers.map(c => [c.role, c]))
  const checks = []
  const expected = ['watcher', 'broker', 'adapter']
  const down = expected.filter(r => !byRole[r]?.running)
  const young = containers.filter(c => c.running && now - Date.parse(c.startedAt) < HOUR)
  checks.push(down.length
    ? check('containers', 'Containers', 'red', `not running: ${down.join(', ')}`)
    : check('containers', 'Containers', young.length ? 'amber' : 'green', young.length
      ? `restarted within the hour: ${young.map(c => c.role).join(', ')}`
      : `up since ${clock(Math.min(...containers.filter(c => c.running).map(c => Date.parse(c.startedAt))))}`))
  checks.push(...earsChecks(watcher, now, !!byRole.watcher?.running))
  checks.push(grantCheck(grant))
  const f = funnel({ watcher, broker, now })
  checks.push(funnelCheck(f, now))
  if (manifest.channelDoor) {
    checks.push(byRole.door?.running
      ? check('harness', 'Harness', 'grey', 'the HTTPS door is up; whether the harness is connected to it is not measured yet')
      : check('harness', 'Harness', 'red', 'the HTTPS door container is not running'))
  } else if (manifest.harness || manifest.mayPost) {
    checks.push(channels > 0
      ? check('harness', 'Harness', 'green', `${channels} channel connection(s) open from the harness`)
      : check('harness', 'Harness', 'red', 'no channel connection from the harness'))
  }
  if (manifest.buzz) {
    const keeping = broker.some(l => l.msg.startsWith('instance-broker-status: keeping status reactions'))
    checks.push(!manifest.buzz.statusReactions
      ? check('reactions', 'Reactions', 'grey', 'status reactions are off in the manifest')
      : check('reactions', 'Reactions', keeping ? 'green' : 'red', keeping ? 'the status keeper is running' : 'the status keeper has not started'))
  }
  const { lastSuspect, lastAdmitted, ...shown } = f
  return { id: manifest.id, pubkey: manifest.pubkey.slice(0, 8), colour: worst(checks.map(c => c.colour)), checks, funnel: shown }
}

// --- Grants: who may task whom --------------------------------------------------------------------

const TASK_CAPS = ['task', 'task+act', 'task-relay']
// The broker's own construction (attention.mjs), byte for byte, so the page reads a grant exactly
// as the broker that enforces it does.
const scopeHash = (agentHex, saltHex) => createHash('sha256').update(Buffer.concat([
  Buffer.from('waggle/da-scope/v1'), Buffer.from([0]), Buffer.from(String(agentHex)), Buffer.from(saltHex || '', 'hex'),
])).digest('hex')
const tag = (ev, name) => (ev.tags || []).find(t => t[0] === name)

// What one target's broker would conclude from these events: the same order, grantor filter,
// revocation and expiry rules as attention.mjs. Returns grantee -> { state, cap, grantId }.
function taskAuthority(events, target) {
  const live = new Map(), ended = new Map()
  const drop = (id, why) => {
    for (const [pk, caps] of live) {
      for (const [cap, g] of caps) if (g.grantId === id) { caps.delete(cap); ended.set(pk, why) }
      if (!caps.size) live.delete(pk)
    }
  }
  for (const ev of [...events].sort((a, b) => (a.created_at || 0) - (b.created_at || 0))) {
    if (!target.grantors.includes(String(ev.pubkey || '').toLowerCase())) continue
    if (ev.kind === 441) { const id = tag(ev, 'e')?.[1]; if (id) drop(id, 'revoked'); continue }
    const grantee = String(tag(ev, 'p')?.[1] || '').toLowerCase(), scope = tag(ev, 'da-scope'), cap = tag(ev, 'da-cap')?.[1]
    if (!grantee || !scope || !TASK_CAPS.includes(cap) || scope[1] !== scopeHash(target.pubkey, scope[2] || '')) continue
    if (!live.has(grantee)) live.set(grantee, new Map())
    live.get(grantee).set(cap, { grantId: ev.id, cap })
    if (grantExpired(ev)) drop(ev.id, 'expired')
  }
  const out = new Map()
  for (const [pk, caps] of live) {
    const g = caps.get('task+act') || caps.get('task') || caps.get('task-relay')
    out.set(pk, { state: 'active', cap: g.cap, grantId: g.grantId })
  }
  for (const [pk, why] of ended) if (!out.has(pk)) out.set(pk, { state: why })
  return out
}

// `events` are kind 440/441 from any author; only verified ones count. `heldBy` maps an event id to
// the relay labels that returned it. `targets` are the roster [{ id, pubkey, grantors, relays }],
// with `relays` as labels. `names` maps a pubkey to a display name.
export function grantGrid({ events = [], heldBy = new Map(), targets = [], names = new Map() }) {
  const verified = [...new Map(events.map(ev => [ev.id, ev])).values()].filter(ev => {
    if (![440, 441].includes(ev.kind)) return false
    try { return verifyEvent(ev) } catch { return false }
  })
  const authority = targets.map(t => taskAuthority(verified, t))
  const grantees = [...new Set(authority.flatMap(a => [...a.keys()]))]
  const label = pk => names.get(pk) || pk.slice(0, 8)
  grantees.sort((a, b) => label(a).localeCompare(label(b)))
  const rows = grantees.map(pk => ({
    name: names.get(pk) || null, pubkey: pk.slice(0, 8),
    cells: targets.map((t, i) => {
      const a = authority[i].get(pk)
      if (!a) return { state: 'none' }
      if (a.state !== 'active') return { state: a.state }
      const relays = [...(heldBy.get(a.grantId) || [])].filter(r => t.relays.includes(r)).sort()
      return { state: 'active', cap: a.cap, grant: a.grantId.slice(0, 8), relays }
    }),
  }))
  const grantors = [...new Set(targets.flatMap(t => t.grantors))].map(pk => ({ name: names.get(pk) || null, pubkey: pk.slice(0, 8) }))
  return { grantors, targets: targets.map(t => ({ name: t.id, pubkey: t.pubkey.slice(0, 8) })), rows }
}

// Check A4 for one target column: red if nobody holds a live task grant to it on a relay its broker
// reads, amber if some grant is held on a single relay (one eviction from silence).
export function grantCheck(column) {
  if (!column) return check('grants', 'Grants', 'grey', 'grants were not read')
  const active = column.filter(c => c.cell.state === 'active')
  if (!active.length) return check('grants', 'Grants', 'red', 'no live task grant to this agent on any relay its broker reads')
  const thin = active.filter(c => c.cell.relays.length < 2)
  const unread = thin.filter(c => !c.cell.relays.length)
  if (unread.length) return check('grants', 'Grants', 'red', `the grant from ${unread.map(c => c.who).join(', ')} is on no relay this broker reads`)
  if (thin.length) return check('grants', 'Grants', 'amber', `held on one relay only: ${thin.map(c => `${c.who} (${c.cell.relays[0]})`).join(', ')}`)
  return check('grants', 'Grants', 'green', `${active.length} live task grant(s), each on ${Math.min(...active.map(c => c.cell.relays.length))}+ relays`)
}

export const gridColumn = (grid, index) => grid.rows.map(r => ({ who: r.name || r.pubkey, cell: r.cells[index] }))

// --- Relays ---------------------------------------------------------------------------------------

// `answers` are [{ label, answered, ms, ids:Set }]. The retention canary is the newest live grant:
// a relay that answers but no longer holds it is forgetting grants (nos.lol, 10-19).
export function relayChecks(answers, newestGrantId) {
  return answers.map(a => {
    const base = { label: a.label, latency_ms: a.answered ? a.ms : null, events: a.ids.size }
    if (!a.answered) return { ...base, colour: 'red', reason: 'did not answer a REQ' }
    if (newestGrantId && !a.ids.has(newestGrantId)) return { ...base, colour: 'amber', reason: `answers, but no longer holds the newest grant (${newestGrantId.slice(0, 8)})` }
    return { ...base, colour: 'green', reason: `answered in ${a.ms} ms${newestGrantId ? '; holds the newest grant' : ''}` }
  })
}

// --- Platform -------------------------------------------------------------------------------------

// `host` is { uptimeSec, diskPct, memAvailPct }, `prev` the collector's last state. A reboot (uptime
// went backwards) is amber for an hour: 10-16 began with one, and the brokers had to re-pair after it.
export function platformChecks({ host = {}, deploy = {}, prev = {}, now = Date.now() }) {
  const checks = []
  const bootAt = Number.isFinite(host.uptimeSec) ? now - host.uptimeSec * 1000 : null
  const rebootAt = prev.bootAt && bootAt && bootAt - prev.bootAt > 2 * MIN ? bootAt : prev.rebootAt || null
  if (!bootAt) checks.push(check('uptime', 'Fleet host', 'grey', 'uptime unknown'))
  else if (rebootAt && now - rebootAt < HOUR) checks.push(check('uptime', 'Fleet host', 'amber', `rebooted ${ago(now, rebootAt)}; check that every broker re-paired`))
  else checks.push(check('uptime', 'Fleet host', 'green', `up ${Math.round(host.uptimeSec / 3600)}h`))
  if (Number.isFinite(host.diskPct)) checks.push(check('disk', 'Disk', host.diskPct >= 90 ? 'red' : host.diskPct >= 80 ? 'amber' : 'green', `${host.diskPct}% used`))
  if (Number.isFinite(host.memAvailPct)) checks.push(check('memory', 'Memory', host.memAvailPct < 5 ? 'red' : host.memAvailPct < 15 ? 'amber' : 'green', `${host.memAvailPct}% available`))
  const sha = String(deploy.deployedSha || '').slice(0, 12)
  if (deploy.timerActive !== true) checks.push(check('deploy', 'Deploy', 'red', 'the deploy timer is not active, so merges to main will not deploy'))
  else if (/^held /.test(deploy.lastOutcome || '')) checks.push(check('deploy', 'Deploy', 'red', `the last release is held after a failed attempt; running ${sha || 'unknown'}`))
  else if (deploy.remoteHead && deploy.settled && deploy.remoteHead !== deploy.deployedSha) checks.push(check('deploy', 'Deploy', 'amber', `running ${sha}, behind main ${String(deploy.remoteHead).slice(0, 12)}`))
  else if (!deploy.deployedSha) checks.push(check('deploy', 'Deploy', 'amber', 'no deployed release recorded'))
  else checks.push(check('deploy', 'Deploy', 'green', `running ${sha}${deploy.remoteHead === deploy.deployedSha ? ', current with main' : ''}`))
  checks.push(check('bridge', 'waggle bridge', 'grey', 'measured from outside the fleet host (status S3)'))
  return { checks, state: { bootAt: bootAt || prev.bootAt || null, rebootAt } }
}

// A web endpoint: `r` is { status, tlsDays } or { error }.
export function webCheck(name, r) {
  if (!r || r.error) return check(name, name, 'red', `unreachable${r?.error ? ` (${r.error})` : ''}`)
  if (r.status >= 400) return check(name, name, 'red', `HTTP ${r.status}`)
  const tls = Number.isFinite(r.tlsDays) ? `; certificate ${r.tlsDays} days left` : ''
  if (Number.isFinite(r.tlsDays) && r.tlsDays < 7) return check(name, name, 'red', `HTTP ${r.status}${tls}`)
  if (Number.isFinite(r.tlsDays) && r.tlsDays < 21) return check(name, name, 'amber', `HTTP ${r.status}${tls}`)
  return check(name, name, 'green', `HTTP ${r.status}${tls}`)
}

// --- What may leave the box -----------------------------------------------------------------------

// The repos and the page are public. The collector enforces this, not the page: a snapshot with
// any of these in a key or a value is never written. Full 64-hex strings are refused too (keys,
// event ids), unless allowlisted; the page names identities by 8-hex prefix.
const FORBIDDEN = [
  ['an IPv4 address', /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/],
  ['an IPv6 address', /\[[0-9a-f:.]*:[0-9a-f:.]*\]|(?<![0-9a-z:])(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}(?![0-9a-z:])|(?<![0-9a-z:])[0-9a-f]{0,4}::(?:[0-9a-f]{1,4})?(?![0-9a-z])/i],
  ['an nsec', /nsec1/i],
  ['a bunker URI', /bunker:\/\//i],
  ['a nostrconnect URI', /nostrconnect:\/\//i],
  ['a credential path', /\/etc\/nvoy\/credentials|\/credentials\//i],
  ['a secret parameter', /[?&]secret=/i],
  ['a box hostname', /\b(?:nvoy-fleet|waggle-box)\b/i],
]
const HEX64 = /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/gi

export function sanitiserFindings(value, { allow64 = [] } = {}) {
  const allowed = new Set(allow64.map(s => s.toLowerCase()))
  const found = []
  const scan = (text, path) => {
    for (const [what, re] of FORBIDDEN) if (re.test(text)) found.push({ path, what })
    for (const m of text.match(HEX64) || []) if (!allowed.has(m.toLowerCase())) { found.push({ path, what: 'a full 64-hex key or id' }); break }
  }
  const walk = (v, path) => {
    if (typeof v === 'string') return scan(v, path)
    if (Array.isArray(v)) return v.forEach((x, i) => walk(x, `${path}[${i}]`))
    if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { scan(k, `${path}.${k} (key)`); walk(x, `${path}.${k}`) }
  }
  walk(value, '$')
  return found
}
