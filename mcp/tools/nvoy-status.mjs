#!/usr/bin/env node
// The status page's collector (status S1). Every minute, on the fleet host, it turns the facts a host
// script gathered (container state and logs, channel processes, uptime, the deploy runner's state)
// plus what the relays and public endpoints answer right now into one sanitised status.json, and
// copies the static page beside it. Caddy serves the pair at waggle.nave.pub/status.
//
//   node mcp/tools/nvoy-status.mjs --facts <dir> --instances /etc/nvoy/instances --state <dir> --out <dir>
//
// It runs in the deployed runtime image with no Docker socket and no credentials: the host script
// (deploy/nvoy-status-facts.sh) is the only part that touches Docker. Nothing it writes carries an
// address, a key, a credential path or message content; status_snapshot.mjs refuses such a snapshot,
// and a refused one is replaced by a red notice that says only how many findings there were.

import { copyFileSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs'
import { isIP } from 'node:net'
import { connect } from 'node:tls'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readManifest } from './runtime_manifest.mjs'
import { relayLabel } from './grant_evidence.mjs'
import { agentChecks, grantGrid, gridColumn, parseLog, platformChecks, relayChecks, sanitiserFindings, webCheck, worst } from './status_snapshot.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const arg = (name, fallback) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : fallback }
const die = m => { console.error(`nvoy-status: ${m}`); process.exit(1) }
const read = (path, fallback = '') => { try { return readFileSync(path, 'utf8') } catch { return fallback } }

const FACTS = arg('--facts'), INSTANCES = arg('--instances', '/etc/nvoy/instances'), STATE = arg('--state'), OUT = arg('--out')
const PAGE = arg('--page', resolve(here, 'status-page'))
const TIMEOUT_MS = Number(arg('--timeout-ms', 8000))
// Public endpoints, each a page anyone can open. An empty --web skips them (tests).
const WEB = (arg('--web', 'waggle.nave.pub=https://waggle.nave.pub/,console=https://waggle.nave.pub/console/,nave.pub=https://nave.pub/,bunker=https://bunker.nave.pub/'))
  .split(',').filter(Boolean).map(pair => { const i = pair.indexOf('='); return [pair.slice(0, i), pair.slice(i + 1)] })
if (!FACTS || !STATE || !OUT) die('usage: --facts <dir> --state <dir> --out <dir> [--instances <dir>] [--web name=url,…]')
const now = Date.now()

// --- The roster -----------------------------------------------------------------------------------

const manifests = []
for (const name of readdirSync(INSTANCES).filter(n => /^[a-z0-9][a-z0-9-]*\.json$/.test(n)).sort()) {
  try { manifests.push(readManifest(INSTANCES, name.slice(0, -5))) } catch (e) { console.error(`nvoy-status: ${name} skipped: ${e.message}`) }
}
// Like attention's NVOY_RELAYS: one relay set for every broker, for a test against local relays.
const override = process.env.NVOY_STATUS_RELAYS?.split(',').map(s => s.trim()).filter(Boolean)
const relaysOf = m => override || m.relays
const allRelays = [...new Set(manifests.flatMap(relaysOf))]
const labelOf = new Map(allRelays.map((url, i) => [url, relayLabel(url, i)]))
const names = new Map()
for (const m of manifests) for (const e of m.mayPost?.mention || []) if (e.name) names.set(e.pubkey, e.name)
for (const m of manifests) names.set(m.pubkey, m.id)

// --- Relays: one REQ each for every grant and revocation by any manifest grantor ------------------

const grantors = [...new Set(manifests.flatMap(m => m.grantors))]
function ask(url) {
  return new Promise(done => {
    const started = Date.now(), events = []
    let ws, finished = false
    const finish = answered => { if (finished) return; finished = true; clearTimeout(timer); try { ws?.close() } catch {} ; done({ url, answered, ms: Date.now() - started, events }) }
    const timer = setTimeout(() => finish(false), TIMEOUT_MS)
    try { ws = new WebSocket(url) } catch { return finish(false) }
    ws.onopen = () => ws.send(JSON.stringify(['REQ', 'status', { kinds: [440, 441], authors: grantors, limit: 2000 }]))
    ws.onmessage = m => {
      let d; try { d = JSON.parse(m.data) } catch { return }
      if (d[0] === 'EVENT' && d[2]) events.push(d[2])
      if (d[0] === 'EOSE') finish(true)
      if (d[0] === 'CLOSED') finish(false)
    }
    ws.onerror = () => finish(false)
  })
}
const answers = grantors.length ? await Promise.all(allRelays.map(ask)) : []
const heldBy = new Map()
for (const a of answers) for (const ev of a.events) {
  if (!heldBy.has(ev.id)) heldBy.set(ev.id, new Set())
  heldBy.get(ev.id).add(labelOf.get(a.url))
}
const events = answers.flatMap(a => a.events)
const grid = grantGrid({ events, heldBy, names,
  targets: manifests.map(m => ({ id: m.id, pubkey: m.pubkey, grantors: m.grantors, relays: relaysOf(m).map(u => labelOf.get(u)) })) })
// The retention canary: the newest grant some broker would honour right now.
const liveIds = new Set(grid.rows.flatMap(r => r.cells.filter(c => c.state === 'active').map(c => c.grant)))
const newest = events.filter(ev => ev.kind === 440 && liveIds.has(ev.id.slice(0, 8))).sort((a, b) => b.created_at - a.created_at)[0]
const relays = relayChecks(answers.map(a => ({ label: labelOf.get(a.url), answered: a.answered, ms: a.ms, ids: new Set(a.events.map(ev => ev.id)) })), newest?.id)

// --- Agents, from the host's facts ----------------------------------------------------------------

const containers = read(join(FACTS, 'containers.txt')).split('\n').filter(Boolean).map(line => {
  const [name, running, startedAt, restarts] = line.replace(/^\//, '').split('|')
  const m = name.match(/^nvoy-([a-z0-9-]+?)-(init|watcher|broker|adapter|notifier|door)(?:-\d+)?$/)
  return m && { instance: m[1], role: m[2], running: running === 'true', startedAt, restarts: Number(restarts) || 0, name }
}).filter(Boolean)
const channels = new Map()
for (const line of read(join(FACTS, 'channels.txt')).split('\n')) {
  const m = line.match(/^\s*(\d+)\s+\S+\.mjs --instance ([a-z0-9-]+)$/)
  if (m) channels.set(m[2], (channels.get(m[2]) || 0) + Number(m[1]))
}
const logOf = (id, role) => parseLog(read(join(FACTS, 'logs', `nvoy-${id}-${role}-1.log`)))
const agents = manifests.map((m, i) => agentChecks({
  manifest: m, now, watcher: logOf(m.id, 'watcher'), broker: logOf(m.id, 'broker'),
  containers: containers.filter(c => c.instance === m.id && c.role !== 'init'), channels: channels.get(m.id) || 0,
  grant: answers.some(a => a.answered) ? gridColumn(grid, i) : null,
}))

// --- Platform and web -----------------------------------------------------------------------------

const host = {}
for (const line of read(join(FACTS, 'host.txt')).split('\n')) {
  const [k, v] = line.split('=')
  if (k && v !== undefined && /^\d+(\.\d+)?$/.test(v.trim())) host[k.trim()] = Number(v.trim())
}
const deployDir = join(FACTS, 'deploy')
let remote = {}
try { remote = JSON.parse(read(join(deployDir, 'REMOTE_HEAD.json'), '{}')) } catch {}
const deploy = { timerActive: read(join(deployDir, 'timer')).trim() === 'active', deployedSha: read(join(deployDir, 'DEPLOYED_SHA')).trim(),
  lastOutcome: read(join(deployDir, 'LAST_OUTCOME')).trim(), remoteHead: remote.head || '', settled: remote.settled === true }
let prev = {}
try { prev = JSON.parse(read(join(STATE, 'collector-state.json'), '{}')) } catch {}
const platform = platformChecks({ host: { uptimeSec: host.uptime_sec, diskPct: host.disk_pct, memAvailPct: host.mem_avail_pct }, deploy, prev, now })

function probe(url) {
  return new Promise(done => {
    let u, sock, tlsDays = null
    try { u = new URL(url) } catch { return done({ error: 'bad address' }) }
    const timer = setTimeout(() => { sock?.destroy(); done({ error: 'timeout' }) }, TIMEOUT_MS)
    const opts = { host: u.hostname, port: Number(u.port) || 443, ...(isIP(u.hostname) ? {} : { servername: u.hostname }) }
    try { sock = connect(opts, () => {
      const valid = Date.parse(sock.getPeerCertificate()?.valid_to || '')
      if (Number.isFinite(valid)) tlsDays = Math.floor((valid - Date.now()) / 86400000)
      sock.write(`HEAD ${u.pathname || '/'} HTTP/1.1\r\nHost: ${u.host}\r\nUser-Agent: nvoy-status/1\r\nConnection: close\r\n\r\n`)
    }) } catch { clearTimeout(timer); return done({ error: 'connection failed' }) }
    let head = ''
    sock.on('data', d => { head += d; const m = head.match(/^HTTP\/1\.[01] (\d{3})/); if (m) { clearTimeout(timer); sock.destroy(); done({ status: Number(m[1]), tlsDays }) } })
    sock.on('error', e => { clearTimeout(timer); done({ error: e.code === 'ENOTFOUND' ? 'name not found' : e.code === 'ECONNREFUSED' ? 'refused' : /CERT|SSL|TLS/.test(e.code || '') ? 'certificate rejected' : 'connection failed' }) })
  })
}
const web = await Promise.all(WEB.map(async ([name, url]) => webCheck(name, await probe(url))))

// --- The snapshot ---------------------------------------------------------------------------------

const snapshot = {
  version: 1, generated_at: new Date(now).toISOString(), release: deploy.deployedSha.slice(0, 12) || null,
  overall: worst([...agents.map(a => a.colour), ...relays.map(r => r.colour), ...platform.checks.map(c => c.colour), ...web.map(c => c.colour)]),
  agents, relays, grants: grid, platform: platform.checks, web,
}
const findings = sanitiserFindings(snapshot)
let published = snapshot
if (findings.length) {
  // The paths go to the journal, which only root reads; the values go nowhere.
  for (const f of findings) console.error(`nvoy-status: withheld: ${f.what} at ${f.path}`)
  published = { version: 1, generated_at: snapshot.generated_at, release: snapshot.release, overall: 'red', withheld: true,
    reason: `this snapshot failed its own sanitiser (${findings.length} finding(s)), so none of it was published` }
}

const atomic = (path, text) => { const tmp = `${path}.${process.pid}.tmp`; writeFileSync(tmp, text, { mode: 0o644 }); renameSync(tmp, path) }
mkdirSync(OUT, { recursive: true }); mkdirSync(STATE, { recursive: true })
for (const file of ['index.html', 'status-view.mjs']) copyFileSync(join(PAGE, file), join(OUT, file))
atomic(join(OUT, 'status.json'), JSON.stringify(published, null, 1) + '\n')
atomic(join(STATE, 'collector-state.json'), JSON.stringify(platform.state) + '\n')
console.log(`nvoy-status: ${published.overall}${published.withheld ? ' (withheld)' : ''} — ${agents.map(a => `${a.id}=${a.colour}`).join(' ')}`)
