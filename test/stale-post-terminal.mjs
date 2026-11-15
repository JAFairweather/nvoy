// Stale frozen post terminal disposition (q-169): when Buzz refuses a frozen post record with
// deterministic "invalid: event timestamp too far from server time" and the frozen created_at is
// not in the future, instance-broker-daemon records it in terminal-posts.jsonl and preserves
// posts/<id>.json + audit logs without retrying forever, while transient relay errors and non-stale
// refusals remain retryable and publish once the relay recovers.

import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import {
  STALE_POST_TERMINAL_LINE,
  isStalePostTimestampRefusal,
  isTerminalPostFailure,
  terminalPostReason,
} from '../mcp/tools/agent_post.mjs'
import { channelPost } from '../mcp/tools/buzz_native.mjs'
import { replyRequestDigest } from '../mcp/tools/outbound_record.mjs'
import { postPublished } from '../mcp/tools/broker_done.mjs'

let fails = 0
const ok = (name, value, detail = '') => {
  console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}${value || !detail ? '' : ` (${detail})`}`)
  if (!value) fails++
}
const sleep = ms => new Promise(r => setTimeout(r, ms))
const until = async (fn, ms = 25000) => {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if (fn()) return true
    await sleep(100)
  }
  return false
}
const hex = n => randomBytes(n).toString('hex')

// --- 1. pure terminal-classification rules ---
const nowSec = 1_794_760_000
ok('exact stale-timestamp refusal on a past frozen post is terminal',
  isStalePostTimestampRefusal('invalid: event timestamp too far from server time', nowSec - 72_000, nowSec))
ok('exact stale-timestamp refusal at current second is terminal',
  isStalePostTimestampRefusal('invalid: event timestamp too far from server time', nowSec, nowSec))
ok('future-stamped frozen post is NOT terminal (waiting can bring server clock into range)',
  !isStalePostTimestampRefusal('invalid: event timestamp too far from server time', nowSec + 60, nowSec))
ok('other Buzz refusals and transient relay errors are NOT stale-timestamp terminal',
  !isStalePostTimestampRefusal('rate-limited: slow down', nowSec - 72_000, nowSec) &&
  !isStalePostTimestampRefusal('error: temporary backend error', nowSec - 72_000, nowSec) &&
  !isStalePostTimestampRefusal('invalid: event id mismatch', nowSec - 72_000, nowSec) &&
  !isStalePostTimestampRefusal('', nowSec - 72_000, nowSec))
ok('daemon terminal classifier matches stale-post line and maps bounded reason',
  isTerminalPostFailure(`instance-broker-post: ${STALE_POST_TERMINAL_LINE}`) &&
  terminalPostReason(`instance-broker-post: ${STALE_POST_TERMINAL_LINE}`) === 'stale-event-timestamp' &&
  !isTerminalPostFailure('instance-broker-post: Buzz relay unavailable: socket closed\ninstance-broker-post: the Buzz relay did not accept the persisted post; it remains retryable') &&
  !isTerminalPostFailure('instance-broker-post: Buzz refused the post: rate-limited: slow down\ninstance-broker-post: the Buzz relay did not accept the persisted post; it remains retryable'))

// --- 2. end-to-end daemon + actuator + Buzz-shaped relay over 4 stale Curator records + 2 transient items ---
const CH = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const neil = getPublicKey(generateSecretKey())
const grantor = getPublicKey(generateSecretKey())

const eventAttempts = new Map()
const contentAttempts = new Map()
const stored = []

const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const buzz = new WebSocketServer({ server: http })
buzz.on('connection', ws => {
  const challenge = hex(32)
  let authed = null
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      const ev = m[1], tag = n => ev.tags.find(t => t[0] === n)?.[1]
      if (!(verifyEvent(ev) && tag('challenge') === challenge && tag('relay') === RELAY && ev.pubkey === agent)) {
        return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      }
      authed = ev.pubkey
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'EVENT') {
      const ev = m[1]
      if (!authed || ev.pubkey !== authed || !verifyEvent(ev)) {
        return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      }
      eventAttempts.set(ev.id, (eventAttempts.get(ev.id) || 0) + 1)
      const cCount = (contentAttempts.get(ev.content) || 0) + 1
      contentAttempts.set(ev.content, cCount)

      // Deterministic stale-timestamp refusal as Buzz emits for old frozen events:
      if (Math.abs(Math.floor(Date.now() / 1000) - ev.created_at) > 900) {
        return ws.send(JSON.stringify(['OK', ev.id, false, 'invalid: event timestamp too far from server time']))
      }
      // Simulate transient abrupt disconnect on attempt 1 of the drop-once fresh post:
      if (ev.content === 'CANARY_FRESH_DROP_ONCE' && cCount === 1) {
        ws.close()
        return
      }
      // Simulate non-terminal relay refusal on attempt 1 of the rate-limited fresh post:
      if (ev.content === 'CANARY_FRESH_RATELIMIT_ONCE' && cCount === 1) {
        return ws.send(JSON.stringify(['OK', ev.id, false, 'rate-limited: slow down']))
      }
      if (!stored.some(s => s.id === ev.id)) stored.push(ev)
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
  })
})

const work = mkdtempSync(join(tmpdir(), 'nvoy-q169-'))
const instances = join(work, 'instances')
const state = join(work, 'state')
const run = join(work, 'run')
const spool = join(work, 'spool')
for (const d of [instances, state, run, spool, join(state, 'posts')]) mkdirSync(d, { recursive: true, mode: 0o700 })

const gid = process.getgid(), uid = process.getuid()
writeFileSync(join(instances, 'curator.json'), JSON.stringify({
  version: 1,
  id: 'curator',
  pubkey: agent,
  broker_mode: 'local',
  key_ref: '/etc/nvoy/credentials/curator.nsec',
  worker_enabled: false,
  delivery_mode: 'notify_only',
  state_dir: state,
  runtime_dir: run,
  spool_dir: spool,
  broker_adapter_gid: gid,
  worker_handoff_gid: gid + 1,
  watcher_uid: uid + 11,
  broker_uid: uid + 12,
  adapter_uid: uid + 13,
  worker_uid: uid + 14,
  grantors: [grantor],
  relays: ['wss://127.0.0.1:1'],
  buzz: { relay: RELAY, channels: [CH] },
  may_post: { channels: [CH], per_hour: 20, mention: [{ name: 'neil', pubkey: neil }] },
}))
const credential = join(work, 'curator.key')
writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })

const staleCreatedSec = Math.floor(Date.now() / 1000) - 36 * 3600
const staleRows = Array.from({ length: 4 }, (_, idx) => {
  const row = {
    version: 1,
    type: 'post-request',
    id: `${idx + 1}`.repeat(32),
    instance: 'curator',
    channel: CH,
    mention: [neil],
    content: `CANARY_STALE_POST_BODY_${idx + 1}`,
    requested_at: staleCreatedSec * 1000,
  }
  const unsignedEvent = {
    pubkey: agent,
    ...channelPost({ channel: CH, content: row.content, mentions: row.mention }),
    created_at: staleCreatedSec + idx,
  }
  const signed = finalizeEvent({ ...unsignedEvent }, agentSk)
  const record = {
    version: 1,
    request_id: row.id,
    request_digest: replyRequestDigest(row),
    fingerprint: getEventHash(unsignedEvent),
    unsigned_event: unsignedEvent,
    event: signed,
    published: false,
  }
  const rawRecord = JSON.stringify(record)
  writeFileSync(join(state, 'posts', `${row.id}.json`), rawRecord, { mode: 0o600 })
  return { row, eventId: signed.id, rawRecord }
})

const dropRow = {
  version: 1,
  type: 'post-request',
  id: 'a'.repeat(32),
  instance: 'curator',
  channel: CH,
  mention: [neil],
  content: 'CANARY_FRESH_DROP_ONCE',
  requested_at: Date.now(),
}
const rateLimitRow = {
  version: 1,
  type: 'post-request',
  id: 'b'.repeat(32),
  instance: 'curator',
  channel: CH,
  mention: [],
  content: 'CANARY_FRESH_RATELIMIT_ONCE',
  requested_at: Date.now(),
}

writeFileSync(
  join(run, 'post-requests.jsonl'),
  [...staleRows.map(s => s.row), dropRow, rateLimitRow].map(r => JSON.stringify(r)).join('\n') + '\n',
  { mode: 0o640 },
)

const hook = join(work, 'spawn-log.mjs')
const spawnLog = join(work, 'spawns.jsonl')
writeFileSync(hook, `import cp from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { appendFileSync } from 'node:fs'
for (const name of ['spawn', 'spawnSync']) {
  const real = cp[name]
  cp[name] = (cmd, args, ...rest) => {
    appendFileSync(${JSON.stringify(spawnLog)}, JSON.stringify((args || []).map(String)) + '\\n')
    return real(cmd, args, ...rest)
  }
}
syncBuiltinESMExports()
`)
writeFileSync(spawnLog, '')
const spawned = () => readFileSync(spawnLog, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
const postSpawnsFor = id => spawned().filter(a => a[0].endsWith('instance-broker-post.mjs') && a.includes(id)).length

let daemonOut = '', daemonErr = ''
try {
  const daemon = spawn(process.execPath, ['--import', hook, 'mcp/tools/instance-broker-daemon.mjs', '--instance', 'curator'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
    env: {
      PATH: process.env.PATH,
      NVOY_INSTANCE_ROOT: instances,
      NVOY_BROKER_CREDENTIAL: credential,
      NVOY_PRESENCE_DIR: join(work, 'no-presence'),
    },
  })
  daemon.stdout.on('data', c => { daemonOut += c })
  daemon.stderr.on('data', c => { daemonErr += c })

  // Wait until all 4 stale records are marked terminal AND both transient fresh posts retry and publish (backoff first step is 5s).
  const converged = await until(
    () =>
      existsSync(join(state, 'terminal-posts.jsonl')) &&
      readFileSync(join(state, 'terminal-posts.jsonl'), 'utf8').trim().split('\n').filter(Boolean).length === 4 &&
      postPublished(state, dropRow) &&
      postPublished(state, rateLimitRow),
    25000,
  )
  // Wait 2.5s more (two additional drainPosts ticks) to prove none of the 4 stale records retry.
  await sleep(2500)
  try { process.kill(-daemon.pid, 'SIGKILL') } catch { /* gone */ }
  await sleep(300)

  ok('daemon marks all 4 stale posts terminal and publishes both retryable fresh posts', converged, daemonErr)

  const terminalRaw = existsSync(join(state, 'terminal-posts.jsonl')) ? readFileSync(join(state, 'terminal-posts.jsonl'), 'utf8') : ''
  const terminalRows = terminalRaw.trim().split('\n').filter(Boolean).map(l => JSON.parse(l))
  ok('terminal-posts.jsonl records exactly the 4 stale ids with stale-event-timestamp reason and zero message bodies',
    terminalRows.length === 4 &&
    staleRows.every(s => terminalRows.some(t => t.type === 'terminal-post' && t.id === s.row.id && t.reason === 'stale-event-timestamp')) &&
    !terminalRaw.includes('CANARY_'))

  ok('each of the 4 stale frozen events was sent to the relay once and never retried on later ticks',
    staleRows.every(s => eventAttempts.get(s.eventId) === 1 && postSpawnsFor(s.row.id) === 1))

  ok('all 4 frozen post records in state/posts/<id>.json remain intact and unpublished for audit',
    staleRows.every(s => readFileSync(join(state, 'posts', `${s.row.id}.json`), 'utf8') === s.rawRecord && !postPublished(state, s.row)))

  ok('transient relay disconnect and rate-limited refusal stayed retryable (held for retry) and published on retry',
    contentAttempts.get('CANARY_FRESH_DROP_ONCE') === 2 &&
    contentAttempts.get('CANARY_FRESH_RATELIMIT_ONCE') === 2 &&
    stored.some(ev => ev.content === 'CANARY_FRESH_DROP_ONCE') &&
    stored.some(ev => ev.content === 'CANARY_FRESH_RATELIMIT_ONCE') &&
    new RegExp(`post ${dropRow.id.slice(0, 12)}… held for retry:`).test(daemonErr) &&
    new RegExp(`post ${rateLimitRow.id.slice(0, 12)}… held for retry:`).test(daemonErr))

  ok('daemon audit logs record terminal disposition for all 4 stale ids without leaking post content',
    staleRows.every(s => new RegExp(`post ${s.row.id.slice(0, 12)}… terminal:.*stale timestamp`).test(daemonErr)) &&
    !`${daemonOut}\n${daemonErr}`.includes('CANARY_'))

  // Restart daemon over the resulting state: zero children should spawn for the 4 terminal posts or 2 published posts!
  writeFileSync(spawnLog, '')
  let restartErr = ''
  const daemon2 = spawn(process.execPath, ['--import', hook, 'mcp/tools/instance-broker-daemon.mjs', '--instance', 'curator'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
    env: {
      PATH: process.env.PATH,
      NVOY_INSTANCE_ROOT: instances,
      NVOY_BROKER_CREDENTIAL: credential,
      NVOY_PRESENCE_DIR: join(work, 'no-presence'),
    },
  })
  daemon2.stderr.on('data', c => { restartErr += c })
  await sleep(2500)
  try { process.kill(-daemon2.pid, 'SIGKILL') } catch { /* gone */ }
  await sleep(300)

  ok('across daemon restart, zero post children spawn for the 4 terminal stale records or 2 published posts',
    [...staleRows.map(s => s.row.id), dropRow.id, rateLimitRow.id].every(id => postSpawnsFor(id) === 0),
    restartErr)
} finally {
  buzz.close()
  await new Promise(r => http.close(r))
  rmSync(work, { recursive: true, force: true })
}

if (fails > 0) process.exit(1)
console.log('ALL stale-post-terminal checks passed')
