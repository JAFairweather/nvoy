// Presence (waggle #721 step 4): counting, judging, deciding. The claim must be as strong as its
// evidence, so every case below that proves "connected" sits beside one that must NOT.
import { keyFingerprint } from '../mcp/tools/participant_unit.mjs'
import { parseChannelArgv, countSessions, buildSnapshot, presenceVerdict, nextPresence, presenceTemplate,
  PRESENCE_D, PRESENCE_TTL_SEC, PRESENCE_REFRESH_SEC, SNAPSHOT_MAX_AGE_SEC } from '../mcp/tools/presence.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }

const m = { id: 'curator', workerUid: 41014 }
const CID = 'a'.repeat(64), OTHER = 'b'.repeat(64)
const FPA = keyFingerprint(Buffer.alloc(51, 1).toString('base64'))
const FPB = keyFingerprint(Buffer.alloc(51, 2).toString('base64'))
const base = ['/usr/local/bin/node', '/srv/nvoy/mcp/tools/claude-channel.mjs', '--instance', 'curator']
const proc = (argv, over = {}) => ({ pid: 1, uid: 41014, cgroup: `0::/system.slice/docker-${CID}.scope`, argv, ...over })
const tagged = fp => proc([...base, '--key-fp', fp])
const now = Date.UTC(2026, 10, 8, 21, 0, 0)

// ---- argv: exact, complete ----
ok('a tagged channel argv names its key', parseChannelArgv([...base, '--key-fp', FPA], m)?.fp === FPA)
ok('an older argv is accepted as untagged', parseChannelArgv(base, m)?.fp === '')
ok('another instance does not parse', parseChannelArgv(base.map(v => v === 'curator' ? 'other' : v), m) === null)
ok('a malformed fingerprint does not parse', parseChannelArgv([...base, '--key-fp', 'SHA256:short'], m) === null)
ok('an extra argument does not parse', parseChannelArgv([...base, '--key-fp', FPA, '--baseline'], m) === null)
ok('a wrapper that only mentions the words does not parse', parseChannelArgv(['/bin/sh', '-c', base.join(' ') + ' --key-fp ' + FPA], m) === null)

// ---- counting: container, uid, argv ----
const good = [tagged(FPA), tagged(FPA), proc(base), tagged(FPB)]
const c = countSessions(good, m, CID)
ok('parallel sessions are counted per key', c.byFp[FPA] === 2 && c.byFp[FPB] === 1 && c.untagged === 1)
ok('a process in another container does not count', countSessions([tagged(FPA), proc([...base, '--key-fp', FPA], { cgroup: `0::/docker-${OTHER}.scope` })], m, CID).byFp[FPA] === 1)
ok('a host process with matching words, outside the container, does not count', countSessions([proc([...base, '--key-fp', FPA], { cgroup: '0::/user.slice/session-3.scope' })], m, CID).counted === 0)
ok('a process under another uid does not count', countSessions([proc([...base, '--key-fp', FPA], { uid: 0 })], m, CID).counted === 0)
ok('no container id counts nothing', countSessions(good, m, '').counted === 0)

// ---- snapshot and verdict ----
const snap = (procs, over = {}) => ({ ...buildSnapshot({ manifest: m, procs, containerId: CID, keyFp: FPA, now }), ...over })
const v = (s, at = now) => presenceVerdict(s, { instance: 'curator', fp: FPA, now: at })
ok('connect: a bound session reads connected', v(snap([tagged(FPA)])).state === 'connected')
ok('parallel: two bound sessions read connected', v(snap([tagged(FPA), tagged(FPA)])).sessions === 2)
ok('last drop: a fresh snapshot with nothing reads disconnected', v(snap([])).state === 'disconnected')
ok('a session of another key is not this key', v(snap([tagged(FPB)])).state === 'disconnected')
ok('old session: only untagged is unproven, never connected and never disconnected', v(snap([proc(base)])).state === 'unproven')
ok('old session beside a bound one is still connected', v(snap([proc(base), tagged(FPA)])).state === 'connected')
ok('a stale snapshot is unproven, so a collector outage is not a last disconnect', v(snap([]), now + (SNAPSHOT_MAX_AGE_SEC + 1) * 1000).state === 'unproven')
ok('a missing snapshot is unproven', v(null).state === 'unproven')
ok('a snapshot for another instance is unproven', v(snap([], { instance: 'other' })).state === 'unproven')
ok('a snapshot naming another key is unproven', v(snap([], { key_fp: FPB })).state === 'unproven')
ok('an unfound adapter container is unproven, not disconnected', v(buildSnapshot({ manifest: m, procs: [], containerId: '', keyFp: FPA, now })).state === 'unproven')
ok('a seat with no fingerprint is unproven', presenceVerdict(snap([tagged(FPA)]), { instance: 'curator', fp: '', now }).state === 'unproven')

// ---- decisions: connect, drop, restart, refresh ----
const sec = Math.floor(now / 1000)
const connect = nextPresence(null, { state: 'connected' }, now)
ok('first connect owes an event with since = now', connect.connected === true && connect.since === sec)
const rec = r => ({ connected: r.connected, since: r.since, event_at: r.seen_at })
ok('an unchanged connected state owes nothing inside the refresh window', nextPresence(rec(connect), { state: 'connected' }, now + 60000) === null)
const refreshed = nextPresence(rec(connect), { state: 'connected' }, now + (PRESENCE_REFRESH_SEC + 1) * 1000)
ok('it is re-signed before the 2 h expiry, keeping its since', refreshed.connected === true && refreshed.since === sec)
ok('the refresh window sits well inside the expiry', PRESENCE_REFRESH_SEC * 2 <= PRESENCE_TTL_SEC)
const drop = nextPresence(rec(connect), { state: 'disconnected' }, now + 120000)
ok('last drop owes connected:false with a new since', drop.connected === false && drop.since === sec + 120)
ok('unproven owes nothing even after a connected record', nextPresence(rec(connect), { state: 'unproven' }, now + 3600000) === null)
const restart = nextPresence(rec(drop), { state: 'connected' }, now + 300000)
ok('restart: reconnect after a drop owes a fresh since', restart.connected === true && restart.since === sec + 300)

// ---- the event ----
const t1 = presenceTemplate({ instance: 'curator', fp: FPA, ...{ connected: true, since: sec, seenAt: sec } }, now, 0)
ok('template is kind 30078 with the presence d tag and a 2 h expiration', t1.kind === 30078 && t1.tags[0][1] === PRESENCE_D && Number(t1.tags[1][1]) === t1.created_at + PRESENCE_TTL_SEC)
ok('content carries exactly the contract fields', JSON.stringify(Object.keys(JSON.parse(t1.content))) === JSON.stringify(['instance', 'key', 'connected', 'since', 'seen_at']))
const t2 = presenceTemplate({ instance: 'curator', fp: FPA, connected: false, since: sec, seenAt: sec }, now, t1.created_at)
ok('a same-second newer state is stamped strictly after the last event', t2.created_at === t1.created_at + 1)

// ---- the collector, against a fake /proc ----
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readProcs, installedFingerprint, collect } from '../mcp/tools/presence-collect.mjs'
import { principalLine } from '../mcp/tools/participant_unit.mjs'

const tmp = mkdtempSync(join(tmpdir(), 'presence-'))
const fakeProc = join(tmp, 'proc'); mkdirSync(fakeProc)
const addProc = (pid, argv, uid, cgroup) => {
  const d = join(fakeProc, String(pid)); mkdirSync(d)
  writeFileSync(join(d, 'cmdline'), argv.join('\0') + '\0')
  writeFileSync(join(d, 'status'), `Name:\tnode\nUid:\t${uid}\t${uid}\t${uid}\t${uid}\n`)
  writeFileSync(join(d, 'cgroup'), cgroup)
}
addProc(100, [...base, '--key-fp', FPA], 41014, `0::/system.slice/docker-${CID}.scope\n`)
addProc(101, ['/bin/sh', '-c', `echo ${base.join(' ')} --key-fp ${FPA}`], 1000, '0::/user.slice\n')
addProc(102, [...base, '--key-fp', FPA], 41014, '0::/user.slice/host.scope\n')
const read = readProcs(fakeProc)
ok('readProcs parses cmdline, real uid and cgroup', read.length === 3 && read[0].argv.length === 6 && read[0].uid === 41014)
ok('only the process in the adapter container with the worker uid counts', countSessions(read, m, CID).counted === 1)

const man = { id: 'curator', workerUid: 41014, workerHandoffGid: 41002, adapterContainer: 'nvoy-curator-adapter-1' }
const body = Buffer.alloc(51, 5).toString('base64')
const line = principalLine(man, 'ssh-ed25519', body)
ok('the installed tagged line yields its own key fingerprint', installedFingerprint(line + '\n', man) === keyFingerprint(body))
ok('an older line yields no fingerprint, so presence stays unproven', installedFingerprint(line.replace(/ --key-fp [^"]+/, '') + '\n', man) === '')
ok('two lines under one comment yield none (ambiguous)', installedFingerprint(line + '\n' + line + '\n', man) === '')

const insts = join(tmp, 'instances'); mkdirSync(insts)
const writeManifest = () => writeFileSync(join(insts, 'curator.json'), JSON.stringify({
  version: 1, id: 'curator', pubkey: 'a'.repeat(64), state_dir: join(tmp, 's'), runtime_dir: join(tmp, 'r'), spool_dir: join(tmp, 'sp'),
  bunker_uri_ref: '/x/b', bunker_client_ref: '/x/c', broker_adapter_gid: 41001, worker_handoff_gid: 41002,
  watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014, delivery_mode: 'notify_only', worker_enabled: false,
  adapter_container: 'nvoy-curator-adapter-1', grantors: ['b'.repeat(64)], relays: ['wss://nos.lol'] }))
writeManifest()
const keys = join(tmp, 'authorized_keys'); writeFileSync(keys, line + '\n')
// bind the fake process to the instance's real key
const FPK = keyFingerprint(body)
addProc(103, [...base, '--key-fp', FPK], 41014, `0::/docker-${CID}.scope\n`)
const outDir = join(tmp, 'out')
let wrote = []
try { wrote = collect({ instances: insts, out: outDir, keysPath: keys, procRoot: fakeProc, containerId: () => CID, now }) } catch (e) { console.log('collect threw', e.message) }
const written = wrote.length ? JSON.parse(readFileSync(join(outDir, 'curator.json'), 'utf8')) : null
ok('collect writes a snapshot for the instance', wrote[0] === 'curator' && written?.instance === 'curator')
ok('the snapshot counts the bound session and names the key', written?.bound === 1 && written?.key_fp === FPK)
ok('the broker can judge it connected', presenceVerdict(written, { instance: 'curator', fp: FPK, now }).state === 'connected')
const gone = collect({ instances: insts, out: outDir, keysPath: keys, procRoot: fakeProc, containerId: () => '', now })
ok('an unfound container is written as such, not as a disconnect', presenceVerdict(JSON.parse(readFileSync(join(outDir, 'curator.json'), 'utf8')), { instance: 'curator', fp: FPK, now }).state === 'unproven' && gone.length === 1)

console.log(fails ? `presence: ${fails} FAILED` : 'presence: all passed')
process.exit(fails ? 1 : 0)
