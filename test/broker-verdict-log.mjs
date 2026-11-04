// The broker daemon prints the native child's verdict (status S0, fix 1). It used to drop a
// child's output whenever the child succeeded, so neither "admitted" nor "heard as data only"
// ever reached the container log, and the 10-19 outage took hours to see. The daemon now forwards
// the child's own verdict lines, bounded, and never a message body.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { childVerdict } from '../mcp/tools/broker_verdict.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const until = async (fn, ms = 20000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100) } return false }

// --- the filter ---
{
  const v = childVerdict({ stdout: 'instance-broker-native: 0123456789ab… admitted from 1a2b3c4d (task)\n',
    stderr: 'instance-broker-native: status[👀] 0123456789ab failed: fact-unrecorded (EACCES)\n' })
  ok('verdict lines from stdout and stderr are both kept', v.length === 2 && /admitted from 1a2b3c4d/.test(v[0]) && /fact-unrecorded/.test(v[1]))
  ok('the wrapped-mail broker\'s lines are kept too', childVerdict({ stderr: 'instance-broker: abc… yielded no message for this identity' }).length === 1)
  const foreign = childVerdict({ stdout: '=== ACTIONABLE (1) ===\n  [2026-10-19] npub1abc…\n    please deploy the thing\n',
    stderr: 'file:///x.mjs:1\nError: boom\n    at foo (x.mjs:1:1)' })
  ok('anything that is not the child\'s own verdict line is dropped, message text included', foreign.length === 0)
  ok('a line is kept only when the prefix starts it', childVerdict({ stdout: 'quoted: instance-broker-native: x' }).length === 0)
  const flood = childVerdict({ stderr: Array.from({ length: 50 }, (_, i) => `instance-broker: line ${i} ${'x'.repeat(1000)}`).join('\n') })
  ok('at most four lines are forwarded', flood.length === 4)
  ok('each line is cut to 240 characters', flood.every(l => l.length === 240 && l.endsWith('…')))
  ok('control characters cannot forge a second log line', childVerdict({ stdout: 'instance-broker: a\r\u001b[2Kfake' })[0] === 'instance-broker: a[2Kfake')
  ok('no output is no verdict', childVerdict({}).length === 0 && childVerdict({ stdout: null, stderr: undefined }).length === 0)
}

// --- the daemon, end to end: a Buzz-shaped relay, a native child, and its verdict in the log ---
const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const humanSk = generateSecretKey()
const stored = []
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const wss = new WebSocketServer({ server: http })
wss.on('connection', ws => {
  const challenge = Buffer.from(generateSecretKey()).toString('hex')
  let authed = false
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') { authed = verifyEvent(m[1]) && m[1].pubkey === agent; return ws.send(JSON.stringify(['OK', m[1].id, authed, ''])) }
    if (m[0] === 'REQ') {
      if (!authed) return ws.send(JSON.stringify(['CLOSED', m[1], 'auth-required']))
      for (const ev of stored) if (m.slice(2).some(f => !f.ids || f.ids.includes(ev.id))) ws.send(JSON.stringify(['EVENT', m[1], ev]))
      ws.send(JSON.stringify(['EOSE', m[1]]))
    }
  })
})
const BODY = 'the body of this message must never reach a log'
const chatter = finalizeEvent({ kind: 9, created_at: Math.floor(Date.now() / 1000), content: BODY, tags: [['h', CH]] }, humanSk)
const mention = finalizeEvent({ kind: 9, created_at: Math.floor(Date.now() / 1000), content: BODY, tags: [['h', CH], ['p', agent]] }, humanSk)
stored.push(chatter, mention)
const ghost = 'f'.repeat(64)

const root = mkdtempSync(join(tmpdir(), 'nvoy-broker-verdict-'))
const instances = join(root, 'instances', 'verdict')
for (const d of ['state', 'run', 'spool']) mkdirSync(join(root, d), { mode: 0o700 })
mkdirSync(instances, { recursive: true })
const gid = process.getgid(), otherGid = process.getgroups().find(g => g !== gid)
writeFileSync(join(instances, 'verdict.json'), JSON.stringify({ version: 1, id: 'verdict', pubkey: agent, worker_enabled: false,
  key_ref: '/etc/nvoy/credentials/verdict.nsec', state_dir: join(root, 'state'), runtime_dir: join(root, 'run'), spool_dir: join(root, 'spool'),
  broker_adapter_gid: gid, worker_handoff_gid: otherGid, watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'], relays: ['wss://127.0.0.1:1'],
  buzz: { relay: RELAY, channels: [CH] } }))
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })
const plant = id => writeFileSync(join(root, 'spool', `${id}.buzz.pending`), JSON.stringify({ observed_at: Date.now(), envelope: id }) + '\n', { mode: 0o660 })
for (const ev of [ghost, chatter.id, mention.id]) plant(ev)

let log = ''
const daemon = spawn(process.execPath, ['mcp/tools/instance-broker-daemon.mjs', '--instance', 'verdict'], { stdio: ['ignore', 'pipe', 'pipe'],
  env: { PATH: process.env.PATH, NVOY_INSTANCE_ROOT: instances, NVOY_BROKER_CREDENTIAL: credential } })
daemon.stdout.on('data', c => { log += c }); daemon.stderr.on('data', c => { log += c })
const line = re => log.split('\n').find(l => re.test(l)) || ''
ok('a successful terminal verdict reaches the daemon log', await until(() => line(new RegExp(`${ghost.slice(0, 12)}… is not stored`))))
ok('it is the child\'s own line, attributed through the daemon',
  /^instance-broker-daemon: instance-broker-native: f{12}… is not stored in any configured channel$/.test(line(/is not stored/)))
ok('a heard message that is not a mention says so', await until(() => line(new RegExp(`${chatter.id.slice(0, 12)}… is not a signed mention`))))
ok('a held message reports the child\'s reason and the relays it asked',
  await until(() => /held for retry: instance-broker-native: live grant policy unavailable \(relays relay#1=unanswered\); marker requeued/.test(line(new RegExp(`${mention.id.slice(0, 12)}… held`)))))
daemon.kill(); await sleep(200)
ok('no message body reaches the log', log.length > 0 && !log.includes(BODY))
ok('no relay address literal reaches the log', !/127\.0\.0\.1:1\b/.test(log))
wss.close(); http.close()

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
