// Multi-instance runtime contract (#44): a public manifest names exactly one identity and
// isolated state. This drives the real CLI, rather than duplicating its validation in a unit.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { spawn } from 'node:child_process'
import net from 'node:net'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-instance-'))
const key = generateSecretKey(), pubkey = getPublicKey(key)
const manifestRoot = join(root, 'instances')
mkdirSync(manifestRoot)
const manifestFile = join(manifestRoot, 'codex-test.json')
const manifest = { version: 1, id: 'codex-test', pubkey: nip19.npubEncode(pubkey),
  state_dir: join(root, 'state-codex'), runtime_dir: join(root, 'run-codex'), spool_dir: join(root, 'spool-codex'), shared_gid: process.getgid(),
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'], relays: ['wss://nos.lol', 'wss://relay.primal.net'] }
writeFileSync(manifestFile, JSON.stringify(manifest))
const cli = (...args) => spawnSync(process.execPath, ['mcp/tools/instance-runtime.mjs', ...args], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })

const good = cli('describe', '--instance', 'codex-test')
const described = JSON.parse(good.stdout || '{}')
ok('a valid instance manifest describes its public identity', good.status === 0 && described.recipient === pubkey)
ok('the description contains no private key reference', !/keyFile|nsec/.test(good.stdout))
ok('the instance receives its own state directory', described.stateDir === manifest.state_dir)

const watcherSource = readFileSync('mcp/tools/instance-runtime.mjs', 'utf8')
ok('the keyless watcher receives an explicit environment, not inherited process secrets', !/\.\.\.process\.env/.test(watcherSource) && !/NVOY_NSEC/.test(watcherSource))
const wakeSource = readFileSync('mcp/tools/keyless-wake-watcher.mjs', 'utf8')
ok('watcher writes the pending marker before advancing seen state', wakeSource.includes('`${id}.pending`') && wakeSource.includes('!seen.has(m[2].id) && record(m[2].id)) mark(m[2].id)'))
ok('watcher markers and adapter socket are group-limited to the matching broker', /chmodSync\(p, 0o660\)/.test(wakeSource) && /chmodSync\(socket, 0o660\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')))
ok('watcher cooldown coalesces notifications but never skips durable queueing', /function record\(id\)[\s\S]*appendFileSync[\s\S]*if \(now - lastWake < cooldown\) return true/.test(wakeSource))
const brokerSource = readFileSync('mcp/tools/instance-broker.mjs', 'utf8')
ok('broker atomically claims the exact pending marker before decrypting', /renameSync\(pendingMarker, markerPath\)/.test(brokerSource) && /--envelope', envelope/.test(brokerSource))
ok('a broker claims a per-state exclusive lock before decrypting', /openSync\(lockPath, 'wx'/.test(brokerSource) && /process\.kill\(prior\.pid, 0\)/.test(brokerSource))

const blocked = cli('attention', '--instance', 'codex-test')
ok('an adapter cannot invoke the keyed attention path', blocked.status !== 0 && /usage/.test(blocked.stderr))

const adapter = spawn(process.execPath, ['mcp/tools/instance-adapter.mjs', '--instance', 'codex-test'], {
  cwd: resolve('.'), env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot }, stdio: ['ignore', 'pipe', 'pipe']
})
let adapterLog = ''
adapter.stdout.on('data', d => { adapterLog += d })
adapter.stderr.on('data', d => { adapterLog += d })
const socket = join(manifest.runtime_dir, 'adapter.sock')
const waitFor = async (predicate, ms = 2000) => {
  const until = Date.now() + ms
  while (Date.now() < until) { if (predicate()) return true; await new Promise(r => setTimeout(r, 25)) }
  return false
}
const packet = { type: 'admitted-task', instance: 'codex-test', envelope: 'b'.repeat(64), messages: [{ from: 'a'.repeat(64), at: 1, content: 'only broker-admitted text' }] }
let ack = ''
const sendPacket = async () => {
  if (!await waitFor(() => existsSync(socket))) return
  await new Promise(resolveAck => {
    const client = net.createConnection(socket)
    client.on('connect', () => client.write(JSON.stringify(packet) + '\n'))
    client.on('data', data => { ack += data; client.end() })
    client.on('close', resolveAck)
    client.on('error', resolveAck)
  })
}
await sendPacket()
await sendPacket() // a redelivery after a broker crash must be acknowledgement-only
adapter.kill('SIGTERM')
if (!ack) console.error(`adapter diagnostic: ${adapterLog}`)
ok('the keyless adapter accepts only the bound instance packet and acknowledges it', /"type":"ack"/.test(ack) && /"instance":"codex-test"/.test(ack))
const admittedQueue = join(manifest.runtime_dir, 'admitted-tasks.jsonl')
ok('the adapter durably queues admitted plaintext before acknowledging', existsSync(admittedQueue) && readFileSync(admittedQueue, 'utf8').includes('only broker-admitted text'))
ok('a replayed envelope is acknowledged but never queued twice', existsSync(admittedQueue) && readFileSync(admittedQueue, 'utf8').trim().split('\n').length === 1)

writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...manifest, id: 'collision', runtime_dir: join(root, 'run-other') }))
const collision = cli('describe', '--instance', 'codex-test')
ok('duplicate participant pubkeys are refused before a runtime starts', collision.status !== 0 && /collision/.test(collision.stderr))

const symlinkRoot = join(root, 'symlink-instances')
mkdirSync(symlinkRoot)
mkdirSync(join(root, 'real-state'))
symlinkSync(join(root, 'real-state'), join(root, 'linked-state'))
writeFileSync(join(symlinkRoot, 'symlink-test.json'), JSON.stringify({ ...manifest, id: 'symlink-test', state_dir: join(root, 'linked-state'), runtime_dir: join(root, 'run-safe') }))
const symlinked = spawnSync(process.execPath, ['mcp/tools/instance-runtime.mjs', 'describe', '--instance', 'symlink-test'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: symlinkRoot } })
ok('symlinked state roots are refused before a runtime starts', symlinked.status !== 0 && /never a symlink/.test(symlinked.stderr))

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
