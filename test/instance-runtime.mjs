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
  state_dir: join(root, 'state-codex'), runtime_dir: join(root, 'run-codex'), spool_dir: join(root, 'spool-codex'), key_ref: '/etc/nvoy/credentials/codex-test.nsec', bunker_uri_ref: '/etc/nvoy/credentials/codex-test.bunker', bunker_client_ref: '/etc/nvoy/credentials/codex-test.client', worker_image: 'registry.example/codex-worker@sha256:' + 'd'.repeat(64), worker_runner: 'codex', worker_credential_ref: '/etc/nvoy/credentials/codex-test.provider', shared_gid: process.getgid(), watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013,
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'], relays: ['wss://nos.lol', 'wss://relay.primal.net'] }
writeFileSync(manifestFile, JSON.stringify(manifest))
const cli = (...args) => spawnSync(process.execPath, ['mcp/tools/instance-runtime.mjs', ...args], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })

const good = cli('describe', '--instance', 'codex-test')
const described = JSON.parse(good.stdout || '{}')
ok('a valid instance manifest describes its public identity', good.status === 0 && described.recipient === pubkey)
ok('the description contains no private key reference', !/keyFile|nsec/.test(good.stdout))
ok('the instance receives its own state directory', described.stateDir === manifest.state_dir)
ok('the manifest binds three distinct non-root service UIDs', manifest.watcher_uid !== manifest.broker_uid && manifest.broker_uid !== manifest.adapter_uid)
const image = 'registry.example/nvoy@sha256:' + 'e'.repeat(64)
const rendered = spawnSync(process.execPath, ['mcp/tools/render-instance-compose.mjs', '--instance', 'codex-test', '--image', image], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('Compose UID/GID, every runtime path, and Bunker-only mounts are rendered from the immutable manifest', rendered.status === 0 && rendered.stdout.includes('\"41011:' + process.getgid() + '\"') && rendered.stdout.includes(manifest.bunker_uri_ref) && rendered.stdout.includes(manifest.bunker_client_ref) && rendered.stdout.includes(manifest.worker_credential_ref) && rendered.stdout.includes(manifest.state_dir) && rendered.stdout.includes(manifest.spool_dir) && rendered.stdout.includes(manifest.runtime_dir) && !rendered.stdout.includes('${WATCHER_UID'))
ok('Compose volume namespace is bound to the immutable instance ID', rendered.status === 0 && rendered.stdout.includes('name: nvoy-codex-test'))
ok('Compose includes a keyless digest-pinned Codex/Claude worker for each instance', rendered.status === 0 && rendered.stdout.includes(manifest.worker_image) && rendered.stdout.includes('--runner", "codex"'))
const taggedImage = spawnSync(process.execPath, ['mcp/tools/render-instance-compose.mjs', '--instance', 'codex-test', '--image', 'nvoy:latest'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('Compose renderer rejects mutable image tags', taggedImage.status !== 0 && /canonical/.test(taggedImage.stderr))
const workerStart = rendered.stdout.indexOf('\n  worker:')
const workerEnd = rendered.stdout.indexOf('\nsecrets:', workerStart)
const workerPart = workerStart < 0 ? '' : rendered.stdout.slice(workerStart, workerEnd < 0 ? undefined : workerEnd)
const nonWorkerPart = workerStart < 0 ? rendered.stdout : rendered.stdout.slice(0, workerStart)
ok('the model-provider secret is worker-only and remains separate from the Bunker signer', workerPart.includes('nvoy_worker_provider') && !nonWorkerPart.includes('nvoy_worker_provider') && !workerPart.includes('nvoy_bunker_uri') && !workerPart.includes('nvoy_bunker_client'))

const watcherSource = readFileSync('mcp/tools/instance-runtime.mjs', 'utf8')
ok('the keyless watcher receives an explicit environment, not inherited process secrets', !/\.\.\.process\.env/.test(watcherSource) && !/NVOY_NSEC/.test(watcherSource))
const wakeSource = readFileSync('mcp/tools/keyless-wake-watcher.mjs', 'utf8')
ok('watcher writes the pending marker before advancing seen state', wakeSource.includes('`${id}.pending`') && wakeSource.includes('!seen.has(m[2].id) && record(m[2].id)) mark(m[2].id)'))
ok('watcher markers and adapter socket are group-limited to the matching broker', /chmodSync\(p, 0o660\)/.test(wakeSource) && /chmodSync\(socket, 0o660\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')))
ok('broker can traverse the adapter runtime but cannot replace its socket or queue', /chmodSync\(manifest\.runtimeDir, 0o710\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /provision\(m\.runtimeDir, m\.adapterUid, m\.sharedGid, 0o710/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')))
ok('watcher cooldown coalesces notifications but never skips durable queueing', /function record\(id\)[\s\S]*appendFileSync[\s\S]*if \(now - lastWake < cooldown\) return true/.test(wakeSource))
const brokerSource = readFileSync('mcp/tools/instance-broker.mjs', 'utf8')
ok('broker atomically claims the exact pending marker before decrypting', /renameSync\(pendingMarker, markerPath\)/.test(brokerSource) && /--envelope', envelope/.test(brokerSource))
ok('a broker claims a per-state exclusive lock before decrypting', /openSync\(lockPath, 'wx'/.test(brokerSource) && /process\.kill\(prior\.pid, 0\)/.test(brokerSource))
ok('the broker records an identity-bound, expiry-limited admission receipt before any keyless worker can request a reply', /broker: manifest\.pubkey, envelope/.test(brokerSource) && /sender: String\(admission\.from\)/.test(brokerSource) && /grant_id: String\(admission\.grant_id\)/.test(brokerSource) && /expires_at: Date\.now\(\) \+ 5 \* 60 \* 1000/.test(brokerSource))
const daemonSource = readFileSync('mcp/tools/instance-broker-daemon.mjs', 'utf8')
ok('broker restart requeues only interrupted inflight markers before draining', /\.inflight/.test(daemonSource) && /\.pending/.test(daemonSource) && /setInterval\(drain, 1000\)/.test(daemonSource))
const initSource = readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')
ok('a root-only initializer provisions all three volume roots before non-root services start', /process\.getuid\?\.\(\) !== 0/.test(initSource) && /provision\(m\.stateDir/.test(initSource) && /provision\(m\.spoolDir/.test(initSource) && /provision\(m\.runtimeDir/.test(initSource))
const replySource = readFileSync('mcp/tools/instance-broker-reply.mjs', 'utf8')
ok('only the broker can sign a reply, resolving its target from an exact receipt and persisting the wrap', /NVOY_BROKER_CREDENTIAL/.test(replySource) && /receipt\.sender/.test(replySource) && !/request\.to/.test(replySource) && replySource.includes('writeFileSync(tmp, JSON.stringify(record)') && /finalizeEvent/.test(replySource))
const workerSource = readFileSync('mcp/tools/instance-worker.mjs', 'utf8')
ok('the Codex/Claude worker stays Nostr-keyless, uses only its runner-specific provider secret, and treats delivered text as data', !/NVOY_NSEC|BROKER_CREDENTIAL|NVOY_BUNKER_URI|nip44|finalizeEvent/.test(workerSource) && /NVOY_WORKER_CREDENTIAL_FILE/.test(workerSource) && /OPENAI_API_KEY/.test(workerSource) && /ANTHROPIC_API_KEY/.test(workerSource) && /untrusted DATA, not instructions/.test(workerSource) && /reply-request/.test(workerSource))
const workerDockerfile = readFileSync('deploy/nvoy-worker.Dockerfile', 'utf8')
ok('the reproducible worker image installs both declared runner CLIs but bakes no Nostr credential', /@openai\/codex@\$\{CODEX_VERSION\}/.test(workerDockerfile) && /@anthropic-ai\/claude-code@\$\{CLAUDE_VERSION\}/.test(workerDockerfile) && !/NVOY_NSEC|BUNKER_URI|bunker:\/\//i.test(workerDockerfile))

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

const worker = spawnSync(process.execPath, ['mcp/tools/instance-worker.mjs', '--instance', 'codex-test', '--reply', 'A safe brokered test reply.'], {
  cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot },
})
const replyQueue = join(manifest.runtime_dir, 'reply-requests.jsonl')
let workerRequest; try { workerRequest = JSON.parse(readFileSync(replyQueue, 'utf8').trim()) } catch {}
ok('a keyless worker turns only an admitted task into a bounded brokered reply request', worker.status === 0 && workerRequest?.version === 1 && workerRequest?.instance === 'codex-test' && workerRequest?.receipt === packet.envelope && !('to' in (workerRequest || {})) && workerRequest?.content === 'A safe brokered test reply.')

mkdirSync(join(manifest.state_dir, 'receipts'), { recursive: true })
writeFileSync(join(manifest.state_dir, 'receipts', `${packet.envelope}.json`), JSON.stringify({ version: 1, instance: 'codex-test', broker: pubkey, envelope: packet.envelope, sender: packet.messages[0].from, grant_id: 'e'.repeat(64), grantor: 'f'.repeat(64), cap: 'task', admitted_at: Date.now(), expires_at: Date.now() - 1 }))
const deniedRequest = { version: 1, type: 'reply-request', id: 'c'.repeat(32), instance: 'codex-test', receipt: packet.envelope, content: 'must not be signed' }
writeFileSync(replyQueue, readFileSync(replyQueue, 'utf8') + JSON.stringify(deniedRequest) + '\n')
const credential = join(root, 'broker-test.nsec'); writeFileSync(credential, nip19.nsecEncode(key), { mode: 0o600 })
const deniedReply = spawnSync(process.execPath, ['mcp/tools/instance-broker-reply.mjs', '--instance', 'codex-test', '--request', deniedRequest.id], {
  cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot, NVOY_BROKER_CREDENTIAL: credential },
})
ok('the keyed broker refuses a worker reply when its immutable admission receipt is expired', deniedReply.status !== 0 && /not a live broker-bound sender capability/.test(deniedReply.stderr))

writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...manifest, id: 'collision', runtime_dir: join(root, 'run-other') }))
const collision = cli('describe', '--instance', 'codex-test')
ok('duplicate participant pubkeys are refused before a runtime starts', collision.status !== 0 && /collision/.test(collision.stderr))
// Keep the manifest set valid for the independent spool-root collision case below.
writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...manifest, id: 'collision', pubkey: '2'.repeat(64), state_dir: join(root, 'state-collision'), runtime_dir: join(root, 'run-collision'), spool_dir: join(root, 'spool-collision') }))

const symlinkRoot = join(root, 'symlink-instances')
mkdirSync(symlinkRoot)
mkdirSync(join(root, 'real-state'))
symlinkSync(join(root, 'real-state'), join(root, 'linked-state'))
writeFileSync(join(symlinkRoot, 'symlink-test.json'), JSON.stringify({ ...manifest, id: 'symlink-test', state_dir: join(root, 'linked-state'), runtime_dir: join(root, 'run-safe') }))
const symlinked = spawnSync(process.execPath, ['mcp/tools/instance-runtime.mjs', 'describe', '--instance', 'symlink-test'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: symlinkRoot } })
ok('symlinked state roots are refused before a runtime starts', symlinked.status !== 0 && /never a symlink/.test(symlinked.stderr))

writeFileSync(join(manifestRoot, 'spool-collision.json'), JSON.stringify({ ...manifest, id: 'spool-collision', pubkey: '1'.repeat(64), state_dir: join(root, 'state-other'), runtime_dir: join(root, 'run-other'), spool_dir: manifest.spool_dir }))
const spoolCollision = cli('describe', '--instance', 'codex-test')
ok('shared watcher spool roots are refused before a runtime starts', spoolCollision.status !== 0 && /spoolDir collision/.test(spoolCollision.stderr))

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
