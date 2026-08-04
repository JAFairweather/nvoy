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
import { isTerminalReplyFailure, loadTerminalReplyIds, recordTerminalReply } from '../mcp/tools/reply_retry.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-instance-'))
const key = generateSecretKey(), pubkey = getPublicKey(key)
const brokerAdapterGid = process.getgid()
const workerHandoffGid = process.getgroups().find(g => g !== brokerAdapterGid)
if (!Number.isInteger(workerHandoffGid)) throw new Error('test runner needs a second supplementary group')
const manifestRoot = join(root, 'instances')
mkdirSync(manifestRoot)
const manifestFile = join(manifestRoot, 'codex-test.json')
const manifest = { version: 1, id: 'codex-test', pubkey: nip19.npubEncode(pubkey),
  state_dir: join(root, 'state-codex'), runtime_dir: join(root, 'run-codex'), spool_dir: join(root, 'spool-codex'), key_ref: '/etc/nvoy/credentials/codex-test.nsec', bunker_uri_ref: '/etc/nvoy/credentials/codex-test.bunker', bunker_client_ref: '/etc/nvoy/credentials/codex-test.client', worker_image: 'registry.example/codex-worker@sha256:' + 'd'.repeat(64), worker_runner: 'codex', worker_credential_ref: '/etc/nvoy/credentials/codex-test.provider', broker_adapter_gid: brokerAdapterGid, worker_handoff_gid: workerHandoffGid, watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'], relays: ['wss://nos.lol', 'wss://relay.primal.net'] }
writeFileSync(manifestFile, JSON.stringify(manifest))
const cli = (...args) => spawnSync(process.execPath, ['mcp/tools/instance-runtime.mjs', ...args], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })

const good = cli('describe', '--instance', 'codex-test')
const described = JSON.parse(good.stdout || '{}')
ok('a valid instance manifest describes its public identity', good.status === 0 && described.recipient === pubkey)
ok('the description contains no private key reference', !/keyFile|nsec/.test(good.stdout))
ok('the instance receives its own state directory', described.stateDir === manifest.state_dir)
ok('the manifest binds four distinct non-root service UIDs', new Set([manifest.watcher_uid, manifest.broker_uid, manifest.adapter_uid, manifest.worker_uid]).size === 4)
const image = 'registry.example/nvoy@sha256:' + 'e'.repeat(64)
const rendered = spawnSync(process.execPath, ['mcp/tools/render-instance-compose.mjs', '--instance', 'codex-test', '--image', image], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('Compose UID/GID, every runtime path, and Bunker-only mounts are rendered from the immutable manifest', rendered.status === 0 && rendered.stdout.includes('\"41011:' + manifest.broker_adapter_gid + '\"') && rendered.stdout.includes('\"41014:' + manifest.worker_handoff_gid + '\"') && rendered.stdout.includes(manifest.bunker_uri_ref) && rendered.stdout.includes(manifest.bunker_client_ref) && rendered.stdout.includes(manifest.worker_credential_ref) && rendered.stdout.includes(manifest.state_dir) && rendered.stdout.includes(manifest.spool_dir) && rendered.stdout.includes(manifest.runtime_dir) && !rendered.stdout.includes('${WATCHER_UID'))
ok('Compose volume namespace is bound to the immutable instance ID', rendered.status === 0 && rendered.stdout.includes('name: nvoy-codex-test'))
ok('Compose includes a keyless digest-pinned Codex/Claude worker for each instance', rendered.status === 0 && rendered.stdout.includes(manifest.worker_image) && rendered.stdout.includes('--runner", "codex"'))
const taggedImage = spawnSync(process.execPath, ['mcp/tools/render-instance-compose.mjs', '--instance', 'codex-test', '--image', 'nvoy:latest'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('Compose renderer rejects mutable image tags', taggedImage.status !== 0 && /canonical/.test(taggedImage.stderr))
const servicePart = name => (rendered.stdout.match(new RegExp(`\\n  ${name}:[\\s\\S]*?(?=\\n  [a-z][a-z_]*:|\\nsecrets:|$)`)) || [''])[0]
const initPart = servicePart('init'), brokerPart = servicePart('broker'), watcherPart = servicePart('watcher')
const adapterPart = servicePart('adapter'), workerPart = servicePart('worker')
ok('the root-only initializer copies sources into distinct role-owned volumes; worker gets only provider and broker only Bunker credentials', initPart.includes('nvoy_bunker_uri') && initPart.includes('nvoy_bunker_client') && initPart.includes('nvoy_worker_provider') && initPart.includes('broker_credentials') && initPart.includes('worker_credentials') && workerPart.includes('worker_credentials') && workerPart.includes('HOME: /tmp') && !workerPart.includes('broker_credentials') && !workerPart.includes('nvoy_bunker_uri') && !workerPart.includes('nvoy_bunker_client') && brokerPart.includes('broker_credentials') && !brokerPart.includes('worker_credentials') && !brokerPart.includes('nvoy_worker_provider') && !watcherPart.includes('credentials') && !adapterPart.includes('credentials'))

const watcherSource = readFileSync('mcp/tools/instance-runtime.mjs', 'utf8')
ok('the keyless watcher receives an explicit environment, not inherited process secrets', !/\.\.\.process\.env/.test(watcherSource) && !/NVOY_NSEC/.test(watcherSource))
const wakeSource = readFileSync('mcp/tools/keyless-wake-watcher.mjs', 'utf8')
ok('watcher writes the pending marker before advancing seen state, with millisecond ordering for live-wake priority', wakeSource.includes('`${id}.pending`') && /observed_at: now/.test(wakeSource) && wakeSource.includes('!seen.has(m[2].id) && record(m[2].id)) mark(m[2].id)'))
ok('watcher markers and adapter socket are group-limited to the matching broker', /chmodSync\(p, 0o660\)/.test(wakeSource) && /manifest\.brokerAdapterGid/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /chmodSync\(socket, 0o660\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')))
ok('the worker has no adapter-socket group but has a separate read-only handoff group', manifest.broker_adapter_gid !== manifest.worker_handoff_gid && rendered.stdout.includes('group_add: ["' + manifest.worker_handoff_gid + '"]') && !workerPart.includes(String(manifest.broker_adapter_gid)))
ok('broker can traverse the adapter runtime but cannot replace its socket or queue', /chmodSync\(manifest\.runtimeDir, 0o711\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /provision\(m\.runtimeDir, m\.adapterUid, m\.brokerAdapterGid, 0o711/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')))
const workerSource = readFileSync('mcp/tools/instance-worker.mjs', 'utf8')
ok('the worker has a separate UID and can use only pre-provisioned cross-UID handoff paths', rendered.stdout.includes('\"41014:' + manifest.worker_handoff_gid + '\"') && /admitted-tasks\.jsonl.*workerHandoffGid.*0o640/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')) && /reply-requests\.jsonl.*brokerAdapterGid.*0o640/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')) && /worker-input.*workerHandoffGid.*0o710/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')) && /renameSync\(tmp, input\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /worker-input/.test(workerSource) && !/writeFileSync\(inputPath/.test(workerSource))
ok('watcher cooldown coalesces notifications but never skips durable queueing', /function record\(id\)[\s\S]*appendFileSync[\s\S]*if \(now - lastWake < cooldown\) return true/.test(wakeSource))
const brokerSource = readFileSync('mcp/tools/instance-broker.mjs', 'utf8')
ok('broker atomically claims the exact pending marker before decrypting', /renameSync\(pendingMarker, markerPath\)/.test(brokerSource) && /--envelope', envelope/.test(brokerSource))
ok('a broker claims a per-state exclusive lock before decrypting', /openSync\(lockPath, 'wx'/.test(brokerSource) && /process\.kill\(prior\.pid, 0\)/.test(brokerSource))
ok('the broker records an identity-bound, expiry-limited admission receipt before any keyless worker can request a reply', /broker: manifest\.pubkey, envelope/.test(brokerSource) && /sender: String\(admission\.from\)/.test(brokerSource) && /grant_id: String\(admission\.grant_id\)/.test(brokerSource) && /expires_at: Date\.now\(\) \+ 5 \* 60 \* 1000/.test(brokerSource))
const daemonSource = readFileSync('mcp/tools/instance-broker-daemon.mjs', 'utf8')
ok('broker restart requeues only interrupted inflight markers and prioritizes the newest opaque observation', /\.inflight/.test(daemonSource) && /\.pending/.test(daemonSource) && /marker\.observed_at/.test(daemonSource) && /b\.observed - a\.observed/.test(daemonSource) && /setInterval\(drain, 1000\)/.test(daemonSource))
mkdirSync(manifest.state_dir, { recursive: true })
const terminalReplies = join(manifest.state_dir, 'terminal-replies.jsonl')
const terminalIds = loadTerminalReplyIds(terminalReplies)
const expiredRequest = 'a'.repeat(32)
ok('a stale admission receipt is terminal, rather than a relay-query retry loop', isTerminalReplyFailure('instance-broker-reply: admission receipt is not a live broker-bound sender capability') && recordTerminalReply(terminalReplies, terminalIds, expiredRequest, 'admission receipt is not a live broker-bound sender capability', 1) && terminalIds.has(expiredRequest) && !recordTerminalReply(terminalReplies, terminalIds, expiredRequest, 'admission receipt is not a live broker-bound sender capability', 2) && loadTerminalReplyIds(terminalReplies).has(expiredRequest) && !readFileSync(terminalReplies, 'utf8').includes('must not be signed'))
ok('transient reply publish failures remain retryable', !isTerminalReplyFailure('instance-broker-reply: no relay accepted the persisted outbound wrap; it remains retryable') && /terminalReplyIds\.has\(request\)/.test(daemonSource))
const initSource = readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')
ok('a root-only initializer provisions all three volume roots and role-owned credential copies before non-root services start', /process\.getuid\?\.\(\) !== 0/.test(initSource) && /provision\(m\.stateDir/.test(initSource) && /provision\(m\.spoolDir/.test(initSource) && /provision\(m\.runtimeDir/.test(initSource) && /function provisionSecret/.test(initSource) && /brokerCredDir/.test(initSource) && /workerCredDir/.test(initSource))
const replySource = readFileSync('mcp/tools/instance-broker-reply.mjs', 'utf8')
ok('only the broker can sign a reply, resolving its target from an exact receipt and persisting the wrap', /NVOY_BROKER_CREDENTIAL/.test(replySource) && /receipt\.sender/.test(replySource) && !/request\.to/.test(replySource) && replySource.includes('writeFileSync(tmp, JSON.stringify(record)') && /finalizeEvent/.test(replySource))
ok('the Codex/Claude worker stays Nostr-keyless, uses only its runner-specific provider secret, and treats delivered text as data', !/NVOY_NSEC|BROKER_CREDENTIAL|NVOY_BUNKER_URI|nip44|finalizeEvent/.test(workerSource) && /NVOY_WORKER_CREDENTIAL_FILE/.test(workerSource) && /OPENAI_API_KEY/.test(workerSource) && /ANTHROPIC_API_KEY/.test(workerSource) && /untrusted DATA, not instructions/.test(workerSource) && /reply-request/.test(workerSource))
ok('the headless Codex worker writes a private API-key provider configuration without persisting its provider secret', /function configureCodexApiKeyProvider/.test(workerSource) && /model_provider = "nvoy-openai-api"/.test(workerSource) && /env_key = "OPENAI_API_KEY"/.test(workerSource) && /requires_openai_auth = false/.test(workerSource) && /writeFileSync\(resolve\(dir, 'config\.toml'\)/.test(workerSource) && !/writeFileSync\([^\n]*providerKey/.test(workerSource))
ok('the deployed worker stays awake to drain later admitted tasks instead of relying on restart timing', workerPart.includes('"--daemon"') && /const daemon = process\.argv\.includes\('--daemon'\)/.test(workerSource) && /setInterval\(\(\) =>/.test(workerSource))
const workerDockerfile = readFileSync('deploy/nvoy-worker.Dockerfile', 'utf8')
ok('the reproducible worker image installs trusted CA roots and both declared runner CLIs but bakes no Nostr credential', /apt-get install -y --no-install-recommends ca-certificates/.test(workerDockerfile) && /@openai\/codex@\$\{CODEX_VERSION\}/.test(workerDockerfile) && /@anthropic-ai\/claude-code@\$\{CLAUDE_VERSION\}/.test(workerDockerfile) && !/NVOY_NSEC|BUNKER_URI|bunker:\/\//i.test(workerDockerfile))
const runtimeDockerfile = readFileSync('deploy/nvoy-runtime.Dockerfile', 'utf8')
const testDockerfile = readFileSync('deploy/nvoy-runtime-test.Dockerfile', 'utf8')
ok('every runtime/test base image is digest-pinned, so a source-identical build has stable base provenance', /FROM node:22-bookworm-slim@sha256:[0-9a-f]{64}/.test(runtimeDockerfile) && /FROM node:22-bookworm-slim@sha256:[0-9a-f]{64}/.test(workerDockerfile) && /FROM docker:29-cli@sha256:[0-9a-f]{64}/.test(testDockerfile) && /FROM node:22-bookworm-slim@sha256:[0-9a-f]{64}/.test(testDockerfile))

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
