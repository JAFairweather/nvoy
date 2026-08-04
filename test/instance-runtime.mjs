// Multi-instance runtime contract (#44): a public manifest names exactly one identity and
// isolated state. This drives the real CLI, rather than duplicating its validation in a unit.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, symlinkSync, unlinkSync, chmodSync } from 'node:fs'
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
const desktopManifestFile = join(manifestRoot, 'codex-desktop.json')
const desktopManifest = { ...manifest, id: 'codex-desktop', pubkey: '3'.repeat(64), state_dir: join(root, 'state-desktop'), runtime_dir: join(root, 'run-desktop'), spool_dir: join(root, 'spool-desktop'),
  broker_mode: 'remote', key_ref: '', bunker_uri_ref: '', bunker_client_ref: '', worker_image: '', worker_runner: '', worker_credential_ref: '',
  delivery_mode: 'codex_app_server', codex_thread_id: '019fc80b-78a6-7b72-b3d2-eced37f55da7', codex_transport: 'local_control_socket', codex_app_server_socket: '/tmp/codex-app-server.sock' }
writeFileSync(desktopManifestFile, JSON.stringify(desktopManifest))
const desktop = cli('describe', '--instance', 'codex-desktop')
ok('a remote-broker Codex desktop binding is keyless and names one explicit local thread', desktop.status === 0 && JSON.parse(desktop.stdout).brokerMode === 'remote' && !/credential|bunker|nsec/i.test(desktop.stdout))
const duplicateDesktopWatcher = cli('watch', '--instance', 'codex-desktop')
ok('a remote-broker Desktop manifest cannot start a second watcher', duplicateDesktopWatcher.status !== 0 && /cannot start a second watcher/.test(duplicateDesktopWatcher.stderr))
mkdirSync(join(root, 'run-desktop'), { recursive: true })
const importRecord = envelope => JSON.stringify({ type: 'admitted-task', instance: 'codex-desktop', envelope, messages: [{ from: 'a'.repeat(64), at: 1, content: 'remote admitted data' }] }) + '\n'
const runImport = (input, ...args) => spawnSync(process.execPath, ['mcp/tools/instance-admitted-import.mjs', '--instance', 'codex-desktop', ...args], { cwd: resolve('.'), encoding: 'utf8', input, env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
const historicalEnvelope = '8'.repeat(64), liveEnvelope = '9'.repeat(64)
const baselineImport = runImport(importRecord(historicalEnvelope), '--baseline')
const liveImport = runImport(importRecord(historicalEnvelope) + importRecord(liveEnvelope))
const replayImport = runImport(importRecord(liveEnvelope))
const desktopQueue = join(root, 'run-desktop', 'admitted-tasks.jsonl')
ok('remote Codex queue install baselines history, imports only a later unseen envelope, and deduplicates replay', baselineImport.status === 0 && liveImport.status === 0 && replayImport.status === 0 && readFileSync(desktopQueue, 'utf8').trim().split('\n').length === 1 && readFileSync(desktopQueue, 'utf8').includes(liveEnvelope) && !readFileSync(desktopQueue, 'utf8').includes(historicalEnvelope))
const wrongInstance = JSON.stringify({ type: 'admitted-task', instance: 'claude-other', envelope: '7'.repeat(64), messages: [{ from: 'a'.repeat(64), at: 1, content: 'cross-instance attempt' }] }) + '\n'
const deniedImport = runImport(wrongInstance)
ok('remote Codex queue import refuses a record for another identity', deniedImport.status !== 0 && /invalid admitted record/.test(deniedImport.stderr))
const desktopDelivered = join(root, 'run-desktop', 'codex-app-server-delivered.jsonl')
writeFileSync(desktopDelivered, JSON.stringify({ version: 1, envelope: liveEnvelope, thread_id: '019fc80b-78a6-7b72-b3d2-eced37f55da7', turn_id: '019fce6b-4727-7a13-8f80-f4a6035c277e', delivered_at: Date.now() }) + '\n', { mode: 0o600 })
const fakeBin = join(root, 'fake-bin'), fakeIdentity = join(root, 'reply-identity'), fakeKnownHosts = join(root, 'known-hosts'), fakeCapture = join(root, 'captured-reply.json')
mkdirSync(fakeBin); writeFileSync(fakeIdentity, 'test-only', { mode: 0o600 }); writeFileSync(fakeKnownHosts, 'test-only', { mode: 0o600 })
const fakeSsh = join(fakeBin, 'ssh')
writeFileSync(fakeSsh, '#!/usr/bin/env node\nconst fs=require("node:fs");let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const x=JSON.parse(s);fs.writeFileSync(process.env.FAKE_CAPTURE,s);process.stdout.write(JSON.stringify({request:x.id,receipt:x.receipt,queued:true}))})\n', { mode: 0o700 }); chmodSync(fakeSsh, 0o700)
const runRemoteReply = envelope => spawnSync(process.execPath, ['mcp/tools/codex-remote-reply.mjs', '--instance', 'codex-desktop', '--envelope', envelope, '--ssh-target', 'reply@nave.test', '--ssh-identity', fakeIdentity, '--known-hosts', fakeKnownHosts], { cwd: resolve('.'), encoding: 'utf8', input: 'reply from the exact Desktop thread', env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, FAKE_CAPTURE: fakeCapture, NVOY_INSTANCE_ROOT: manifestRoot } })
const remoteReply = runRemoteReply(liveEnvelope)
let capturedReply; try { capturedReply = JSON.parse(readFileSync(fakeCapture, 'utf8')) } catch {}
ok('the exact delivered Desktop thread can submit one recipient-free brokered reply request', remoteReply.status === 0 && capturedReply?.receipt === liveEnvelope && capturedReply?.instance === 'codex-desktop' && capturedReply?.content === 'reply from the exact Desktop thread' && !('to' in capturedReply))
const undeliveredReply = runRemoteReply('6'.repeat(64))
ok('the Desktop reply tool refuses an envelope not delivered to its bound thread', undeliveredReply.status !== 0 && /was not delivered/.test(undeliveredReply.stderr))

if (process.getuid?.() > 0) {
  const replyRoot = join(root, 'reply-instances'), replyRuntime = join(root, 'reply-runtime')
  mkdirSync(replyRoot); mkdirSync(replyRuntime)
  const uid = process.getuid(), ids = [uid + 1, uid + 2, uid + 3].map((value, index) => value === uid ? uid + 10 + index : value)
  writeFileSync(join(replyRoot, 'reply-test.json'), JSON.stringify({ ...manifest, id: 'reply-test', pubkey: '5'.repeat(64), state_dir: join(root, 'reply-state'), runtime_dir: replyRuntime, spool_dir: join(root, 'reply-spool'), delivery_mode: 'notify_only', watcher_uid: ids[0], broker_uid: ids[1], adapter_uid: ids[2], worker_uid: uid }))
  writeFileSync(join(replyRuntime, 'admitted-tasks.jsonl'), JSON.stringify({ type: 'admitted-task', instance: 'reply-test', envelope: liveEnvelope, messages: [{ from: 'a'.repeat(64), at: 1, content: 'admitted' }] }) + '\n')
  const importRequest = { version: 1, type: 'reply-request', id: '4'.repeat(32), instance: 'reply-test', receipt: liveEnvelope, content: 'bounded Desktop reply' }
  const importedReply = spawnSync(process.execPath, ['mcp/tools/instance-desktop-reply-import.mjs', '--instance', 'reply-test'], { cwd: resolve('.'), encoding: 'utf8', input: JSON.stringify(importRequest), env: { ...process.env, NVOY_INSTANCE_ROOT: replyRoot } })
  const importedRequest = JSON.parse(readFileSync(join(replyRuntime, 'reply-requests.jsonl'), 'utf8').trim())
  ok('the worker-UID forced endpoint queues a bounded request only for an admitted single-sender receipt', importedReply.status === 0 && importedRequest.id === importRequest.id && importedRequest.receipt === liveEnvelope && !('to' in importedRequest))
} else ok('the worker-UID forced endpoint queues a bounded request only for an admitted single-sender receipt (root runner skips UID execution)', true)

writeFileSync(join(root, 'run-desktop', 'codex-app-server-delivered.jsonl'), JSON.stringify({ version: 1, envelope: liveEnvelope, thread_id: desktopManifest.codex_thread_id, turn_id: '019fce6b-4727-7a13-8f80-f4a6035c277f' }) + '\n')
const requestReply = input => spawnSync(process.execPath, ['mcp/tools/desktop-reply-request.mjs', '--instance', 'codex-desktop', '--receipt', liveEnvelope], { cwd: resolve('.'), encoding: 'utf8', input, env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
const desktopReply = requestReply('Yes.\n'), duplicateReply = requestReply('Again.\n')
ok('the keyless Desktop can request one reply only for a notification delivered to its fixed thread', desktopReply.status === 0 && duplicateReply.status !== 0 && /already has a reply request/.test(duplicateReply.stderr) && readFileSync(join(root, 'run-desktop', 'reply-requests.jsonl'), 'utf8').includes('"content":"Yes."'))

const syncUid = process.getuid(), syncRuntime = join(root, 'run-sync'), syncEnvelope = '6'.repeat(64)
const syncManifest = { ...manifest, id: 'sync-test', pubkey: '5'.repeat(64), state_dir: join(root, 'state-sync'), runtime_dir: syncRuntime, spool_dir: join(root, 'spool-sync'),
  watcher_uid: syncUid === 41021 ? 41024 : 41021, broker_uid: syncUid === 41022 ? 41025 : 41022, adapter_uid: syncUid === 41023 ? 41026 : 41023, worker_uid: syncUid }
writeFileSync(join(manifestRoot, 'sync-test.json'), JSON.stringify(syncManifest)); mkdirSync(syncRuntime, { recursive: true })
writeFileSync(join(syncRuntime, 'admitted-tasks.jsonl'), JSON.stringify({ type: 'admitted-task', instance: 'sync-test', envelope: syncEnvelope, messages: [{ from: 'a'.repeat(64), at: 1, content: 'sync me' }] }) + '\n')
writeFileSync(join(syncRuntime, 'reply-requests.jsonl'), '')
const syncRequest = JSON.stringify({ version: 1, type: 'reply-request', id: '1'.repeat(32), instance: 'sync-test', receipt: syncEnvelope, content: 'Remote yes.' }) + '\n'
const runSync = input => spawnSync(process.execPath, ['mcp/tools/instance-desktop-sync.mjs', '--instance', 'sync-test'], { cwd: resolve('.'), encoding: 'utf8', input, env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
const firstSync = runSync(syncRequest), replaySync = runSync(syncRequest)
const badSync = runSync(JSON.stringify({ ...JSON.parse(syncRequest), id: '2'.repeat(32), receipt: '7'.repeat(64) }) + '\n')
ok('the restricted server sync imports a bounded admitted-envelope reply exactly once and exports only admitted tasks', firstSync.status === 0 && replaySync.status === 0 && badSync.status !== 0 && firstSync.stdout.includes(syncEnvelope) && readFileSync(join(syncRuntime, 'reply-requests.jsonl'), 'utf8').trim().split('\n').length === 1)
writeFileSync(join(manifestRoot, 'bad-desktop.json'), JSON.stringify({ ...manifest, id: 'bad-desktop', pubkey: '4'.repeat(64), state_dir: join(root, 'state-bad-desktop'), runtime_dir: join(root, 'run-bad-desktop'), spool_dir: join(root, 'spool-bad-desktop'), delivery_mode: 'codex_app_server' }))
const badDesktop = cli('describe', '--instance', 'bad-desktop')
ok('an inbound event cannot silently select or create a Codex desktop thread', badDesktop.status !== 0 && /explicit codex_thread_id/.test(badDesktop.stderr))
// Invalid manifests must not remain in this fixture: every production command preflights the
// complete instance root and therefore correctly refuses an invalid neighbour.
unlinkSync(join(manifestRoot, 'bad-desktop.json'))
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
ok('watcher writes the pending marker before advancing seen state, with millisecond ordering for live-wake priority', wakeSource.includes('`${id}.pending`') && /observed_at: now/.test(wakeSource) && /else if \(record\(m\[2\]\.id\)\) mark\(m\[2\]\.id\)/.test(wakeSource))
ok('a fresh identity can baseline existing backdated NIP-17 wraps without delivering them', /command === 'baseline'/.test(watcherSource) && /--baseline-existing/.test(watcherSource) && /m\[0\] === 'EOSE'/.test(wakeSource) && /baseline\(m\[2\]\.id\)/.test(wakeSource) && /baseline complete/.test(wakeSource))
ok('watcher markers and adapter socket are group-limited to the matching broker', /chmodSync\(p, 0o660\)/.test(wakeSource) && /manifest\.brokerAdapterGid/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /chmodSync\(socket, 0o660\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')))
ok('the worker has no adapter-socket group but has a separate read-only handoff group', manifest.broker_adapter_gid !== manifest.worker_handoff_gid && rendered.stdout.includes('group_add: ["' + manifest.worker_handoff_gid + '"]') && !workerPart.includes(String(manifest.broker_adapter_gid)))
ok('broker can traverse the adapter runtime but cannot replace its socket or queue', /chmodSync\(manifest\.runtimeDir, 0o711\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /provision\(m\.runtimeDir, m\.adapterUid, m\.brokerAdapterGid, 0o711/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')))
const workerSource = readFileSync('mcp/tools/instance-worker.mjs', 'utf8')
const codexDesktopSource = readFileSync('mcp/tools/codex-app-server-adapter.mjs', 'utf8')
const codexTransportSource = readFileSync('mcp/tools/codex_app_server.mjs', 'utf8')
const admittedExportSource = readFileSync('mcp/tools/instance-admitted-export.mjs', 'utf8')
const admittedImportSource = readFileSync('mcp/tools/instance-admitted-import.mjs', 'utf8')
const remoteBridgeSource = readFileSync('mcp/tools/codex-remote-bridge.mjs', 'utf8')
const remoteReplySource = readFileSync('mcp/tools/codex-remote-reply.mjs', 'utf8')
const remoteReplyImportSource = readFileSync('mcp/tools/instance-desktop-reply-import.mjs', 'utf8')
ok('Desktop replies name only a delivered receipt while the broker retains recipient resolution and signing', /codex-app-server-delivered\.jsonl/.test(remoteReplySource) && /thread_id === manifest\.codexThreadId/.test(remoteReplySource) && /receipt, content/.test(remoteReplySource) && !/request\.to|["']to["']\s*:|NVOY_NSEC|NVOY_BROKER_CREDENTIAL|bunker:|wss:\/\//.test(remoteReplySource) && /manifest\.workerUid/.test(remoteReplyImportSource) && /reply receipt already has a request/.test(remoteReplyImportSource) && !/finalizeEvent|nip44|NVOY_NSEC|NVOY_BROKER_CREDENTIAL/.test(remoteReplyImportSource))
ok('Desktop delivery mode disables the independent headless model drain before reading a provider credential', /manifest\.deliveryMode !== 'headless'/.test(workerSource) && /headless model drain disabled/.test(workerSource) && workerSource.indexOf("manifest.deliveryMode !== 'headless'") < workerSource.indexOf('let providerKey'))
const desktopReplySource = readFileSync('mcp/tools/desktop-reply-request.mjs', 'utf8')
const desktopSyncSource = readFileSync('mcp/tools/instance-desktop-sync.mjs', 'utf8')
ok('the Codex context adapter resumes only the manifest-bound thread after broker admission, with no Nostr key or network listener', /thread\/resume/.test(codexTransportSource) && /threadId: id/.test(codexTransportSource) && /turn\/start/.test(codexTransportSource) && /local_control_socket/.test(codexDesktopSource) && /admitted-tasks\.jsonl/.test(codexDesktopSource) && !/NVOY_NSEC|NVOY_BROKER_CREDENTIAL|bunker:|wss:\/\//.test(codexDesktopSource + codexTransportSource))
ok('remote desktop delivery exports only adapter-admitted records and imports them without any Nostr credential', /process\.getuid.*manifest\.adapterUid/.test(admittedExportSource) && /admitted-tasks\.jsonl/.test(admittedExportSource) && /--baseline/.test(admittedImportSource) && /remote-imported\.jsonl/.test(admittedImportSource) && !/NVOY_NSEC|NVOY_BROKER_CREDENTIAL|bunker:|wss:\/\//.test(admittedExportSource + admittedImportSource))
ok('the remote Codex bridge uses a restricted duplex sync and a keyless child environment', /BatchMode=yes/.test(remoteBridgeSource) && /StrictHostKeyChecking=yes/.test(remoteBridgeSource) && /ClearAllForwardings=yes/.test(remoteBridgeSource) && /input: replies/.test(remoteBridgeSource) && /const childEnv = \{ HOME:/.test(remoteBridgeSource) && !/\.\.\.process\.env/.test(remoteBridgeSource) && !/NVOY_NSEC|NVOY_BROKER_CREDENTIAL|bunker:|wss:\/\//.test(remoteBridgeSource + desktopReplySource + desktopSyncSource))
ok('Desktop reply tooling cannot choose a recipient or sign; server sync runs only as the manifest worker UID', /codex-app-server-delivered\.jsonl/.test(desktopReplySource) && /already has a reply request/.test(desktopReplySource) && /process\.getuid.*manifest\.workerUid/.test(desktopSyncSource) && !/recipient|\[['"]p['"]|signEvent|nip44|finalizeEvent/.test(desktopReplySource + desktopSyncSource))
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
ok('the worker supplies its authenticated delivery directly over stdin rather than asking the model to discover a private file', /JSON\.stringify\(delivery\)/.test(workerSource) && /'--- BEGIN DELIVERED MESSAGE ---'/.test(workerSource) && /\['exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--cd', manifest\.runtimeDir, '-'\]/.test(workerSource) && /input: prompt/.test(workerSource))
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
