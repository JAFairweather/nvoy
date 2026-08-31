// Multi-instance runtime contract (#44): a public manifest names exactly one identity and
// isolated state. This drives the real CLI, rather than duplicating its validation in a unit.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, symlinkSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { spawn } from 'node:child_process'
import net from 'node:net'
import { createHash } from 'node:crypto'
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import { isTerminalReplyFailure, loadPublishedReplyIds, loadReplyRequestDigests, loadTerminalReplyIds, recordTerminalReply } from '../mcp/tools/reply_retry.mjs'
import { claimChannelSource, completeChannelSource, channelSourceClaims } from '../mcp/tools/channel_source_dedup.mjs'
import { validateAdmittedTask } from '../mcp/tools/admitted_task.mjs'

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
const manifest = { version: 1, id: 'codex-test', pubkey: nip19.npubEncode(pubkey), service_user: 'nvoy-codex-test',
  state_dir: join(root, 'state-codex'), runtime_dir: join(root, 'run-codex'), spool_dir: join(root, 'spool-codex'), key_ref: '/etc/nvoy/credentials/codex-test.nsec', bunker_uri_ref: '/etc/nvoy/credentials/codex-test.bunker', bunker_client_ref: '/etc/nvoy/credentials/codex-test.client', worker_image: 'registry.example/codex-worker@sha256:' + 'd'.repeat(64), worker_runner: 'codex', worker_credential_ref: '/etc/nvoy/credentials/codex-test.provider', broker_adapter_gid: brokerAdapterGid, worker_handoff_gid: workerHandoffGid, watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'],
  task_carriers: [{ pubkey: '7'.repeat(64), channels: ['a8186b53-537d-46ad-a7e7-b6486c58970e'] }],
  relays: ['wss://nos.lol', 'wss://relay.primal.net'] }
let isolationSequence = 0
const isolatedManifest = (base, id, overrides = {}) => {
  const n = ++isolationSequence
  const credential = (value, suffix) => value ? `/etc/nvoy/credentials/${id}.${suffix}` : ''
  return { ...base, id, service_user: `nvoy-${id}`,
    state_dir: join(root, `state-${id}`), runtime_dir: join(root, `run-${id}`), spool_dir: join(root, `spool-${id}`),
    watcher_uid: 44000 + n * 10 + 1, broker_uid: 44000 + n * 10 + 2,
    adapter_uid: 44000 + n * 10 + 3, worker_uid: 44000 + n * 10 + 4,
    broker_adapter_gid: 45000 + n * 2, worker_handoff_gid: 45000 + n * 2 + 1,
    key_ref: credential(base.key_ref, 'nsec'), bunker_uri_ref: credential(base.bunker_uri_ref, 'bunker-uri'),
    bunker_client_ref: credential(base.bunker_client_ref, 'nip46-client'),
    worker_credential_ref: credential(base.worker_credential_ref, 'provider'), ...overrides }
}
writeFileSync(manifestFile, JSON.stringify(manifest))
const cli = (...args) => spawnSync(process.execPath, ['mcp/tools/instance-runtime.mjs', ...args], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })

const good = cli('describe', '--instance', 'codex-test')
const described = JSON.parse(good.stdout || '{}')
ok('a valid instance manifest describes its public identity', good.status === 0 && described.recipient === pubkey)
ok('the description contains no private key reference', !/keyFile|nsec/.test(good.stdout))
ok('the instance receives its own state directory', described.stateDir === manifest.state_dir)
ok('the manifest binds four distinct non-root service UIDs', new Set([manifest.watcher_uid, manifest.broker_uid, manifest.adapter_uid, manifest.worker_uid]).size === 4)
const desktopManifestFile = join(manifestRoot, 'codex-desktop.json')
const desktopSshKey = join(root, 'desktop-ssh-key'), desktopKnownHosts = join(root, 'desktop-known-hosts')
writeFileSync(desktopSshKey, 'private-test-placeholder\n', { mode: 0o600 })
writeFileSync(desktopKnownHosts, 'nave.pub ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly\n', { mode: 0o600 })
const desktopManifest = isolatedManifest(manifest, 'codex-desktop', { pubkey: '3'.repeat(64),
  state_dir: join(root, 'state-desktop'), runtime_dir: join(root, 'run-desktop'), spool_dir: join(root, 'spool-desktop'),
  broker_mode: 'remote', key_ref: '', bunker_uri_ref: '', bunker_client_ref: '', worker_image: '', worker_runner: '', worker_credential_ref: '',
  delivery_mode: 'codex_app_server', codex_thread_id: '019fc80b-78a6-7b72-b3d2-eced37f55da7', codex_transport: 'local_control_socket', codex_app_server_socket: '/tmp/codex-app-server.sock',
  ssh_target: 'nvoy-sync@nave.pub', ssh_identity_file: desktopSshKey, ssh_known_hosts_file: desktopKnownHosts,
  ssh_known_hosts_sha256: createHash('sha256').update(readFileSync(desktopKnownHosts)).digest('hex') })
writeFileSync(desktopManifestFile, JSON.stringify(desktopManifest))
const desktop = cli('describe', '--instance', 'codex-desktop')
ok('a remote-broker Codex desktop binding is keyless and names one explicit local thread', desktop.status === 0 && JSON.parse(desktop.stdout).brokerMode === 'remote' && !/credential|bunker|nsec/i.test(desktop.stdout))
const macDriver = join(root, 'codex-macos-ui'); writeFileSync(macDriver, '#!/bin/sh\n', { mode: 0o700 })
const macManifest = isolatedManifest(desktopManifest, 'codex-macos', { pubkey: '2'.repeat(64),
  delivery_mode: 'macos_desktop', codex_app_bundle_id: 'com.openai.codex', codex_project_label: 'connect', codex_chat_label: 'Waggle V1', codex_ui_driver: macDriver })
writeFileSync(join(manifestRoot, 'codex-macos.json'), JSON.stringify(macManifest))
const macDesktop = cli('describe', '--instance', 'codex-macos'), macDescription = JSON.parse(macDesktop.stdout || '{}')
ok('macOS V1 binds one keyless identity to the fixed app, project, chat, and durable thread', macDesktop.status === 0 &&
  macDescription.deliveryMode === 'macos_desktop' && macDescription.desktopBinding?.appBundleId === 'com.openai.codex' &&
  macDescription.desktopBinding?.projectLabel === 'connect' && macDescription.desktopBinding?.chatLabel === 'Waggle V1' &&
  macDescription.desktopBinding?.threadId === desktopManifest.codex_thread_id)
writeFileSync(join(manifestRoot, 'bad-macos.json'), JSON.stringify(isolatedManifest(macManifest, 'bad-macos', { pubkey: '1'.repeat(64), codex_app_bundle_id: 'com.apple.TextEdit' })))
const badMac = cli('describe', '--instance', 'bad-macos')
ok('macOS V1 refuses a manifest-selected foreign application', badMac.status !== 0 && /fixed Codex bundle/.test(badMac.stderr))
unlinkSync(join(manifestRoot, 'bad-macos.json'))
const duplicateDesktopWatcher = cli('watch', '--instance', 'codex-desktop')
ok('a remote-broker Desktop manifest cannot start a second watcher', duplicateDesktopWatcher.status !== 0 && /cannot start a second watcher/.test(duplicateDesktopWatcher.stderr))
writeFileSync(join(manifestRoot, 'remote-with-worker.json'), JSON.stringify(isolatedManifest(desktopManifest, 'remote-with-worker', { pubkey: 'e'.repeat(64), worker_image: manifest.worker_image, worker_runner: manifest.worker_runner, worker_credential_ref: '/etc/nvoy/credentials/remote-with-worker.provider' })))
const remoteWithWorker = cli('describe', '--instance', 'remote-with-worker')
ok('a remote-broker Desktop manifest rejects every model-worker/provider credential reference', remoteWithWorker.status !== 0 && /worker-disabled manifest cannot carry/.test(remoteWithWorker.stderr))
unlinkSync(join(manifestRoot, 'remote-with-worker.json'))
const keyedEnv = { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot, NVOY_BROKER_CREDENTIAL: desktopSshKey }
const blockedBroker = spawnSync(process.execPath, ['mcp/tools/instance-broker.mjs', 'deliver', '--instance', 'codex-desktop', '--envelope', 'f'.repeat(64)], { cwd: resolve('.'), encoding: 'utf8', env: keyedEnv })
const blockedDaemon = spawnSync(process.execPath, ['mcp/tools/instance-broker-daemon.mjs', '--instance', 'codex-desktop'], { cwd: resolve('.'), encoding: 'utf8', env: keyedEnv })
const blockedReply = spawnSync(process.execPath, ['mcp/tools/instance-broker-reply.mjs', '--instance', 'codex-desktop', '--request', 'f'.repeat(32), '--prepare'], { cwd: resolve('.'), encoding: 'utf8', env: keyedEnv })
ok('every keyed broker executable rejects a remote Desktop manifest even when a credential is injected', [blockedBroker, blockedDaemon, blockedReply].every(result => result.status !== 0 && /remote-broker Desktop/.test(result.stderr)))
mkdirSync(join(root, 'run-desktop'), { recursive: true })
const importRecord = envelope => JSON.stringify({ type: 'admitted-task', instance: 'codex-desktop', envelope, messages: [{ from: 'a'.repeat(64), at: 1, content: 'remote admitted data' }] }) + '\n'
const runImport = (input, ...args) => spawnSync(process.execPath, ['mcp/tools/instance-admitted-import.mjs', '--instance', 'codex-desktop', ...args], { cwd: resolve('.'), encoding: 'utf8', input, env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
const historicalEnvelope = '8'.repeat(64), liveEnvelope = '9'.repeat(64)
const baselineImport = runImport(importRecord(historicalEnvelope), '--baseline')
const liveImport = runImport(importRecord(historicalEnvelope) + importRecord(liveEnvelope))
const replayImport = runImport(importRecord(liveEnvelope))
const desktopQueue = join(root, 'run-desktop', 'admitted-tasks.jsonl')
ok('remote Codex queue install baselines history, imports only a later unseen envelope, and deduplicates replay', baselineImport.status === 0 && liveImport.status === 0 && replayImport.status === 0 && readFileSync(desktopQueue, 'utf8').trim().split('\n').length === 1 && readFileSync(desktopQueue, 'utf8').includes(liveEnvelope) && !readFileSync(desktopQueue, 'utf8').includes(historicalEnvelope))
const appServerBaseline = spawnSync(process.execPath, ['mcp/tools/codex-app-server-adapter.mjs', '--instance', 'codex-desktop', '--baseline'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('switching a remote Desktop binding to app-server delivery baselines every existing local envelope without starting a turn',
  appServerBaseline.status === 0 && JSON.parse(appServerBaseline.stdout).baselined === 1 &&
  readFileSync(join(root, 'run-desktop', 'codex-app-server-baseline.jsonl'), 'utf8').includes(liveEnvelope))
const wrongInstance = JSON.stringify({ type: 'admitted-task', instance: 'claude-other', envelope: '7'.repeat(64), messages: [{ from: 'a'.repeat(64), at: 1, content: 'cross-instance attempt' }] }) + '\n'
const deniedImport = runImport(wrongInstance)
ok('remote Codex queue import refuses a record for another identity', deniedImport.status !== 0 && /invalid admitted record/.test(deniedImport.stderr))
const notificationEnvelope = 'a'.repeat(64)
const notificationRecord = JSON.stringify({ type: 'verified-notification', instance: 'codex-desktop', envelope: notificationEnvelope,
  notification: { version: 1, type: 'verified-channel-activity', source_author: 'b'.repeat(64), source_event: 'c'.repeat(64),
    source_channel: manifest.task_carriers[0].channels[0], carrier: manifest.task_carriers[0].pubkey,
    carrier_grant_id: 'd'.repeat(64), carrier_grantor: manifest.grantors[0], reason: 'reply', observed_at: 1785930000 } }) + '\n'
const notificationImport = runImport(notificationRecord)
ok('remote import accepts a content-free verified notification through the same fixed-instance transport',
  notificationImport.status === 0 && readFileSync(desktopQueue, 'utf8').includes(notificationEnvelope) && !readFileSync(desktopQueue, 'utf8').includes('execute me'))
writeFileSync(join(root, 'run-desktop', 'codex-app-server-delivered.jsonl'), JSON.stringify({ version: 1, envelope: liveEnvelope, thread_id: desktopManifest.codex_thread_id, turn_id: '019fce6b-4727-7a13-8f80-f4a6035c277f' }) + '\n')
const requestReply = (input, receipt = liveEnvelope) => spawnSync(process.execPath, ['mcp/tools/desktop-reply-request.mjs', '--instance', 'codex-desktop', '--receipt', receipt], { cwd: resolve('.'), encoding: 'utf8', input, env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
const desktopReply = requestReply('Yes.\n'), duplicateReply = requestReply('Again.\n')
ok('the keyless Desktop can request one reply only for a notification delivered to its fixed thread', desktopReply.status === 0 && duplicateReply.status !== 0 && /already has a reply request/.test(duplicateReply.stderr) && readFileSync(join(root, 'run-desktop', 'reply-requests.jsonl'), 'utf8').includes('"content":"Yes."'))
const notificationReply = requestReply('No authority.\n', notificationEnvelope)
ok('a verified activity notification cannot acquire a reply capability at the keyless Desktop boundary',
  notificationReply.status !== 0 && /not a single-sender admitted notification/.test(notificationReply.stderr))

const syncUid = process.getuid(), syncRuntime = join(root, 'run-sync'), syncEnvelope = '6'.repeat(64)
const syncManifest = isolatedManifest(manifest, 'sync-test', { pubkey: '5'.repeat(64), runtime_dir: syncRuntime,
  watcher_uid: syncUid === 47011 ? 47015 : 47011, broker_uid: syncUid === 47012 ? 47016 : 47012, adapter_uid: syncUid, worker_uid: syncUid === 47014 ? 47017 : 47014 })
writeFileSync(join(manifestRoot, 'sync-test.json'), JSON.stringify(syncManifest)); mkdirSync(syncRuntime, { recursive: true })
writeFileSync(join(syncRuntime, 'admitted-tasks.jsonl'), JSON.stringify({ type: 'admitted-task', instance: 'sync-test', envelope: syncEnvelope, messages: [{ from: 'a'.repeat(64), at: 1, content: 'sync me' }] }) + '\n')
writeFileSync(join(syncRuntime, 'desktop-reply-requests.jsonl'), '')
const syncRequest = JSON.stringify({ version: 1, type: 'reply-request', id: '1'.repeat(32), instance: 'sync-test', receipt: syncEnvelope, content: 'Remote yes.' }) + '\n'
const runSync = input => spawnSync(process.execPath, ['mcp/tools/instance-desktop-sync.mjs', '--instance', 'sync-test'], { cwd: resolve('.'), encoding: 'utf8', input, env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
const firstSync = runSync(syncRequest), replaySync = runSync(syncRequest)
const badSync = runSync(JSON.stringify({ ...JSON.parse(syncRequest), id: '2'.repeat(32), receipt: '7'.repeat(64) }) + '\n')
ok('the restricted server sync imports a bounded admitted-envelope reply exactly once and exports only admitted tasks', firstSync.status === 0 && replaySync.status === 0 && badSync.status !== 0 && firstSync.stdout.includes(syncEnvelope) && readFileSync(join(syncRuntime, 'desktop-reply-requests.jsonl'), 'utf8').trim().split('\n').length === 1)

// Behavioral fake for the supported stdio app-server lifecycle and crash recovery. The first
// run must initialize -> read -> resume -> start with unique IDs. The second simulates a crash
// after Codex persisted the turn but before Nvoy wrote its delivery journal; thread/read must
// recover the envelope marker without starting another turn.
const spawnRuntime = join(root, 'run-spawn'), spawnThread = '019fc80b-78a6-7b72-b3d2-eced37f55da8', spawnEnvelope = '4'.repeat(64)
const spawnManifest = isolatedManifest(manifest, 'spawn-test', { pubkey: 'd'.repeat(64), runtime_dir: spawnRuntime,
  worker_image: '', worker_runner: '', worker_credential_ref: '', worker_enabled: false, delivery_mode: 'codex_app_server', codex_thread_id: spawnThread, codex_transport: 'spawn' })
writeFileSync(join(manifestRoot, 'spawn-test.json'), JSON.stringify(spawnManifest)); mkdirSync(spawnRuntime, { recursive: true })
writeFileSync(join(spawnRuntime, 'admitted-tasks.jsonl'), JSON.stringify({ type: 'admitted-task', instance: 'spawn-test', envelope: spawnEnvelope, messages: [{ from: 'a'.repeat(64), at: 1, content: 'fake lifecycle' }] }) + '\n')
const appServerFakeBin = join(root, 'fake-app-server-bin'), fakeCodex = join(appServerFakeBin, 'codex'), lifecycleLog = join(root, 'app-server-lifecycle.log')
mkdirSync(appServerFakeBin)
const fakeSource = prior => `#!/usr/bin/env node
import readline from 'node:readline'; import { appendFileSync } from 'node:fs'
const thread=${JSON.stringify(spawnThread)}, log=${JSON.stringify(lifecycleLog)}, prior=${JSON.stringify(prior)}, token=${JSON.stringify(`NVOY_ENVELOPE_ID=${spawnEnvelope}`)}
const out=x=>process.stdout.write(JSON.stringify(x)+'\\n')
readline.createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line); appendFileSync(log,m.method+':'+String(m.id||'notify')+(m.method==='turn/start'?':'+String(m.params?.clientUserMessageId||''):'')+'\\n')
if(m.method==='initialize')out({id:m.id,result:{}})
if(m.method==='thread/read')out({id:m.id,result:{thread:{id:thread,turns:prior?[{id:'019fce6b-4727-7a13-8f80-f4a6035c2770',items:[{type:'userMessage',content:[{type:'text',text:token}]}]}]:[]}}})
if(m.method==='thread/resume')out({id:m.id,result:{thread:{id:thread}}})
if(m.method==='turn/start')out({id:m.id,result:{turn:{id:'019fce6b-4727-7a13-8f80-f4a6035c2771'}}})})`
writeFileSync(fakeCodex, fakeSource(false), { mode: 0o700 })
const runSpawnAdapter = () => spawnSync(process.execPath, ['mcp/tools/codex-app-server-adapter.mjs', '--instance', 'spawn-test', '--once'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, PATH: `${appServerFakeBin}:${process.env.PATH}`, NVOY_INSTANCE_ROOT: manifestRoot } })
const firstSpawn = runSpawnAdapter(), firstLifecycle = readFileSync(lifecycleLog, 'utf8')
ok('spawn app-server uses ordered initialize/read/resume/start framing with unique request ids and an envelope-owned user-message id', firstSpawn.status === 0 && /initialize:1[\s\S]*initialized:notify[\s\S]*thread\/read:2[\s\S]*thread\/resume:3[\s\S]*turn\/start:4:nvoy:4444/.test(firstLifecycle))
unlinkSync(join(spawnRuntime, 'codex-app-server-delivered.jsonl')); writeFileSync(lifecycleLog, ''); writeFileSync(fakeCodex, fakeSource(true), { mode: 0o700 })
const recoveredSpawn = runSpawnAdapter(), recoveredLifecycle = readFileSync(lifecycleLog, 'utf8')
ok('a persisted Codex envelope marker closes the post-turn/start crash duplicate window', recoveredSpawn.status === 0 && /thread\/read:2/.test(recoveredLifecycle) && !/thread\/resume|turn\/start/.test(recoveredLifecycle) && readFileSync(join(spawnRuntime, 'codex-app-server-delivered.jsonl'), 'utf8').includes(spawnEnvelope))

const desktopPublicKey = join(root, 'desktop-sync.pub')
writeFileSync(desktopPublicKey, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly desktop\n')
const forcedKey = spawnSync(process.execPath, ['mcp/tools/instance-desktop-authorized-key.mjs', '--instance', 'codex-test', '--public-key-file', desktopPublicKey], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('the installer renders an exact restrict+forced-command SSH capability for only one instance', forcedKey.status === 0 && forcedKey.stdout.startsWith('restrict,command="/usr/bin/env NVOY_INSTANCE_ROOT=/etc/nvoy/instances /usr/bin/node /opt/nvoy/mcp/tools/instance-desktop-sync.mjs --instance codex-test" ssh-ed25519 ') && !/permitopen|environment=|pty/.test(forcedKey.stdout))
const forcedDockerKey = spawnSync(process.execPath, ['mcp/tools/instance-desktop-authorized-key.mjs', '--instance', 'codex-test', '--public-key-file', desktopPublicKey, '--container', 'nvoy-codex-jaf-adapter-1'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('the Docker installer stanza fixes container, non-root adapter UID/GID, executable, and instance without a shell', forcedDockerKey.status === 0 && forcedDockerKey.stdout.startsWith(`restrict,command="/usr/bin/docker exec -i --user ${manifest.adapter_uid}:${manifest.broker_adapter_gid} nvoy-codex-jaf-adapter-1 /usr/local/bin/node /srv/nvoy/mcp/tools/instance-desktop-sync.mjs --instance codex-test" ssh-ed25519 `))
const claudeManifest = isolatedManifest(manifest, 'claude-channel', { pubkey: 'c'.repeat(64),
  worker_image: '', worker_runner: '', worker_credential_ref: '', worker_enabled: false, delivery_mode: 'notify_only' })
writeFileSync(join(manifestRoot, 'claude-channel.json'), JSON.stringify(claudeManifest))
const forcedClaudeKey = spawnSync(process.execPath, ['mcp/tools/instance-claude-channel-authorized-key.mjs', '--instance', 'claude-channel', '--public-key-file', desktopPublicKey, '--container', 'nvoy-claude-channel-adapter-1'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('the Claude channel installer fixes a restricted worker-UID/GID MCP command distinct from the adapter', forcedClaudeKey.status === 0 &&
  forcedClaudeKey.stdout.startsWith(`restrict,command="/usr/bin/docker exec -i --user ${claudeManifest.worker_uid}:${claudeManifest.worker_handoff_gid} nvoy-claude-channel-adapter-1 /usr/local/bin/node /srv/nvoy/mcp/tools/claude-channel.mjs --instance claude-channel" ssh-ed25519 `) &&
  !forcedClaudeKey.stdout.includes(`--user ${claudeManifest.adapter_uid}:`) && !/permitopen|environment=|pty/.test(forcedClaudeKey.stdout))
writeFileSync(join(manifestRoot, 'bad-desktop.json'), JSON.stringify(isolatedManifest(manifest, 'bad-desktop', { pubkey: '4'.repeat(64), worker_image: '', worker_runner: '', worker_credential_ref: '', worker_enabled: false, delivery_mode: 'codex_app_server' })))
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
const releaseWorkerImage = 'registry.example/codex-worker@sha256:' + 'a'.repeat(64)
const renderedRelease = spawnSync(process.execPath, ['mcp/tools/render-instance-compose.mjs', '--instance', 'codex-test', '--image', image, '--worker-image', releaseWorkerImage], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('the release reconciler can override only the worker image with another immutable digest', renderedRelease.status === 0 && renderedRelease.stdout.includes(releaseWorkerImage) && !renderedRelease.stdout.includes(manifest.worker_image))
const desktopComposeManifest = isolatedManifest(manifest, 'desktop-compose', { pubkey: 'b'.repeat(64),
  worker_image: '', worker_runner: '', worker_credential_ref: '', worker_enabled: false, delivery_mode: 'codex_app_server', codex_thread_id: spawnThread, codex_transport: 'spawn' })
writeFileSync(join(manifestRoot, 'desktop-compose.json'), JSON.stringify(desktopComposeManifest))
const renderedDesktop = spawnSync(process.execPath, ['mcp/tools/render-instance-compose.mjs', '--instance', 'desktop-compose', '--image', image], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('Desktop Compose omits the independent model worker and every provider-secret provisioning path', renderedDesktop.status === 0 && !/\n  worker:/.test(renderedDesktop.stdout) && !/worker-provider|worker_credentials|nvoy_worker_provider|WORKER_CREDENTIAL|WORKER_IMAGE|WORKER_RUNNER/.test(renderedDesktop.stdout))
const desktopWorkerOverride = spawnSync(process.execPath, ['mcp/tools/render-instance-compose.mjs', '--instance', 'desktop-compose', '--image', image, '--worker-image', releaseWorkerImage], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot } })
ok('a worker release cannot silently add a model worker to a worker-disabled Desktop identity', desktopWorkerOverride.status !== 0 && /worker-disabled/.test(desktopWorkerOverride.stderr))
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
ok('the NIP-59 baseline cannot silently truncate at 5,000 ids', /SEEN_CAP = 100_000/.test(wakeSource) && /baseline exceeds/.test(wakeSource) && !/seen\.size > 5000/.test(wakeSource))
ok('watcher markers and adapter socket are group-limited to the matching broker', /chmodSync\(p, 0o660\)/.test(wakeSource) && /manifest\.brokerAdapterGid/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /chmodSync\(socket, 0o660\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')))
ok('the worker has no adapter-socket group but has a separate read-only handoff group', manifest.broker_adapter_gid !== manifest.worker_handoff_gid && rendered.stdout.includes('group_add: ["' + manifest.worker_handoff_gid + '"]') && !workerPart.includes(String(manifest.broker_adapter_gid)))
const claudeChannelSource = readFileSync('mcp/tools/claude-channel.mjs', 'utf8')
const runtimeInitSource = readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')
ok('the native Claude channel consumes as worker UID with read-only admission and separate writable state/reply paths',
  /process\.getuid.*manifest\.workerUid/.test(claudeChannelSource) && !/process\.getuid.*manifest\.adapterUid/.test(claudeChannelSource) &&
  /claude-channel-state/.test(claudeChannelSource) && /reply-requests\.jsonl/.test(claudeChannelSource) &&
  /deliveryMode === 'notify_only'.*claude-channel-state/.test(runtimeInitSource.replace(/\n/g, ' ')))
ok('broker can traverse the adapter runtime but cannot replace its socket or queue', /chmodSync\(manifest\.runtimeDir, 0o711\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /provision\(m\.runtimeDir, m\.adapterUid, m\.brokerAdapterGid, 0o711/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')))
const workerSource = readFileSync('mcp/tools/instance-worker.mjs', 'utf8')
const codexDesktopSource = readFileSync('mcp/tools/codex-app-server-adapter.mjs', 'utf8')
const desktopPromptSource = readFileSync('mcp/tools/desktop_instruction_prompt.mjs', 'utf8')
const codexTransportSource = readFileSync('mcp/tools/codex_app_server.mjs', 'utf8')
const admittedExportSource = readFileSync('mcp/tools/instance-admitted-export.mjs', 'utf8')
const admittedImportSource = readFileSync('mcp/tools/instance-admitted-import.mjs', 'utf8')
const remoteBridgeSource = readFileSync('mcp/tools/codex-remote-bridge.mjs', 'utf8')
ok('Desktop delivery mode disables the independent headless model drain before reading a provider credential', /manifest\.deliveryMode !== 'headless'/.test(workerSource) && /headless model drain disabled/.test(workerSource) && workerSource.indexOf("manifest.deliveryMode !== 'headless'") < workerSource.indexOf('let providerKey'))
const desktopReplySource = readFileSync('mcp/tools/desktop-reply-request.mjs', 'utf8')
const desktopSyncSource = readFileSync('mcp/tools/instance-desktop-sync.mjs', 'utf8')
ok('the Codex context adapter resumes only the manifest-bound thread after broker admission, with no Nostr key or network listener', /thread\/resume/.test(codexTransportSource) && /threadId: id/.test(codexTransportSource) && /turn\/start/.test(codexTransportSource) && /local_control_socket/.test(codexDesktopSource) && /admitted-tasks\.jsonl/.test(codexDesktopSource) && !/NVOY_NSEC|NVOY_BROKER_CREDENTIAL|bunker:|wss:\/\//.test(codexDesktopSource + codexTransportSource))
ok('remote desktop delivery exports only adapter-admitted records and imports them without any Nostr credential', /process\.getuid.*manifest\.adapterUid/.test(admittedExportSource) && /admitted-tasks\.jsonl/.test(admittedExportSource) && /--baseline/.test(admittedImportSource) && /remote-imported\.jsonl/.test(admittedImportSource) && !/NVOY_NSEC|NVOY_BROKER_CREDENTIAL|bunker:|wss:\/\//.test(admittedExportSource + admittedImportSource))
ok('remote import queues before advancing its cursor, closing the crash-loss window', admittedImportSource.indexOf('appendFileSync(queue') < admittedImportSource.indexOf('appendFileSync(cursor'))
ok('the remote Codex bridge uses a manifest-fixed restricted duplex sync, pinned host integrity, and a keyless child environment', /BatchMode=yes/.test(remoteBridgeSource) && /StrictHostKeyChecking=yes/.test(remoteBridgeSource) && /ClearAllForwardings=yes/.test(remoteBridgeSource) && /sshKnownHostsSha256/.test(remoteBridgeSource) && /input: replies/.test(remoteBridgeSource) && /const childEnv = \{ HOME:/.test(remoteBridgeSource) && !/\.\.\.process\.env/.test(remoteBridgeSource) && !/NVOY_NSEC|NVOY_BROKER_CREDENTIAL|bunker:|wss:\/\//.test(remoteBridgeSource + desktopReplySource + desktopSyncSource))
ok('Desktop reply tooling cannot choose a recipient or sign; server sync runs only as the credential-free manifest adapter UID', /codex-app-server-delivered\.jsonl/.test(desktopReplySource) && /already has a reply request/.test(desktopReplySource) && /process\.getuid.*manifest\.adapterUid/.test(desktopSyncSource) && /desktop-reply-requests\.jsonl/.test(desktopSyncSource) && !/recipient|\[['"]p['"]|signEvent|nip44|finalizeEvent/.test(desktopReplySource + desktopSyncSource))
ok('the worker has a separate UID and can use only pre-provisioned cross-UID handoff paths', rendered.stdout.includes('\"41014:' + manifest.worker_handoff_gid + '\"') && /admitted-tasks\.jsonl.*workerHandoffGid.*0o640/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')) && /reply-requests\.jsonl.*brokerAdapterGid.*0o640/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')) && /worker-input.*workerHandoffGid.*0o710/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')) && /renameSync\(tmp, input\)/.test(readFileSync('mcp/tools/instance-adapter.mjs', 'utf8')) && /worker-input/.test(workerSource) && !/writeFileSync\(inputPath/.test(workerSource))
ok('watcher cooldown coalesces notifications but never skips durable queueing', /function record\(id\)[\s\S]*appendFileSync[\s\S]*if \(now - lastWake < cooldown\) return true/.test(wakeSource))
const brokerSource = readFileSync('mcp/tools/instance-broker.mjs', 'utf8')
ok('an unverifiable live policy requeues the opaque marker instead of consuming it as a denial', /if \(!report\.policyUsable\)[\s\S]*renameSync\(markerPath, pendingMarker\)[\s\S]*process\.exit\(75\)/.test(brokerSource) && !/!report\.policyUsable \|\|/.test(brokerSource))
ok('broker atomically claims the exact pending marker before decrypting', /renameSync\(pendingMarker, markerPath\)/.test(brokerSource) && /--envelope', envelope/.test(brokerSource))
ok('a broker claims a per-state exclusive lock before decrypting', /openSync\(lockPath, 'wx'/.test(brokerSource) && /process\.kill\(prior\.pid, 0\)/.test(brokerSource))
ok('the broker records an identity-bound, expiry-limited admission receipt before any keyless worker can request a reply', /broker: manifest\.pubkey, envelope/.test(brokerSource) && /sender: String\(admission\.from\)/.test(brokerSource) && /grant_id: String\(admission\.grant_id\)/.test(brokerSource) && /expires_at: Date\.now\(\) \+ 5 \* 60 \* 1000/.test(brokerSource))
ok('the broker carries its verified task authority into Desktop delivery instead of downgrading it to generic data',
  /type: 'scoped-instruction'/.test(brokerSource) && /scope_subject: manifest\.pubkey/.test(brokerSource) &&
  /authenticated sender text above is a user instruction/.test(desktopPromptSource) &&
  /DATA-ONLY NOSTR NOTIFICATION/.test(desktopPromptSource) &&
  /desktopInstructionPrompt/.test(codexDesktopSource))
ok('the Desktop adapter gives each admitted envelope a stable app-server user-message id',
  /return `nvoy:\$\{task\.envelope\}`/.test(codexDesktopSource) &&
  /clientUserMessageId: userMessageId\(task\)/.test(codexDesktopSource) &&
  /clientUserMessageId/.test(codexTransportSource))
const daemonSource = readFileSync('mcp/tools/instance-broker-daemon.mjs', 'utf8')
ok('the broker daemon rate-limits retries after transient policy failures', /retryAfter\.get\(item\.envelope\)/.test(daemonSource) && /Date\.now\(\) \+ 5000/.test(daemonSource))
ok('broker restart requeues only interrupted inflight markers and prioritizes the newest opaque observation', /\.inflight/.test(daemonSource) && /\.pending/.test(daemonSource) && /marker\.observed_at/.test(daemonSource) && /b\.observed - a\.observed/.test(daemonSource) && /setInterval\(drain, 1000\)/.test(daemonSource))
mkdirSync(manifest.state_dir, { recursive: true })
const terminalReplies = join(manifest.state_dir, 'terminal-replies.jsonl')
const terminalIds = loadTerminalReplyIds(terminalReplies)
const expiredRequest = 'a'.repeat(32)
ok('a missing or stale admission receipt is terminal, rather than a relay-query retry loop', isTerminalReplyFailure('instance-broker-reply: admission receipt is missing') && isTerminalReplyFailure('instance-broker-reply: admission receipt is not a live broker-bound sender capability') && recordTerminalReply(terminalReplies, terminalIds, expiredRequest, 'admission receipt is not a live broker-bound sender capability', 1) && terminalIds.has(expiredRequest) && !recordTerminalReply(terminalReplies, terminalIds, expiredRequest, 'admission receipt is not a live broker-bound sender capability', 2) && loadTerminalReplyIds(terminalReplies).has(expiredRequest) && !readFileSync(terminalReplies, 'utf8').includes('must not be signed'))
ok('the broker daemon invokes only the mechanically bounded prepare mode and has no approval input',
  /awaiting discrete approval/.test(daemonSource) && /instance-broker-reply\.mjs/.test(daemonSource) &&
  /'--prepare'/.test(daemonSource) && !/'--approval'/.test(daemonSource))
// Assert the wiring, not just the module. The isolated reply_retry assertions above pass identically
// whether or not the daemon ever calls them — which is exactly how the Aug 6 rewrite dropped these
// call sites with a green suite. A component test cannot fail when the component is unplugged.
ok('the broker daemon actually consults and records terminal replies rather than re-proposing forever',
  /terminalReplyIds\.has\(request\)/.test(daemonSource) && /isTerminalReplyFailure\(/.test(daemonSource) &&
  /recordTerminalReply\(/.test(daemonSource) && /loadTerminalReplyIds\(/.test(daemonSource))
const publishedDir = join(manifest.state_dir, 'outbound')
mkdirSync(publishedDir, { recursive: true })
const publishedRequest = 'b'.repeat(32)
const publishedQueue = join(manifest.runtime_dir, 'published-reply-test.jsonl')
mkdirSync(manifest.runtime_dir, { recursive: true })
const publishedRequestRecord = { version: 1, type: 'reply-request', id: publishedRequest, instance: 'codex-test', receipt: 'a'.repeat(64), content: 'completed reply' }
writeFileSync(publishedQueue, JSON.stringify(publishedRequestRecord) + '\n')
const publishedRequestDigests = loadReplyRequestDigests([publishedQueue], 'codex-test')
const publishedWrap = JSON.parse(JSON.stringify(finalizeEvent({ kind: 1059, created_at: 1, tags: [['p', pubkey]], content: 'ciphertext' }, generateSecretKey())))
const validPublishedRecord = { version: 1, request_id: publishedRequest, request_digest: publishedRequestDigests.get(publishedRequest), wrap: publishedWrap, published: true, published_at: 1, accepted: 1 }
writeFileSync(join(publishedDir, `${publishedRequest}.json`), JSON.stringify(validPublishedRecord))
writeFileSync(join(publishedDir, `${'c'.repeat(32)}.json`), JSON.stringify({ version: 1, request_id: 'c'.repeat(32), published: false }))
writeFileSync(join(publishedDir, `${'d'.repeat(32)}.json`), JSON.stringify({ version: 1, request_id: 'd'.repeat(32), request_digest: 'e'.repeat(64), wrap: { ...publishedWrap, sig: '0'.repeat(128) }, published: true, published_at: 1, accepted: 1 }))
const completedReplies = loadPublishedReplyIds(publishedDir, publishedRequestDigests)
writeFileSync(join(publishedDir, `${publishedRequest}.json`), JSON.stringify({ ...validPublishedRecord, request_digest: '0'.repeat(64) }))
const wrongDigestReplies = loadPublishedReplyIds(publishedDir, publishedRequestDigests)
writeFileSync(join(publishedDir, `${publishedRequest}.json`), JSON.stringify({ ...validPublishedRecord, wrap: { ...publishedWrap, sig: '0'.repeat(128) } }))
const forgedWrapReplies = loadPublishedReplyIds(publishedDir, publishedRequestDigests)
writeFileSync(join(publishedDir, `${publishedRequest}.json`), JSON.stringify(validPublishedRecord))
ok('only an exact-request-digest-bound valid signed published wrap is recognized as a historical completion', completedReplies.has(publishedRequest) && !wrongDigestReplies.has(publishedRequest) && !forgedWrapReplies.has(publishedRequest) && !completedReplies.has('c'.repeat(32)) && !completedReplies.has('d'.repeat(32)))
const sourceIndex = join(manifest.state_dir, 'channel-source-admissions.jsonl')
const sourceEvent = 'e'.repeat(64), firstCarrierEnvelope = 'f'.repeat(64), rewrappedEnvelope = 'a'.repeat(64)
const firstSource = claimChannelSource(sourceIndex, sourceEvent, firstCarrierEnvelope)
const sameEnvelopeRetry = claimChannelSource(sourceIndex, sourceEvent, firstCarrierEnvelope)
const sourceCompleted = completeChannelSource(sourceIndex, sourceEvent, firstCarrierEnvelope)
const completionReplay = completeChannelSource(sourceIndex, sourceEvent, firstCarrierEnvelope)
const afterRestartRewrap = claimChannelSource(sourceIndex, sourceEvent, rewrappedEnvelope)
ok('two carrier envelopes for one signed source yield one durable admission across retry and restart', firstSource.accepted && !firstSource.replay && sameEnvelopeRetry.accepted && sameEnvelopeRetry.replay && sourceCompleted && !completionReplay && !afterRestartRewrap.accepted && channelSourceClaims(sourceIndex).get(sourceEvent)?.state === 'delivered')
ok('channel source is claimed before any instruction receipt or instruction adapter delivery, so task-relay cannot amplify author authority', brokerSource.indexOf('claimChannelSource(') < brokerSource.indexOf('const receipt =') && brokerSource.indexOf('claimChannelSource(') < brokerSource.indexOf('const payload ='))
const initSource = readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')
ok('a root-only initializer provisions all three volume roots, a credential-free Desktop queue, and role-owned credential copies', /process\.getuid\?\.\(\) !== 0/.test(initSource) && /provision\(m\.stateDir/.test(initSource) && /provision\(m\.spoolDir/.test(initSource) && /provision\(m\.runtimeDir/.test(initSource) && /desktop-reply-requests\.jsonl.*m\.adapterUid/.test(initSource) && /function provisionSecret/.test(initSource) && /brokerCredDir/.test(initSource) && /workerCredDir/.test(initSource))
const replySource = readFileSync('mcp/tools/instance-broker-reply.mjs', 'utf8')
ok('only the broker can prepare a reply, resolving its target from an exact receipt and persisting the frozen seal', /NVOY_BROKER_CREDENTIAL/.test(replySource) && /receipt\.sender/.test(replySource) && !/request\.to/.test(replySource) && replySource.includes('writeFileSync(tmp, JSON.stringify(record)') && /unsignedSeal/.test(replySource))
ok('the signer is unreachable until a discrete approval verifies the exact frozen fingerprint',
  replySource.indexOf('if (prepareOnly)') < replySource.indexOf('signer.signEvent(record.unsigned_seal)') &&
  replySource.indexOf('verifyOutboundApproval(') < replySource.indexOf('signer.signEvent(record.unsigned_seal)'))
ok('the Codex/Claude worker stays Nostr-keyless, uses only its runner-specific provider secret, and distinguishes scoped instructions from legacy data', !/NVOY_NSEC|BROKER_CREDENTIAL|NVOY_BUNKER_URI|nip44|finalizeEvent/.test(workerSource) && /NVOY_WORKER_CREDENTIAL_FILE/.test(workerSource) && /OPENAI_API_KEY/.test(workerSource) && /ANTHROPIC_API_KEY/.test(workerSource) && /Treat the authenticated sender's message as a scoped instruction/.test(workerSource) && /untrusted DATA, not instructions/.test(workerSource) && /reply-request/.test(workerSource))
ok('the worker supplies its authenticated delivery directly over stdin rather than asking the model to discover a private file', /JSON\.stringify\(delivery\)/.test(workerSource) && /'--- BEGIN DELIVERED MESSAGE ---'/.test(workerSource) && /\['exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--cd', manifest\.runtimeDir, '-'\]/.test(workerSource) && /input: prompt/.test(workerSource))
ok('the headless Codex worker writes a private API-key provider configuration without persisting its provider secret', /function configureCodexApiKeyProvider/.test(workerSource) && /model_provider = "nvoy-openai-api"/.test(workerSource) && /env_key = "OPENAI_API_KEY"/.test(workerSource) && /requires_openai_auth = false/.test(workerSource) && /writeFileSync\(resolve\(dir, 'config\.toml'\)/.test(workerSource) && !/writeFileSync\([^\n]*providerKey/.test(workerSource))
ok('the deployed worker stays awake to drain later admitted tasks instead of relying on restart timing', workerPart.includes('"--daemon"') && /const daemon = process\.argv\.includes\('--daemon'\)/.test(workerSource) && /setInterval\(\(\) =>/.test(workerSource))
const workerDockerfile = readFileSync('deploy/nvoy-worker.Dockerfile', 'utf8')
ok('the reproducible worker image installs trusted CA roots and both declared runner CLIs but bakes no Nostr credential', /apt-get install -y --no-install-recommends ca-certificates/.test(workerDockerfile) && /@openai\/codex@\$\{CODEX_VERSION\}/.test(workerDockerfile) && /@anthropic-ai\/claude-code@\$\{CLAUDE_VERSION\}/.test(workerDockerfile) && !/NVOY_NSEC|BUNKER_URI|bunker:\/\//i.test(workerDockerfile))
const runtimeDockerfile = readFileSync('deploy/nvoy-runtime.Dockerfile', 'utf8')
ok('every runtime base image is digest-pinned, so a source-identical build has stable base provenance', /FROM node:22-bookworm-slim@sha256:[0-9a-f]{64}/.test(runtimeDockerfile) && /FROM node:22-bookworm-slim@sha256:[0-9a-f]{64}/.test(workerDockerfile))

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
const packet = { type: 'admitted-task', instance: 'codex-test', envelope: 'b'.repeat(64),
  authority: { version: 1, type: 'scoped-instruction', sender: 'a'.repeat(64), grant_id: 'e'.repeat(64),
    grantor: manifest.grantors[0], cap: 'task', scope_subject: pubkey, policy_checked_at: Date.now() },
  messages: [{ from: 'a'.repeat(64), at: 1, content: 'only broker-admitted text' }] }
ok('broker authority is accepted only when grant, scope, capability, and every sender bind',
  validateAdmittedTask(packet, { instance: 'codex-test', scopeSubject: pubkey, grantors: manifest.grantors }).trustedInstruction === true)
let forgedAuthorityRejected = false
try { validateAdmittedTask({ ...packet, authority: { ...packet.authority, sender: '9'.repeat(64) } }, { instance: 'codex-test', scopeSubject: pubkey, grantors: manifest.grantors }) }
catch { forgedAuthorityRejected = true }
ok('a sender mismatch cannot turn admitted data into a trusted instruction', forgedAuthorityRejected)
let wrongScopeRejected = false
try { validateAdmittedTask({ ...packet, authority: { ...packet.authority, scope_subject: '9'.repeat(64) } }, { instance: 'codex-test', scopeSubject: pubkey, grantors: manifest.grantors }) }
catch { wrongScopeRejected = true }
ok('authority scoped to another participant identity is rejected at the keyless boundary', wrongScopeRejected)
let wrongGrantorRejected = false
try { validateAdmittedTask({ ...packet, authority: { ...packet.authority, grantor: '8'.repeat(64) } }, { instance: 'codex-test', scopeSubject: pubkey, grantors: manifest.grantors }) }
catch { wrongGrantorRejected = true }
ok('authority from outside the manifest grantor set is rejected at the keyless boundary', wrongGrantorRejected)
const carriedPacket = { ...packet, envelope: 'c'.repeat(64),
  authority: { ...packet.authority, version: 2, carrier: '7'.repeat(64), carrier_grant_id: '6'.repeat(64),
    carrier_grantor: manifest.grantors[0], source_event: '5'.repeat(64), reply_channel: manifest.task_carriers[0].channels[0] },
  messages: [{ from: packet.authority.sender, at: 2, content: 'signed channel instruction', event_id: '5'.repeat(64), kind: 9 }] }
ok('channel authority requires the original sender plus a separately configured carrier and reply channel',
  validateAdmittedTask(carriedPacket, { instance: 'codex-test', scopeSubject: pubkey, grantors: manifest.grantors, carriers: manifest.task_carriers }).trustedInstruction === true)
let wrongCarrierRejected = false
try { validateAdmittedTask({ ...carriedPacket, authority: { ...carriedPacket.authority, carrier: '4'.repeat(64) } }, { instance: 'codex-test', scopeSubject: pubkey, grantors: manifest.grantors, carriers: manifest.task_carriers }) }
catch { wrongCarrierRejected = true }
ok('an unconfigured carrier cannot launder channel text into an instruction', wrongCarrierRejected)
let redirectedChannelRejected = false
try { validateAdmittedTask({ ...carriedPacket, authority: { ...carriedPacket.authority, reply_channel: 'ffffffff-ffff-ffff-ffff-ffffffffffff' } }, { instance: 'codex-test', scopeSubject: pubkey, grantors: manifest.grantors, carriers: manifest.task_carriers }) }
catch { redirectedChannelRejected = true }
ok('a carrier cannot redirect authority or replies to another channel', redirectedChannelRejected)
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
ok('the keyed broker requires an explicit prepare-or-approval mode before evaluating any reply',
  deniedReply.status !== 0 && /--prepare.*--approval/.test(deniedReply.stderr))
const deniedPrepare = spawnSync(process.execPath, ['mcp/tools/instance-broker-reply.mjs', '--instance', 'codex-test', '--request', deniedRequest.id, '--prepare'], {
  cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot, NVOY_BROKER_CREDENTIAL: credential },
})
// This receipt is long expired AND has no live grant behind it. It must still be refused — but
// #150 moved the reason. The deadline started at admission, ran out before the agent could act,
// and made legitimate wakes permanently unanswerable; authorisation now comes from the
// present-tense policy re-check, which re-derives the chain from live relays. So assert the
// property that matters — nothing is signed without a live matching chain — and assert the
// refusal is NOT the clock, or this test would keep passing for a reason that no longer
// protects anything.
ok('prepare mode still refuses a proposal with no live matching grant chain',
  deniedPrepare.status !== 0 &&
  /no longer has a live matching grant chain|could not recheck live grant policy/.test(deniedPrepare.stderr))
ok('...and it is refused by present-tense policy rather than by an expiry clock',
  !/not a live broker-bound sender capability/.test(deniedPrepare.stderr))

writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...manifest, id: 'collision', runtime_dir: join(root, 'run-other') }))
const collision = cli('describe', '--instance', 'codex-test')
ok('duplicate participant pubkeys are refused before a runtime starts', collision.status !== 0 && /collision/.test(collision.stderr))
const isolated = { ...manifest, id: 'collision', pubkey: '0'.repeat(64), service_user: 'nvoy-collision',
  state_dir: join(root, 'state-collision'), runtime_dir: join(root, 'run-collision'), spool_dir: join(root, 'spool-collision'),
  watcher_uid: 42011, broker_uid: 42012, adapter_uid: 42013, worker_uid: 42014,
  broker_adapter_gid: brokerAdapterGid + 100, worker_handoff_gid: workerHandoffGid + 100,
  key_ref: '/etc/nvoy/credentials/collision.nsec', bunker_uri_ref: '/etc/nvoy/credentials/collision.bunker',
  bunker_client_ref: '/etc/nvoy/credentials/collision.client', worker_credential_ref: '/etc/nvoy/credentials/collision.provider' }

writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...isolated, broker_uid: manifest.watcher_uid }))
const uidCollision = cli('describe', '--instance', 'codex-test')
ok('a service UID cannot be reused by another role in another instance', uidCollision.status !== 0 && /service UID collision/.test(uidCollision.stderr))
writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...isolated, worker_handoff_gid: manifest.broker_adapter_gid }))
const gidCollision = cli('describe', '--instance', 'codex-test')
ok('a service GID cannot be reused by another group in another instance', gidCollision.status !== 0 && /service GID collision/.test(gidCollision.stderr))
writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...isolated, bunker_client_ref: manifest.bunker_uri_ref }))
const credentialCollision = cli('describe', '--instance', 'codex-test')
ok('a credential path cannot be reused under another credential role', credentialCollision.status !== 0 && /credential reference collision/.test(credentialCollision.stderr))
writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...isolated, state_dir: manifest.runtime_dir }))
const pathCollision = cli('describe', '--instance', 'codex-test')
ok('a filesystem root cannot be reused under another runtime role', pathCollision.status !== 0 && /filesystem root collision/.test(pathCollision.stderr))
writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify({ ...isolated, service_user: manifest.service_user }))
const userCollision = cli('describe', '--instance', 'codex-test')
ok('a named service user cannot be shared by two participant instances', userCollision.status !== 0 && /service user collision/.test(userCollision.stderr))
// Keep the manifest set valid for the independent spool-root collision case below.
writeFileSync(join(manifestRoot, 'collision.json'), JSON.stringify(isolated))

const symlinkRoot = join(root, 'symlink-instances')
mkdirSync(symlinkRoot)
mkdirSync(join(root, 'real-state'))
symlinkSync(join(root, 'real-state'), join(root, 'linked-state'))
writeFileSync(join(symlinkRoot, 'symlink-test.json'), JSON.stringify({ ...manifest, id: 'symlink-test', state_dir: join(root, 'linked-state'), runtime_dir: join(root, 'run-safe') }))
const symlinked = spawnSync(process.execPath, ['mcp/tools/instance-runtime.mjs', 'describe', '--instance', 'symlink-test'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: symlinkRoot } })
ok('symlinked state roots are refused before a runtime starts', symlinked.status !== 0 && /never a symlink/.test(symlinked.stderr))

writeFileSync(join(manifestRoot, 'spool-collision.json'), JSON.stringify({ ...isolated, id: 'spool-collision', pubkey: '1'.repeat(64), service_user: 'nvoy-spool-collision', state_dir: join(root, 'state-other'), runtime_dir: join(root, 'run-other'), spool_dir: manifest.spool_dir,
  watcher_uid: 43011, broker_uid: 43012, adapter_uid: 43013, worker_uid: 43014,
  broker_adapter_gid: brokerAdapterGid + 200, worker_handoff_gid: workerHandoffGid + 200,
  key_ref: '/etc/nvoy/credentials/spool.nsec', bunker_uri_ref: '/etc/nvoy/credentials/spool.bunker',
  bunker_client_ref: '/etc/nvoy/credentials/spool.client', worker_credential_ref: '/etc/nvoy/credentials/spool.provider' }))
const spoolCollision = cli('describe', '--instance', 'codex-test')
ok('shared watcher spool roots are refused before a runtime starts', spoolCollision.status !== 0 && /filesystem root collision/.test(spoolCollision.stderr))

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
