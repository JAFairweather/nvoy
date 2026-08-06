import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { realpathSync } from 'node:fs'
import { spawnSync } from 'node:child_process'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-claude-doctor-'))
const tool = resolve('mcp/tools/claude-channel-doctor.mjs')
const identity = join(root, 'identity'), known = join(root, 'known_hosts'), claude = join(root, 'claude')
writeFileSync(identity, 'PRIVATE-CONTENT-MUST-NEVER-PRINT\n', { mode: 0o600 })
writeFileSync(known, 'broker.example ssh-ed25519 AAAAC3NzaTest\n', { mode: 0o644 })
const makeClaude = version => { writeFileSync(claude, `#!/bin/sh\necho '${version}'\n`, { mode: 0o700 }); chmodSync(claude, 0o700) }
const client = ({ claudeFile = claude, identityFile = identity, knownHostsFile = known, target = 'nvoy-channel@broker.example', cwd } = {}) => spawnSync(process.execPath,
  [tool, '--mode', 'client', '--server', 'nvoy-claude-jaf', '--claude', claudeFile,
    '--identity-file', identityFile, '--known-hosts-file', knownHostsFile, '--ssh-target', target], { encoding: 'utf8', cwd })

makeClaude('2.1.80 (Claude Code)')
const good = client(), description = JSON.parse(good.stdout || '{}')
ok('client doctor accepts the minimum native Channel version', good.status === 0 && description.claudeVersion === '2.1.80')
ok('client doctor renders a closed, host-pinned, identity-scoped stdio tunnel', description.mcpConfig?.mcpServers?.['nvoy-claude-jaf']?.args?.join(' ').includes('StrictHostKeyChecking=yes') && description.mcpConfig.mcpServers['nvoy-claude-jaf'].args.includes('-F') && description.mcpConfig.mcpServers['nvoy-claude-jaf'].args.includes('/dev/null'))
ok('client doctor emits the exact native Channel opt-in', description.launch?.at(-1) === 'server:nvoy-claude-jaf')
ok('client doctor never prints private credential contents', !good.stdout.includes('PRIVATE-CONTENT-MUST-NEVER-PRINT'))
ok('client doctor renders canonical absolute paths only', description.launch?.[0] === realpathSync(claude) && description.mcpConfig.mcpServers['nvoy-claude-jaf'].args.includes(realpathSync(identity)) && description.mcpConfig.mcpServers['nvoy-claude-jaf'].args.some(arg => arg === `UserKnownHostsFile=${realpathSync(known)}`))

const relativeClaude = client({ claudeFile: 'claude', cwd: root })
ok('client doctor refuses a relative Claude executable even when it resolves in cwd', relativeClaude.status !== 0 && /path must be absolute/.test(relativeClaude.stderr))
const relativeIdentity = client({ identityFile: 'identity', cwd: root })
ok('client doctor refuses a relative identity path', relativeIdentity.status !== 0 && /path must be absolute/.test(relativeIdentity.stderr))
const relativeKnown = client({ knownHostsFile: 'known_hosts', cwd: root })
ok('client doctor refuses a relative known_hosts path', relativeKnown.status !== 0 && /path must be absolute/.test(relativeKnown.stderr))
const writableClaude = join(root, 'writable-claude'); writeFileSync(writableClaude, '#!/bin/sh\necho "2.2.0"\n', { mode: 0o777 }); chmodSync(writableClaude, 0o777)
const writableExecutable = client({ claudeFile: writableClaude })
ok('client doctor refuses a group/world-writable Claude executable', writableExecutable.status !== 0 && /not group\/world writable/.test(writableExecutable.stderr))

makeClaude('2.1.79 (Claude Code)')
const old = client()
ok('client doctor refuses Claude versions before native Channels', old.status !== 0 && /2\.1\.80 or newer/.test(old.stderr))
makeClaude('2.2.0 (Claude Code)')
chmodSync(identity, 0o640)
const loose = client()
ok('client doctor refuses a group-readable SSH identity', loose.status !== 0 && /mode 0600/.test(loose.stderr))
chmodSync(identity, 0o600)
const identityLink = join(root, 'identity-link'); symlinkSync(identity, identityLink)
const linked = client({ identityFile: identityLink })
ok('client doctor refuses a symlink SSH identity', linked.status !== 0 && /non-symlink/.test(linked.stderr))
const hostile = client({ target: '-oProxyCommand=bad' })
ok('client doctor refuses a caller-shaped SSH target', hostile.status !== 0 && /client usage/.test(hostile.stderr))
const replaceable = join(root, 'replaceable'); mkdirSync(replaceable, { mode: 0o777 }); chmodSync(replaceable, 0o777)
const replaceableKnown = join(replaceable, 'known_hosts'); writeFileSync(replaceableKnown, 'broker.example ssh-ed25519 AAAAC3NzaTest\n', { mode: 0o644 })
const replaceablePath = client({ knownHostsFile: replaceableKnown })
ok('client doctor refuses a credential beneath a replaceable parent directory', replaceablePath.status !== 0 && /non-replaceable/.test(replaceablePath.stderr))

const manifests = join(root, 'instances'); mkdirSync(manifests)
const publicKey = join(root, 'channel.pub'); writeFileSync(publicKey, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly channel\n', { mode: 0o600 })
const manifest = { version: 1, id: 'claude-test', pubkey: '1'.repeat(64), grantors: ['2'.repeat(64)], relays: ['wss://nos.lol'],
  state_dir: join(root, 'state'), runtime_dir: join(root, 'runtime'), spool_dir: join(root, 'spool'), key_ref: '/run/secrets/claude-test',
  broker_adapter_gid: 42011, worker_handoff_gid: 42012, watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  broker_mode: 'local', worker_enabled: false, delivery_mode: 'notify_only' }
writeFileSync(join(manifests, 'claude-test.json'), JSON.stringify(manifest))
const broker = spawnSync(process.execPath, [tool, '--mode', 'broker', '--instance', 'claude-test', '--public-key-file', publicKey, '--container', 'nvoy-claude-1'], { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
const brokerDescription = JSON.parse(broker.stdout || '{}')
ok('broker doctor validates and binds a notify-only identity', broker.status === 0 && brokerDescription.instance === 'claude-test' && brokerDescription.recipient === '1'.repeat(64))
ok('broker doctor emits the exact worker UID/GID baseline before key installation', brokerDescription.baseline?.includes('41014:42012') && /baseline before/.test(brokerDescription.invariants?.[0] || ''))
const relativePublic = spawnSync(process.execPath, [tool, '--mode', 'broker', '--instance', 'claude-test', '--public-key-file', 'channel.pub', '--container', 'nvoy-claude-1'], { encoding: 'utf8', cwd: root, env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
ok('broker doctor refuses a relative public-key path', relativePublic.status !== 0 && /path must be absolute/.test(relativePublic.stderr))
const wrongManifest = { ...manifest, id: 'claude-wrong', pubkey: '3'.repeat(64), state_dir: join(root, 'wrong-state'), runtime_dir: join(root, 'wrong-runtime'), spool_dir: join(root, 'wrong-spool'), delivery_mode: 'headless', worker_enabled: false }
writeFileSync(join(manifests, 'claude-wrong.json'), JSON.stringify(wrongManifest))
const wrong = spawnSync(process.execPath, [tool, '--mode', 'broker', '--instance', 'claude-wrong', '--public-key-file', publicKey, '--container', 'nvoy-claude-1'], { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
ok('broker doctor refuses a non-notify-only identity', wrong.status !== 0 && /notify_only/.test(wrong.stderr))

if (fails) process.exit(1)
