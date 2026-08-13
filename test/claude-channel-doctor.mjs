import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, symlinkSync, openSync, ftruncateSync, closeSync } from 'node:fs'
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

// #186. The doctor never READS the Claude executable — it stats it, checks its mode bits and spawns
// it with `--version` — so the 64 MB cap guarded nothing and refused every shipped binary (2.1.229
// is 281 MB). Client mode could not succeed for anyone. This is the load-bearing assertion: it is
// the case that was broken in production, and it must be a real oversized file, not a mock.
//
// Sparse, so the 70 MB is apparent size and ~4 KB on disk. lstat reports the apparent size, which
// is what the cap compared against.
const bigClaude = join(root, 'big-claude')
writeFileSync(bigClaude, '#!/bin/sh\necho "2.2.0 (Claude Code)"\nexit 0\n', { mode: 0o700 })
{ const fd = openSync(bigClaude, 'r+'); ftruncateSync(fd, 70 * 1024 * 1024); closeSync(fd) }
chmodSync(bigClaude, 0o700)
const big = client({ claudeFile: bigClaude })
ok('client doctor accepts a Claude executable larger than the old 64 MB cap (#186)',
  big.status === 0 && JSON.parse(big.stdout || '{}').claudeVersion === '2.2.0')

// The three conditions `regular()` used to collapse into one string. Asserting only that each is
// REFUSED cannot tell a correct refusal from a correct refusal with a misleading explanation — and
// that is precisely what cost an hour here: the oversized binary is a regular non-symlink file, but
// the message said "must be a bounded regular non-symlink file", and `claude` on PATH genuinely IS
// an nvm symlink, so the most legible word in the refusal confirmed the wrong hypothesis.
const bigKnown = join(root, 'big-known-hosts')
writeFileSync(bigKnown, `${'broker.example ssh-ed25519 AAAAC3NzaTest\n'.repeat(8000)}`, { mode: 0o644 })
const oversize = client({ knownHostsFile: bigKnown })
ok('a file the doctor DOES read is still capped, and says so by name',
  oversize.status !== 0 && /known_hosts file is \d+ bytes, above the 262144-byte limit/.test(oversize.stderr))
ok('  …and names neither of the other two conditions', !/symlink|regular file/.test(oversize.stderr))

const claudeDir = join(root, 'claude-dir'); mkdirSync(claudeDir, { mode: 0o755 })
const notRegular = client({ claudeFile: claudeDir })
ok('a non-regular path is refused for being non-regular, not for its size',
  notRegular.status !== 0 && /Claude executable must be a regular file/.test(notRegular.stderr) && !/bytes|symlink/.test(notRegular.stderr))

const claudeLink = join(root, 'claude-link'); symlinkSync(claude, claudeLink)
const linkedClaude = client({ claudeFile: claudeLink })
ok('a symlink is refused for being a symlink, not for its size',
  linkedClaude.status !== 0 && /Claude executable must not be a symlink/.test(linkedClaude.stderr) && !/bytes|regular file/.test(linkedClaude.stderr))

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
ok('client doctor refuses a symlink SSH identity', linked.status !== 0 && /SSH identity file must not be a symlink/.test(linked.stderr))
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
  broker_mode: 'local', worker_enabled: false, delivery_mode: 'notify_only',
  // Named explicitly rather than left to the nvoy-<id>-adapter-1 default, so the fixture exercises
  // the manifest field the doctor now checks --container against (#188).
  adapter_container: 'nvoy-claude-1' }
writeFileSync(join(manifests, 'claude-test.json'), JSON.stringify(manifest))
const broker = spawnSync(process.execPath, [tool, '--mode', 'broker', '--instance', 'claude-test', '--public-key-file', publicKey, '--container', 'nvoy-claude-1'], { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
const brokerDescription = JSON.parse(broker.stdout || '{}')
ok('broker doctor validates and binds a notify-only identity', broker.status === 0 && brokerDescription.instance === 'claude-test' && brokerDescription.recipient === '1'.repeat(64))
ok('broker doctor emits the exact worker UID/GID baseline before key installation', brokerDescription.baseline?.includes('41014:42012') && /baseline before/.test(brokerDescription.invariants?.[0] || ''))
// Every command the broker output hands an owner must be runnable in the environment it names.
// `/usr/local/bin/node` and `/srv/nvoy` live inside the adapter image, not on the container host —
// verified on nave.pub, where the host has neither — so a command referencing them and NOT wrapped
// in `docker exec` fails with `node: command not found` on the host. authorizedKeyRenderer was
// unwrapped, and nothing asserted it, so it was the second line of a two-line procedure the owner
// is told to run verbatim.
{
  const cmds = { baseline: brokerDescription.baseline, authorizedKeyRenderer: brokerDescription.authorizedKeyRenderer }
  for (const [name, cmd] of Object.entries(cmds)) {
    const needsContainer = (cmd || []).some(a => typeof a === 'string' && (a.startsWith('/srv/nvoy/') || a === '/usr/local/bin/node'))
    ok(`${name} names a container-only path, so it must be wrapped in docker exec`,
      !needsContainer || (cmd[0] === '/usr/bin/docker' && cmd[1] === 'exec'))
    ok(`  …and ${name} runs as the worker identity, never the container's default root`,
      !needsContainer || (cmd.includes('--user') && cmd[cmd.indexOf('--user') + 1] === '41014:42012'))
    ok(`  …and ${name} names the container it was given`, !needsContainer || cmd.includes('nvoy-claude-1'))
  }
  // NEGATIVE CONTROL. Every assertion above is satisfied by wrapping something in docker exec; none
  // of them checks the wrapped command still does its job. These pin what each one actually runs,
  // so a future edit cannot satisfy the shape while pointing at the wrong tool.
  ok('NEGATIVE CONTROL — baseline still invokes claude-channel.mjs with --baseline',
    brokerDescription.baseline?.includes('/srv/nvoy/mcp/tools/claude-channel.mjs') && brokerDescription.baseline?.includes('--baseline'))
  ok('NEGATIVE CONTROL — the renderer still invokes the authorized-key tool, not the channel tool',
    brokerDescription.authorizedKeyRenderer?.includes('/srv/nvoy/mcp/tools/instance-claude-channel-authorized-key.mjs') &&
    !brokerDescription.authorizedKeyRenderer?.includes('--baseline'))
  // #188. Wrapping the command in `docker exec` is what created the next problem: everything after
  // the container name runs INSIDE the image, so a host path in that tail resolves to nothing. The
  // doctor validated the public key on the host and then handed the path to a container process,
  // which died with "public key file is missing" on the live adapter — on the step invariant 2
  // tells the owner to run unmodified.
  //
  // The container shares exactly two paths with the host (`/etc/nvoy/instances` bind, the
  // `/run/nvoy/<id>` volume), its rootfs is read-only so `docker cp` is refused, and everything
  // else it can reach is in-image. So the rule is about the boundary, not about this one flag.
  const renderCmd = brokerDescription.authorizedKeyRenderer || []
  const inContainer = renderCmd.slice(renderCmd.indexOf('nvoy-claude-1') + 1)
  const CONTAINER_VISIBLE = ['/srv/nvoy/', '/usr/local/bin/', '/etc/nvoy/instances/', '/run/nvoy/']
  const hostPaths = inContainer.filter(a => typeof a === 'string' && a.startsWith('/') && !CONTAINER_VISIBLE.some(p => a.startsWith(p)))
  ok('every absolute path the renderer runs WITH is one the container can see (#188)',
    inContainer.length > 0 && hostPaths.length === 0)
  ok('  …and the test can tell: the fixture key really does live on a host-only path',
    !CONTAINER_VISIBLE.some(p => realpathSync(publicKey).startsWith(p)))

  // By value, so nothing has to cross the boundary. A public key is not a secret.
  ok('  …so the key travels as its two parsed fields, not as a path',
    inContainer.includes('--public-key-type') && inContainer.includes('ssh-ed25519') &&
    inContainer.includes('--public-key-body') && inContainer.includes('AAAAC3NzaC1lZDI1NTE5AAAAITestOnly') &&
    !inContainer.includes('--public-key-file'))

  // The assertions above are all about shape. This one runs the renderer through the arguments the
  // doctor actually emitted — the whole point being that a command can be well-shaped and still not
  // work. `docker exec … <container> /usr/local/bin/node <renderer>` is stripped because the test
  // host has neither the container nor that node; the ARGUMENTS are what is under test.
  const rendererArgs = inContainer.slice(inContainer.indexOf('/usr/local/bin/node') + 2)
  const rendered = spawnSync(process.execPath, [resolve('mcp/tools/instance-claude-channel-authorized-key.mjs'), ...rendererArgs],
    { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
  ok('the emitted arguments actually drive the renderer to a principal line',
    rendered.status === 0 && /^restrict,command="/.test(rendered.stdout.trim()))
  ok('  …and that line is the forced command, bound to the worker identity and taking no caller argument',
    /command="\/usr\/bin\/docker exec -i --user 41014:42012 nvoy-claude-1 \/usr\/local\/bin\/node \/srv\/nvoy\/mcp\/tools\/claude-channel\.mjs --instance claude-test"/.test(rendered.stdout))
  ok('  …and it carries the key the doctor was asked about',
    rendered.stdout.includes('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly'))

  // NEGATIVE CONTROL for the renderer's new branch. It must not accept a key by value that it would
  // have refused from a file, or "by value" is a way around the validation rather than a way around
  // the filesystem.
  const malformed = spawnSync(process.execPath, [resolve('mcp/tools/instance-claude-channel-authorized-key.mjs'),
    '--instance', 'claude-test', '--public-key-type', 'ssh-rsa', '--public-key-body', 'AAAAB3NzaC1yc2E'],
    { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
  ok('NEGATIVE CONTROL — a key supplied by value is validated exactly as one read from a file',
    malformed.status !== 0 && /unsupported or malformed OpenSSH public key/.test(malformed.stderr))
  const bothWays = spawnSync(process.execPath, [resolve('mcp/tools/instance-claude-channel-authorized-key.mjs'),
    '--instance', 'claude-test', '--public-key-file', publicKey, '--public-key-type', 'ssh-ed25519', '--public-key-body', 'AAAAC3NzaC1lZDI1NTE5AAAAITestOnly'],
    { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
  ok('  …and supplying both forms is refused rather than one silently winning',
    bothWays.status !== 0 && /not both/.test(bothWays.stderr))
}

const relativePublic = spawnSync(process.execPath, [tool, '--mode', 'broker', '--instance', 'claude-test', '--public-key-file', 'channel.pub', '--container', 'nvoy-claude-1'], { encoding: 'utf8', cwd: root, env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
ok('broker doctor refuses a relative public-key path', relativePublic.status !== 0 && /path must be absolute/.test(relativePublic.stderr))
const wrongManifest = { ...manifest, id: 'claude-wrong', pubkey: '3'.repeat(64), state_dir: join(root, 'wrong-state'), runtime_dir: join(root, 'wrong-runtime'), spool_dir: join(root, 'wrong-spool'), delivery_mode: 'headless', worker_enabled: false }
writeFileSync(join(manifests, 'claude-wrong.json'), JSON.stringify(wrongManifest))
const wrong = spawnSync(process.execPath, [tool, '--mode', 'broker', '--instance', 'claude-wrong', '--public-key-file', publicKey, '--container', 'nvoy-claude-1'], { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
ok('broker doctor refuses a non-notify-only identity', wrong.status !== 0 && /notify_only/.test(wrong.stderr))

// #188, third leg. The doctor echoed `--container` into both emitted commands without checking it,
// and the renderer asserts it against the manifest. So naming any container other than the
// instance's adapter produced a well-formed command that died on the step the owner is told to run
// unmodified, and a `baseline` aimed at a container that may not be theirs. It went unnoticed
// because the value that was tried happened to equal the nvoy-<id>-adapter-1 default.
const wrongContainer = spawnSync(process.execPath, [tool, '--mode', 'broker', '--instance', 'claude-test', '--public-key-file', publicKey, '--container', 'nvoy-somebody-elses-1'], { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
ok('broker doctor refuses a --container that is not this instance\'s adapter, instead of emitting a command that fails later',
  wrongContainer.status !== 0 && /is not this instance's adapter/.test(wrongContainer.stderr))
ok('  …and names both what was asked for and what the manifest declares',
  /nvoy-somebody-elses-1/.test(wrongContainer.stderr) && /nvoy-claude-1/.test(wrongContainer.stderr))
// The control: the check refuses the wrong container rather than refusing every container. Asserted
// by the successful run at the top of this section, named here so the pairing is not accidental.
ok('  NEGATIVE CONTROL — the manifest\'s own adapter is still accepted', broker.status === 0)

if (fails) process.exit(1)
