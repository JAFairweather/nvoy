// The install line (waggle DESIGN_ADD_AN_AGENT.md step 4): key made on the box and kept across runs,
// host key pinned from the line, one public line on stdout, nothing written when a tool is missing.
// ssh-keygen is real; Claude Code and tmux are fakes, and the harness itself is not started here.
import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { readClientConfig, recallEntry } from '../mcp/tools/channel_client.mjs'
import { parseHostKey, publicHalf } from '../mcp/tools/box-install.mjs'

const root = mkdtempSync(join(tmpdir(), 'nvoy-box-'))
const bin = join(root, 'bin'); mkdirSync(bin)
const fake = (name, body) => { writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`); chmodSync(join(bin, name), 0o755) }
fake('tmux', 'exit 0')
fake('claude', 'echo "2.1.90 (Claude Code)"')
fake('claude-old', 'echo "2.1.79 (Claude Code)"')

spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'fleet host', '-f', join(root, 'hostkey')])
const hostPub = readFileSync(join(root, 'hostkey.pub'), 'utf8').trim()
const hostKey = hostPub.split(' ').slice(0, 2).join(' ')

// The host key: one key, its body naming the type on its label.
assert.equal(parseHostKey(hostKey), hostKey)
assert.throws(() => parseHostKey(hostPub), /must be one key/, 'a comment is refused')
assert.throws(() => parseHostKey(`${hostKey}\n${hostKey}`), /must be one key/, 'a second key is refused')
assert.throws(() => parseHostKey(`ecdsa-sha2-nistp256 ${hostKey.split(' ')[1]}`), /not a ecdsa-sha2-nistp256 key/, 'a mislabelled body is refused')
assert.throws(() => parseHostKey('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ'), /must be one key/)
assert.throws(() => parseHostKey(''), /must be one key/)
assert.equal(publicHalf(hostPub), hostKey, 'the printed half drops the comment')
assert.throws(() => publicHalf('ssh-rsa AAAAB3NzaC1yc2E'), /not one ed25519 key/)

const id = 'crystal-test', target = 'nvoy-channel@fleet.example'
const run = (args, dir) => spawnSync(process.execPath, [resolve('mcp/tools/box-install.mjs'), ...args, '--instance', id, '--ssh-target', target,
  '--host-key', hostKey, '--dir', dir, '--claude', join(bin, 'claude')], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:/usr/bin:/bin` } })
const noPrivate = r => assert.ok(!/PRIVATE KEY/.test(r.stdout + r.stderr), 'the private key is never printed')

// A wrong line, or a missing tool: nothing written.
let dir = join(root, 'refused'), r
r = spawnSync(process.execPath, [resolve('mcp/tools/box-install.mjs'), '--instance', id, '--ssh-target', 'fleet.example', '--host-key', hostKey, '--dir', dir], { encoding: 'utf8' })
assert.equal(r.status, 1); assert.match(r.stderr, /user@host/); assert.ok(!existsSync(dir))
r = run(['--claude', join(bin, 'claude-old')], dir)
assert.equal(r.status, 2); assert.match(r.stderr, /nothing was changed: Claude Code 2\.1\.80 or later \(found 2\.1\.79\)/); assert.ok(!existsSync(dir))
r = spawnSync(process.execPath, [resolve('mcp/tools/box-install.mjs'), '--instance', id, '--ssh-target', target, '--host-key', hostKey, '--dir', 'relative/dir'], { encoding: 'utf8' })
assert.equal(r.status, 1); assert.match(r.stderr, /--dir must be absolute/)

// First run: key made here, host pinned, one public line out, waiting on the owner's Claude login.
dir = join(root, 'box')
r = run([], dir); noPrivate(r)
assert.equal(r.status, 3, r.stderr)
const lines = r.stdout.trim().split('\n')
assert.equal(lines.length, 1, 'stdout is one line')
assert.match(lines[0], /^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$/)
assert.match(r.stderr, /made a new channel key/); assert.match(r.stderr, /claude setup-token/)
const mode = p => statSync(join(dir, p)).mode & 0o777
assert.equal(mode('.'), 0o700); assert.equal(mode('channel'), 0o600); assert.equal(mode('client.json'), 0o600); assert.equal(mode('known_hosts'), 0o644)
assert.equal(readFileSync(join(dir, 'known_hosts'), 'utf8'), `fleet.example ${hostKey}\n`, 'known_hosts is the one pinned key')
const config = JSON.parse(readFileSync(join(dir, 'client.json'), 'utf8'))
assert.deepEqual(Object.keys(config).sort(), ['credential_file', 'home', 'identity_file', 'instance', 'known_hosts_file', 'ssh_target'])
assert.equal(config.ssh_target, target)

// Second run: the same key, so the half already bound stays right.
const first = lines[0]
r = run([], dir); assert.equal(r.status, 3); assert.equal(r.stdout.trim(), first); assert.match(r.stderr, /kept the channel key/)

// A lost .pub is rebuilt from the kept key, not replaced by a new one.
rmSync(join(dir, 'channel.pub'))
r = run([], dir); assert.equal(r.stdout.trim(), first)

// A swapped .pub (another valid key) is never printed: the half comes from the kept private key.
spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(root, 'other')])
writeFileSync(join(dir, 'channel.pub'), readFileSync(join(root, 'other.pub')))
r = run([], dir); assert.equal(r.stdout.trim(), first, 'the printed half matches the kept key')
assert.equal(publicHalf(readFileSync(join(dir, 'channel.pub'), 'utf8')), first, 'the stale .pub is rewritten')

// With the owner's login saved: the config is one the portable harness accepts, and the start line is printed.
writeFileSync(join(dir, 'claude-oauth-token'), 'not-a-real-token\n', { mode: 0o600 })
r = run([], dir); noPrivate(r)
assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout.trim(), first)
assert.match(r.stderr, /instance-harness\.mjs --instance crystal-test --remote .*client\.json/)
const read = readClientConfig(join(dir, 'client.json'), id)
assert.equal(read.target, target); assert.equal(read.home, join(dir, 'home'))
assert.equal(read.remember, false, 'memory instructions are off unless the config says so')
const clientPath = join(dir, 'client.json'), client = JSON.parse(readFileSync(clientPath, 'utf8'))
writeFileSync(clientPath, JSON.stringify({ ...client, remember: true }))
assert.equal(readClientConfig(clientPath, id).remember, true, 'remember: true turns the memory rule on')
writeFileSync(clientPath, JSON.stringify({ ...client, remember: 'yes' }))
assert.throws(() => readClientConfig(clientPath, id), /remember must be true or false/)
writeFileSync(clientPath, JSON.stringify(client))
assert.equal(readClientConfig(clientPath, id).recall, null, 'no recall block, no memory reader')
const recall = { identity_file: join(root, 'other'), known_hosts_file: client.known_hosts_file, ssh_target: 'hive-memory-gw@herd-cloud' }
writeFileSync(clientPath, JSON.stringify({ ...client, recall }))
assert.deepEqual({ ...readClientConfig(clientPath, id).recall }, { identity: realpathSync(join(root, 'other')), knownHosts: realpathSync(client.known_hosts_file), target: 'hive-memory-gw@herd-cloud' },
  'a recall block names the read key, its pinned host and the gateway')
writeFileSync(clientPath, JSON.stringify({ ...client, recall: { ...recall, identity_file: client.identity_file } }))
assert.throws(() => readClientConfig(clientPath, id), /two keys/, 'the read key is never the channel key')
writeFileSync(clientPath, JSON.stringify({ ...client, recall: { ...recall, command: 'sh' } }))
assert.throws(() => readClientConfig(clientPath, id), /recall takes exactly/, 'a recall block holds only the three paths')
writeFileSync(clientPath, JSON.stringify({ ...client, recall: { ...recall, ssh_target: 'gw@herd-cloud -oProxyCommand=x' } }))
assert.throws(() => readClientConfig(clientPath, id), /recall ssh_target/)
assert.deepEqual({ ...recallEntry({ local: true }, 'crystalclaude', 'agent-crystalclaude') }, { local: true }, 'on the store\'s box the instance\'s own login reads with no key')
assert.throws(() => recallEntry({ local: true }, 'crystalclaude', 'agent-crusty'), /reads only as agent-crystalclaude/, 'another agent\'s login never reads as this instance')
assert.throws(() => recallEntry({ local: true }, 'crystalclaude', 'root'), /reads only as agent-crystalclaude/)
assert.throws(() => recallEntry({ local: 'yes' }, 'crystalclaude', 'agent-crystalclaude'), /local must be true/)
assert.throws(() => recallEntry({ local: true, ssh_target: 'hive-memory-gw@herd-cloud' }, 'crystalclaude', 'agent-crystalclaude'), /recall takes exactly/, 'local recall is exactly { local: true }')
writeFileSync(clientPath, JSON.stringify({ ...client, recall: { local: true } }))
assert.throws(() => readClientConfig(clientPath, id), new RegExp(`reads only as agent-${id}`), 'the client config checks the process user')
writeFileSync(clientPath, JSON.stringify(client))
assert.ok(!(r.stdout + r.stderr).includes('not-a-real-token'), 'the login is never printed')

rmSync(root, { recursive: true, force: true })
console.log('box-install: host key one-and-typed, wrong line and old Claude change nothing, key made here and kept, pub rebuilt, swapped pub corrected, one stdout line, login never printed, harness config accepted')
