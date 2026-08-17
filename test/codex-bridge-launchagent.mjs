import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const base = mkdtempSync(join(tmpdir(), 'nvoy-launchagent-'))
const instances = join(base, 'instances'), runtime = join(base, 'runtime')
mkdirSync(instances); mkdirSync(runtime)
const identity = join(base, 'id'), known = join(base, 'known')
writeFileSync(identity, 'test\n', { mode: 0o600 }); chmodSync(identity, 0o600)
writeFileSync(known, 'host ssh-ed25519 test\n', { mode: 0o600 }); chmodSync(known, 0o600)
const manifest = { version: 1, id: 'codex-test', pubkey: '2'.repeat(64), broker_mode: 'remote',
  state_dir: join(base, 'state'), runtime_dir: runtime, spool_dir: join(base, 'spool'),
  broker_adapter_gid: 41001, worker_handoff_gid: 41002, watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  delivery_mode: 'codex_app_server', worker_enabled: false, codex_thread_id: '019fce57-063d-7f50-b837-967d33ee384a',
  codex_transport: 'local_control_socket', codex_app_server_socket: join(base, 'control.sock'),
  ssh_target: 'sync@example.test', ssh_identity_file: identity, ssh_known_hosts_file: known,
  ssh_known_hosts_sha256: createHash('sha256').update(readFileSync(known)).digest('hex'), grantors: ['4'.repeat(64)],
  task_carriers: [{ pubkey: '5'.repeat(64), channels: ['a8186b53-537d-46ad-a7e7-b6486c58970e'] }], relays: ['wss://nos.lol'] }
writeFileSync(join(instances, 'codex-test.json'), JSON.stringify(manifest))
const env = { HOME: base, PATH: process.env.PATH, NVOY_INSTANCE_ROOT: instances }
const run = spawnSync(process.execPath, ['mcp/tools/install-codex-bridge-launchagent.mjs', '--instance', 'codex-test', '--print'],
  { cwd: resolve('.'), encoding: 'utf8', env })
if (run.status !== 0) console.error(run.stderr)
ok('renderer accepts one immutable keyless Codex binding', run.status === 0 && run.stdout.includes('pub.nave.nvoy.codex-test.codex-bridge'))
ok('LaunchAgent fixes the instance, interval, repository bridge, and manifest root', run.stdout.includes('codex-remote-bridge.mjs') && run.stdout.includes('<string>codex-test</string>') && run.stdout.includes('<string>2000</string>') && run.stdout.includes(instances))
ok('LaunchAgent contains no Nostr, Bunker, provider, relay, or inbound-selected authority', !/nsec|bunker|nip46|OPENAI_API_KEY|ANTHROPIC_API_KEY|wss:\/\//i.test(run.stdout))
ok('LaunchAgent has supervised startup and bounded environment', run.stdout.includes('<key>RunAtLoad</key><true/>') && run.stdout.includes('<key>KeepAlive</key><true/>') && !run.stdout.includes(process.env.NVOY_NSEC || 'never-present-secret'))
const wake = spawnSync(process.execPath, ['mcp/tools/install-codex-bridge-launchagent.mjs', '--instance', 'codex-test', '--wake-adapter', '--print'],
  { cwd: resolve('.'), encoding: 'utf8', env })
if (wake.status !== 0) console.error(wake.stderr)
ok('wake adapter LaunchAgent is a separate supervised job for the same immutable instance', wake.status === 0 && wake.stdout.includes('pub.nave.nvoy.codex-test.codex-wake') && wake.stdout.includes('codex-wake-adapter.mjs') && wake.stdout.includes('<string>codex-test</string>'))
ok('wake adapter LaunchAgent does not run the broker bridge interval loop', !wake.stdout.includes('codex-remote-bridge.mjs') && !wake.stdout.includes('<string>--interval-ms</string>'))
process.exitCode = fails ? 1 : 0
