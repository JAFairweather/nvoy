// Docker-only deployment boundary check for Nvoy #44.
// The normal unit test runs on developer machines. This one proves the rendered UID/GID model
// against a real Docker daemon: the worker cannot use or replace the adapter socket/queue while
// the broker account can connect.
import { spawnSync } from 'node:child_process'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'

if (process.env.NVOY_CONTAINER_TEST !== '1') {
  console.log('instance-runtime-container: skipped (set NVOY_CONTAINER_TEST=1 on the Docker deployment host)')
  process.exit(0)
}

const image = String(process.env.NVOY_RUNTIME_IMAGE || '')
if (!image) throw new Error('NVOY_RUNTIME_IMAGE is required for the container boundary check')
const docker = (args, input = '') => spawnSync('docker', args, { encoding: 'utf8', input })
if (docker(['version', '--format', '{{.Server.Version}}']).status !== 0) throw new Error('Docker daemon is unavailable')

const stamp = `nvoy-it-${process.pid}-${Date.now().toString(36)}`
const pubkey = getPublicKey(generateSecretKey())
const manifest = {
  version: 1, id: 'codex-test', pubkey,
  state_dir: '/var/lib/nvoy/codex-test', runtime_dir: '/run/nvoy/codex-test', spool_dir: '/var/lib/nvoy-watcher/codex-test',
  broker_adapter_gid: 41001, worker_handoff_gid: 41002, watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  bunker_uri_ref: '/etc/nvoy/credentials/unused.bunker', bunker_client_ref: '/etc/nvoy/credentials/unused.client',
  worker_image: 'registry.example/worker@sha256:' + 'd'.repeat(64), worker_runner: 'codex', worker_credential_ref: '/etc/nvoy/credentials/unused.provider',
  grantors: ['4'.repeat(64)], relays: ['wss://nos.lol'],
}
const volume = kind => `${stamp}-${kind}`
const instances = volume('instances'), state = volume('state'), spool = volume('spool'), runtime = volume('runtime'), adapter = `${stamp}-adapter`
const mount = (name, target) => ['-v', `${name}:${target}`]
const base = ['--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/tmp:mode=1777', ...mount(instances, '/etc/nvoy/instances:ro')]
const run = (args, label) => {
  const result = docker(['run', ...args])
  if (result.status !== 0) throw new Error(`${label}: ${(result.stderr || result.stdout).trim()}`)
  return result
}
const check = (name, result, expected = 0) => {
  const pass = result.status === expected
  console.log(`${pass ? 'ok  ' : 'FAIL'} — ${name}`)
  if (!pass) throw new Error(`${name}: ${(result.stderr || result.stdout).trim()}`)
}

try {
  for (const name of [instances, state, spool, runtime]) check(`create ${name}`, docker(['volume', 'create', name]))
  const seed = docker(['run', '--rm', '-i', '--user', '0:0', ...mount(instances, '/etc/nvoy/instances'), image, 'node', '-e', "const fs=require('node:fs');let body='';process.stdin.on('data',d=>body+=d);process.stdin.on('end',()=>{fs.mkdirSync('/etc/nvoy/instances',{recursive:true});fs.writeFileSync('/etc/nvoy/instances/codex-test.json',body,{mode:0o644})})"], JSON.stringify(manifest))
  check('seed immutable instance manifest', seed)
  // The deployment host has only this pulled image and the public manifest — not a source
  // checkout. Rendering must therefore prove the image carries its Compose template.
  const rendered = docker(['run', '--rm', '--read-only', '--tmpfs', '/tmp:mode=1777', '--user', '0:0', ...mount(instances, '/etc/nvoy/instances:ro'), image,
    'node', 'mcp/tools/render-instance-compose.mjs', '--instance', manifest.id,
    '--image', 'registry.example/runtime@sha256:' + 'a'.repeat(64)])
  check('runtime image renders the instance Compose contract', rendered)
  if (!String(rendered.stdout).includes('name: nvoy-codex-test')) throw new Error('rendered Compose did not bind the instance id')
  if (!String(rendered.stdout).includes('target: "/run/nvoy/codex-test"')) throw new Error('rendered Compose did not produce YAML-safe volume targets')
  run([...base, '--user', '0:0', '--cap-add=CHOWN', '--cap-add=FOWNER', '--cap-add=DAC_OVERRIDE', ...mount(state, manifest.state_dir), ...mount(spool, manifest.spool_dir), ...mount(runtime, manifest.runtime_dir), image, 'node', 'mcp/tools/instance-runtime-init.mjs', '--instance', manifest.id], 'initializer')
  check('start adapter', docker(['run', '-d', '--name', adapter, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/tmp:mode=1777', '--user', '41013:41001', '--group-add', '41002', ...mount(instances, '/etc/nvoy/instances:ro'), ...mount(runtime, manifest.runtime_dir), image, 'node', 'mcp/tools/instance-adapter.mjs', '--instance', manifest.id]))
  const probe = `const net=require('node:net');const c=net.createConnection('/run/nvoy/codex-test/adapter.sock');c.on('connect',()=>process.exit(9));c.on('error',e=>process.exit(e.code==='EACCES'?0:8));setTimeout(()=>process.exit(7),1500)`
  const deniedSocket = docker(['run', '--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/tmp:mode=1777', '--user', '41014:41002', ...mount(instances, '/etc/nvoy/instances:ro'), ...mount(runtime, manifest.runtime_dir), image, 'node', '-e', probe])
  check('worker cannot connect to adapter socket', deniedSocket)
  const deniedReplace = docker(['run', '--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/tmp:mode=1777', '--user', '41014:41002', ...mount(instances, '/etc/nvoy/instances:ro'), ...mount(runtime, manifest.runtime_dir), image, 'node', '-e', `const fs=require('node:fs');try{fs.unlinkSync('/run/nvoy/codex-test/adapter.sock');process.exit(9)}catch(e){process.exit(e.code==='EACCES'||e.code==='EPERM'?0:8)}`])
  check('worker cannot replace adapter socket', deniedReplace)
  const brokerConnect = docker(['run', '--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/tmp:mode=1777', '--user', '41012:41001', ...mount(instances, '/etc/nvoy/instances:ro'), ...mount(runtime, manifest.runtime_dir), image, 'node', '-e', `const net=require('node:net');const c=net.createConnection('/run/nvoy/codex-test/adapter.sock');c.on('connect',()=>process.exit(0));c.on('error',()=>process.exit(8));setTimeout(()=>process.exit(7),1500)`])
  check('broker group can connect to adapter socket', brokerConnect)
  console.log('instance-runtime-container: all passed')
} finally {
  docker(['rm', '-f', adapter])
  for (const name of [instances, state, spool, runtime]) docker(['volume', 'rm', '-f', name])
}
