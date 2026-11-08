// The fleet wrapper for nvoy-onboard (#322): it runs the tool in the deployed runtime image with every
// host path the steps write, at the same path, plus the docker CLI and socket apply needs. A fake
// docker records the run; the tools' own defaults are read from source, so a moved default fails here.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const repo = join(dirname(fileURLToPath(import.meta.url)), '..')
const wrapper = join(repo, 'deploy', 'nvoy-onboard.sh')
const source = file => readFileSync(join(repo, 'mcp', 'tools', file), 'utf8')
const tmp = mkdtempSync(join(tmpdir(), 'nvoy-onboard-wrapper-'))
const deploy = join(tmp, 'deploy'), onboardState = join(tmp, 'onboard'), argvFile = join(tmp, 'argv'), hostKey = join(tmp, 'host_key.pub')
mkdirSync(deploy)
const fake = join(tmp, 'docker')
writeFileSync(fake, `#!/bin/sh\nprintf '%s\\n' "$@" > "${argvFile}"\nexit "\${FAKE_EXIT:-0}"\n`, { mode: 0o755 })
const run = (args, env = {}) => spawnSync('sh', [wrapper, ...args], { encoding: 'utf8',
  env: { ...process.env, NVOY_DOCKER: fake, NVOY_DEPLOY_STATE: deploy, NVOY_ONBOARD_STATE: onboardState, NVOY_HOST_KEY: hostKey, ...env } })

// No deployed image: refused, and docker is never called.
let r = run(['run', 'curator'])
assert.equal(r.status, 1)
assert.match(r.stderr, /no deployed runtime image/)
assert.equal(existsSync(argvFile), false)

const image = 'nvoy-runtime@sha256:' + 'ab'.repeat(32)
writeFileSync(join(deploy, 'DEPLOYED_RUNTIME_IMAGE'), image + '\n')
r = run(['run', 'curator', '--authorized-keys', '/root/.ssh/authorized_keys', '--relay', 'wss://a b'], { FAKE_EXIT: '4' })
assert.equal(r.status, 4, 'the tool\'s exit code (4: waiting on a step) is the wrapper\'s')
assert.equal(statSync(onboardState).mode & 0o777, 0o700)
const argv = readFileSync(argvFile, 'utf8').split('\n').slice(0, -1)
assert.deepEqual(argv.slice(0, 5), ['run', '--rm', '-i', '-u', '0:0'])
assert.ok(!argv.includes('-t'), 'no tty when stdin is not one')
const at = argv.indexOf(image)
assert.deepEqual(argv.slice(at - 2), ['--entrypoint', 'node', image, '/srv/nvoy/mcp/tools/nvoy-onboard.mjs',
  'run', 'curator', '--authorized-keys', '/root/.ssh/authorized_keys', '--relay', 'wss://a b'])
const envs = argv.flatMap((arg, i) => arg === '-e' ? [argv[i + 1]] : [])
assert.deepEqual(envs, ['HOME=/root', 'NVOY_GRANT_RELAYS'])
const mounts = argv.flatMap((arg, i) => arg === '-v' ? [argv[i + 1]] : []).map(spec => {
  const [from, to, mode = 'rw'] = spec.split(':')
  return { from, to, mode }
})
const covers = (path, mode) => mounts.find(m => (path === m.to || path.startsWith(m.to + '/')) && (mode === 'ro' || m.mode === 'rw'))

// Every path a step reads or writes, with where the default comes from.
assert.match(source('nvoy-onboard.mjs'), /'\/etc\/nvoy\/instances'/)
assert.match(source('instance-identity.mjs'), /'\/etc\/nvoy\/instances'/)
assert.match(source('instance-identity.mjs'), /join\(dirname\(root\), 'identity-blocks\.jsonl'\)/)
assert.match(source('nvoy-onboard.mjs'), /'\/var\/lib\/nvoy-onboard'/)
assert.match(source('nvoy-onboard.mjs'), /process\.env\.HOME \|\| '\/root', '\.nvoy', 'staged'/)
assert.match(source('instance-identity.mjs'), /'\/var\/lib\/nvoy-deploy'/)
assert.match(source('instance-identity.mjs'), /spawnSync\('\/usr\/bin\/docker'/)
assert.match(source('onboard_run.mjs'), /backupRoot = '\/root'/)
assert.match(source('onboard_receipt.mjs'), /RUNNER_CONFIG = '\/etc\/nvoy\/onboard\/runner\.json'/)
assert.match(source('onboard_receipt.mjs'), /hostKeyPath = '\/etc\/ssh\/ssh_host_ed25519_key\.pub'/)
const needs = [
  ['/etc/nvoy/instances/curator.json', 'rw'],      // apply installs the manifest; givers rewrite
  ['/etc/nvoy/identity-blocks.jsonl', 'rw'],       // apply reserves the block
  ['/etc/nvoy/credentials/curator.nip46-client', 'rw'], // instance-pair seats both files (fleet refs)
  ['/root/.nvoy/staged/curator.json', 'rw'],       // allocate stages; HOME=/root in the container
  ['/root/.ssh/authorized_keys', 'rw'],            // apply seats the channel principal (root is the channel account)
  ['/root/pi-dog-backups-20261107', 'rw'],         // a giver rewrite's dated backup
  ['/var/lib/nvoy-onboard/requests.jsonl', 'rw'],  // the ledger and receipts
  ['/var/lib/nvoy-deploy/DEPLOYED_MANIFESTS.json', 'ro'], // apply waits on the runner's record
  ['/run/nvoy/curator/profile-requests.jsonl', 'rw'], // the profile step queues the first kind 0
  ['/usr/bin/docker', 'ro'],                       // apply's baseline
  ['/var/run/docker.sock', 'rw'],
  ['/etc/nvoy/onboard/runner.json', 'ro'],          // watch: the runner key's config and its two credential files
  ['/etc/nvoy/onboard/nvoy-onboard.nip46-client', 'rw'], // runner-pair seats them
]
for (const [path, mode] of needs) assert.ok(covers(path, mode), `${path} is mounted ${mode}`)
assert.equal(mounts.find(m => m.to === '/var/lib/nvoy-deploy').mode, 'ro', 'the runner\'s record is never written')
assert.equal(mounts.find(m => m.to === '/var/lib/nvoy-deploy').from, deploy)
assert.equal(mounts.find(m => m.to === '/var/lib/nvoy-onboard').from, onboardState)
assert.equal(mounts.find(m => m.to === '/etc/ssh/ssh_host_ed25519_key.pub'), undefined, 'a host key that is not there is not mounted')
for (const m of mounts.filter(m => !['/var/lib/nvoy-deploy', '/var/lib/nvoy-onboard'].includes(m.to)))
  assert.equal(m.from, m.to, `${m.to} is the same path inside and out`)

// The host key, once there, is mounted read-only where watch reads it, and nothing else of /etc/ssh.
writeFileSync(hostKey, 'ssh-ed25519 AAAA test\n')
r = run(['watch'])
assert.equal(r.status, 0)
const watchMounts = readFileSync(argvFile, 'utf8').split('\n').flatMap((arg, i, all) => arg === '-v' ? [all[i + 1]] : [])
assert.deepEqual(watchMounts.filter(spec => spec.includes('/etc/ssh')), [`${hostKey}:/etc/ssh/ssh_host_ed25519_key.pub:ro`])

// One writer at a time, where the host has flock: a held lock refuses run and watch, never show.
if (spawnSync('sh', ['-c', 'command -v flock']).status === 0) {
  const holder = spawnSync('sh', ['-c', `exec 9>"${join(onboardState, '.lock')}"; flock -n 9 && sh "${wrapper}" watch; echo "inner=$?"`], { encoding: 'utf8',
    env: { ...process.env, NVOY_DOCKER: fake, NVOY_DEPLOY_STATE: deploy, NVOY_ONBOARD_STATE: onboardState, NVOY_HOST_KEY: hostKey } })
  assert.match(holder.stdout, /inner=75/, 'a second writer is refused while the lock is held')
  assert.match(holder.stderr, /another onboarding run holds/)
  const show = spawnSync('sh', ['-c', `exec 9>"${join(onboardState, '.lock')}"; flock -n 9 && sh "${wrapper}" show curator; echo "inner=$?"`], { encoding: 'utf8',
    env: { ...process.env, NVOY_DOCKER: fake, NVOY_DEPLOY_STATE: deploy, NVOY_ONBOARD_STATE: onboardState, NVOY_HOST_KEY: hostKey } })
  assert.match(show.stdout, /inner=0/, 'show writes nothing and takes no lock')
}

// The image the wrapper names really has the tool at that path.
assert.match(readFileSync(join(repo, 'deploy', 'nvoy-runtime.Dockerfile'), 'utf8'), /WORKDIR \/srv\/nvoy/)

rmSync(tmp, { recursive: true, force: true })
console.log('onboard-wrapper: refuses with no deployed image, passes the exit code, mounts every path the steps write and the docker socket pass')
