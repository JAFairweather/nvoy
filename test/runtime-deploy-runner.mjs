// Pull-release regression: no network and no Docker daemon. Fake executables preserve the real
// runner's process boundary while driving immutable-image resolution, multi-identity promotion,
// already-current behavior, and whole-set rollback.

import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

let failures = 0
const ok = (label, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${label}`); if (!value) failures++ }
const repo = resolve('.')
const work = mkdtempSync(join(tmpdir(), 'nvoy-release-'))
const instances = join(work, 'instances'), state = join(work, 'state'), bin = join(work, 'bin')
const calls = join(work, 'calls.log')
mkdirSync(instances); mkdirSync(state); mkdirSync(bin)
for (const name of ['state-a', 'run-a', 'spool-a', 'state-b', 'run-b', 'spool-b']) mkdirSync(join(work, name))

const base = {
  version: 1, pubkey: '1'.repeat(64), grantors: ['2'.repeat(64)], relays: ['wss://nos.lol'],
  bunker_uri_ref: '/etc/nvoy/credentials/test.bunker', bunker_client_ref: '/etc/nvoy/credentials/test.client',
  broker_adapter_gid: 49001, worker_handoff_gid: 49002,
  watcher_uid: 49101, broker_uid: 49102, adapter_uid: 49103, worker_uid: 49104,
}
writeFileSync(join(instances, 'alpha.json'), JSON.stringify({ ...base, id: 'alpha',
  state_dir: join(work, 'state-a'), runtime_dir: join(work, 'run-a'), spool_dir: join(work, 'spool-a'),
  worker_image: 'registry.invalid/old-worker@sha256:' + '9'.repeat(64), worker_runner: 'codex',
  worker_credential_ref: '/etc/nvoy/credentials/test.provider' }))
writeFileSync(join(instances, 'beta.json'), JSON.stringify({ ...base, id: 'beta', pubkey: '3'.repeat(64),
  state_dir: join(work, 'state-b'), runtime_dir: join(work, 'run-b'), spool_dir: join(work, 'spool-b'),
  worker_enabled: false, delivery_mode: 'notify_only' }))

const executable = (name, body) => writeFileSync(join(bin, name), `#!/bin/sh\nset -eu\n${body}\n`, { mode: 0o700 })
executable('fake-git', `printf 'git %s\\n' "$*" >> ${JSON.stringify(calls)}`)
executable('fake-npm', `printf 'npm %s\\n' "$*" >> ${JSON.stringify(calls)}`)
writeFileSync(join(work, 'boundary.py'), `from pathlib import Path\nPath(${JSON.stringify(calls)}).open('a').write('boundary passed\\n')\n`)
executable('fake-docker', `
printf 'docker %s\\n' "$*" >> ${JSON.stringify(calls)}
if [ "$1" = pull ]; then exit 0; fi
if [ "$1 $2" = 'image inspect' ]; then
  for tag do :; done
  repo="\${tag%:sha-*}"
  case "$repo" in *worker) d=$(printf 'b%.0s' $(seq 1 64));; *) d=$(printf 'a%.0s' $(seq 1 64));; esac
  printf '%s@sha256:%s\\n' "$repo" "$d"
  exit 0
fi
if [ "$1" = run ]; then
  instance=''; runtime=''; worker=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --instance) instance="$2"; shift 2;;
      --image) runtime="$2"; shift 2;;
      --worker-image) worker="$2"; shift 2;;
      *) shift;;
    esac
  done
  printf 'name: nvoy-%s\\nservices:\n' "$instance"
  for service in init watcher broker adapter; do printf '  %s:\n    image: "%s"\\n' "$service" "$runtime"; done
  [ -z "$worker" ] || printf '  worker:\n    image: "%s"\\n' "$worker"
  exit 0
fi
if [ "$1" = compose ]; then
  file="$3"; shift 3
  if [ "$1" = config ] && [ "\${2:-}" = -q ]; then exit 0; fi
  if [ "$1" = config ]; then cat "$file"; exit 0; fi
  if [ "$1" = up ]; then
    case "\${FAKE_UP_FAIL_INSTANCE:-}" in
      ?*) case "$file" in
        *"$FAKE_UP_FAIL_INSTANCE"*)
          marker="\${FAKE_MUTATION_MARKER:?}"
          if [ ! -e "$marker" ]; then touch "$marker"; exit 42; fi
          rm -f "$marker"
          ;;
      esac ;;
    esac
    exit 0
  fi
  if [ "$1" = down ]; then exit 0; fi
  if [ "$1" = ps ] && [ "\${2:-}" = --status ]; then
    case "\${FAKE_FAIL_INSTANCE:-}" in ?*) case "$file" in *"$FAKE_FAIL_INSTANCE"*) printf 'watcher\\nadapter\\n'; exit 0;; esac;; esac
    printf 'watcher\\nbroker\\nadapter\\n'
    grep -q '^  worker:' "$file" && printf 'worker\\n'
    exit 0
  fi
  if [ "$1" = ps ]; then printf '{"State":"exited","ExitCode":0}\\n'; exit 0; fi
fi
exit 2`)

const sha1 = '4'.repeat(40), sha2 = '5'.repeat(40), sha3 = '6'.repeat(40)
const invoke = (sha, extra = {}) => spawnSync('python3', ['deploy/runtime-deploy-runner.py'], {
  cwd: repo, encoding: 'utf8', env: { ...process.env, NVOY_RELEASE_SHA: sha,
    NVOY_TEST_RELEASE_SHA: sha,
    NVOY_INSTANCE_ROOT: instances, NVOY_DEPLOY_STATE: state, NVOY_DEPLOY_HUB: repo,
    NVOY_DOCKER: join(bin, 'fake-docker'), NVOY_GIT: join(bin, 'fake-git'), NVOY_NPM: join(bin, 'fake-npm'),
    NVOY_BOUNDARY_TEST: join(work, 'boundary.py'), NVOY_SETTLE_MS: '0', ...extra },
})

try {
  const first = invoke(sha1)
  if (first.status !== 0) console.error(first.stdout, first.stderr)
  ok('a successful exact-SHA release exits cleanly', first.status === 0 && /deploy OK/.test(first.stdout))
  ok('the verified SHA is recorded only after promotion', existsSync(join(state, 'DEPLOYED_SHA')) && readFileSync(join(state, 'DEPLOYED_SHA'), 'utf8').trim() === sha1)
  if (!existsSync(join(state, 'DEPLOYED_SHA'))) throw new Error('baseline deploy failed; remaining checks would be misleading')
  const alpha = readFileSync(join(instances, 'alpha.compose.yml'), 'utf8')
  const beta = readFileSync(join(instances, 'beta.compose.yml'), 'utf8')
  ok('every runtime role is pinned to the resolved runtime digest', alpha.includes('nvoy-runtime@sha256:' + 'a'.repeat(64)) && beta.includes('nvoy-runtime@sha256:' + 'a'.repeat(64)))
  ok('only a worker-enabled identity receives the worker release digest', alpha.includes('nvoy-worker@sha256:' + 'b'.repeat(64)) && !beta.includes('nvoy-worker@sha256:'))

  writeFileSync(calls, '')
  const current = invoke(sha1)
  const currentCalls = readFileSync(calls, 'utf8')
  ok('an already-current tick health-checks but does not pull, render, or restart', current.status === 0 && /already current and healthy/.test(current.stdout) && /docker compose .* ps/.test(currentCalls) && !/docker pull| up -d|git |npm |boundary/.test(currentCalls))

  const oldAlpha = readFileSync(join(instances, 'alpha.compose.yml'), 'utf8')
  const oldBeta = readFileSync(join(instances, 'beta.compose.yml'), 'utf8')
  writeFileSync(calls, '')
  const failed = invoke(sha2, { FAKE_FAIL_INSTANCE: 'beta.compose.yml' })
  const failureCalls = readFileSync(calls, 'utf8')
  ok('a failed identity makes the release fail loudly', failed.status !== 0 && /services not running: broker/.test(failed.stderr))
  ok('a partial candidate restores every already-touched identity', (failureCalls.match(/docker compose .* up -d/g) || []).length >= 4)
  ok('a failed release leaves the previous Compose set and verified SHA intact',
    readFileSync(join(instances, 'alpha.compose.yml'), 'utf8') === oldAlpha &&
    readFileSync(join(instances, 'beta.compose.yml'), 'utf8') === oldBeta &&
    readFileSync(join(state, 'DEPLOYED_SHA'), 'utf8').trim() === sha1)

  writeFileSync(calls, '')
  const mutationMarker = join(work, 'beta-partially-mutated')
  const upFailed = invoke(sha3, { FAKE_UP_FAIL_INSTANCE: 'beta.compose.yml', FAKE_MUTATION_MARKER: mutationMarker })
  const upFailureCalls = readFileSync(calls, 'utf8')
  const betaUps = upFailureCalls.split('\n').filter(line => /docker compose .*beta\.compose\.yml up -d/.test(line))
  ok('a Compose up that mutates then fails makes the release fail loudly', upFailed.status !== 0 && /candidate failed/.test(upFailed.stderr))
  ok('the identity whose Compose up failed is itself rolled back', betaUps.length === 2 && !existsSync(mutationMarker))
  ok('an up-time failure preserves the previous verified SHA and live Compose set',
    readFileSync(join(instances, 'alpha.compose.yml'), 'utf8') === oldAlpha &&
    readFileSync(join(instances, 'beta.compose.yml'), 'utf8') === oldBeta &&
    readFileSync(join(state, 'DEPLOYED_SHA'), 'utf8').trim() === sha1)
  ok('the inter-process deploy lock is removed after success and failure', !existsSync(join(state, '.deploy-lock')))

  const workflow = readFileSync('.github/workflows/publish-runtime-images.yml', 'utf8')
  ok('image publication is downstream of the complete test gate', /publish:\n\s+needs: test/.test(workflow) && /run: npm test/.test(workflow))
  ok('the non-container gate uses the immutable official setup-node v4 commit',
    workflow.includes('actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020'))
  const unit = readFileSync('deploy/nvoy-runtime-deploy.service', 'utf8')
  ok('GitHub gets no host deployment credential; the host timer owns promotion', !/ssh|DEPLOY_KEY|HOST_KEY/i.test(workflow) && /runtime-deploy-runner\.py/.test(unit))
  ok('the protected unit keeps Docker and Git out of the hidden root home',
    /Environment=HOME=\/tmp\/nvoy-home/.test(unit) &&
    /Environment=DOCKER_CONFIG=\/tmp\/nvoy-docker/.test(unit) &&
    /PrivateTmp=yes/.test(unit) && /ProtectHome=yes/.test(unit))
} finally { rmSync(work, { recursive: true, force: true }) }

if (failures) process.exit(1)
console.log('runtime-deploy-runner: all checks passed')
