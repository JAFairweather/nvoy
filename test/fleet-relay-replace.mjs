// Fleet relay migration regression (q-158): pure-Python host tool replaces wss://nos.lol with
// wss://relay.nave.pub in seat manifests and 0600 Bunker signer pointers, dj-codex first then
// --all, preserving secret= query segments byte-for-byte, never leaking credentials, recreating
// only touched Compose stacks, converging cleanly with runtime-deploy-runner.py, and rolling back
// (or retaining .deploy-lock on unverified rollback) on fault.

import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync,
  readdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { generateSecretKey } from 'nostr-tools'
import { loadBunkerUri } from '../mcp/dist/identity.js'
import { makeBunkerSigner } from '../mcp/tools/nip46-signer.mjs'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'

let failures = 0
const ok = (label, value, detail = '') => {
  console.log(`${value ? 'ok  ' : 'FAIL'} — ${label}${value || !detail ? '' : ` (${detail})`}`)
  if (!value) failures++
}

const repo = resolve('.')
const work = mkdtempSync(join(tmpdir(), 'nvoy-q158-'))
const instances = join(work, 'instances')
const creds = join(work, 'credentials')
const state = join(work, 'state')
const backups = join(work, 'backups')
const bin = join(work, 'bin')
const calls = join(work, 'calls.log')

mkdirSync(instances, { mode: 0o755 })
mkdirSync(creds, { mode: 0o700 })
mkdirSync(state, { mode: 0o700 })
mkdirSync(bin, { mode: 0o700 })
writeFileSync(calls, '')

const sha = 'a'.repeat(40)
const runtimeImage = `ghcr.io/jafairweather/nvoy-runtime@sha256:${'b'.repeat(64)}`
const workerImage = `ghcr.io/jafairweather/nvoy-worker@sha256:${'c'.repeat(64)}`
const candidateDir = join(state, `candidate-${sha}`)
mkdirSync(candidateDir, { mode: 0o700 })

const CANARY_DJ = 'CANARY_SECRET_DJ%2BRAW~999'
const CANARY_WD = 'CANARY_SECRET_WD%2F123%3D'
const CANARY_BAD = 'CANARY_MALFORMED_LEAK_PROBE_777'

const executable = (name, body) =>
  writeFileSync(join(bin, name), `#!/bin/sh\nset -eu\n${body}\n`, { mode: 0o700 })

// Fake docker runs the REAL Node runtime_manifest.mjs validator when replace-instance-relay.py
// mounts staged manifests to /etc/nvoy/instances:ro, and records all compose operations.
executable('fake-docker', `
printf 'docker %s\\n' "$*" >> ${JSON.stringify(calls)}
if [ "$1" = run ]; then
  stage=''
  prev=''
  is_estate=0
  instance=''
  runtime=''
  worker=''
  for arg in "$@"; do
    case "$arg" in
      *:/etc/nvoy/instances:ro) stage="\${arg%:/etc/nvoy/instances:ro}" ;;
      *estate-valid*) is_estate=1 ;;
    esac
    case "$prev" in
      --instance) instance="$arg" ;;
      --image) runtime="$arg" ;;
      --worker-image) worker="$arg" ;;
    esac
    prev="$arg"
  done
  if [ "$is_estate" = 1 ]; then
    exec ${JSON.stringify(process.execPath)} -e 'import(process.argv[1]).then(m=>{m.assertNoCollisions(process.argv[2]);console.log("estate-valid")}).catch(e=>{console.error(e?.message||String(e));process.exit(1)})' ${JSON.stringify(join(repo, 'mcp/tools/runtime_manifest.mjs'))} "$stage"
  fi
  printf 'name: nvoy-%s\\nservices:\\n' "$instance"
  for svc in init watcher broker adapter; do printf '  %s:\\n    image: "%s"\\n' "$svc" "$runtime"; done
  [ -z "$worker" ] || printf '  worker:\\n    image: "%s"\\n' "$worker"
  exit 0
fi
if [ "$1" = compose ]; then
  file="$3"; shift 3
  if [ "$1" = config ] && [ "\${2:-}" = -q ]; then exit 0; fi
  if [ "$1" = config ]; then cat "$file"; exit 0; fi
  if [ "$1" = up ]; then
    case "\${FAKE_UP_FAIL_MODE:-}" in
      once)
        marker="\${FAKE_FAIL_MARKER:?}"
        if [ ! -e "$marker" ]; then touch "$marker"; exit 42; fi
        ;;
      always)
        exit 43
        ;;
    esac
    exit 0
  fi
  if [ "$1" = ps ] && [ "\${2:-}" = --status ]; then
    printf 'watcher\\nbroker\\nadapter\\n'
    grep -q '^  worker:' "$file" && printf 'worker\\n'
    exit 0
  fi
  if [ "$1" = ps ]; then
    printf '{"State":"exited","ExitCode":0}\\n'
    exit 0
  fi
fi
exit 2
`)

executable('fake-git', `
case "$3" in
  rev-parse) echo ${JSON.stringify(sha)} ;;
  ls-remote) printf '%s\\trefs/heads/main\\n' ${JSON.stringify(sha)} ;;
  merge-base) exit 0 ;;
esac
`)

const seats = [
  {
    id: 'dj-codex',
    pubkey: '1'.repeat(64),
    signerPk: 'd'.repeat(64),
    relays: ['wss://nos.lol', 'wss://relay.nave.pub'],
    bunkerUri: `bunker://${'d'.repeat(64)}?relay=wss%3A%2F%2Fnos.lol&relay=wss%3A%2F%2Frelay.nave.pub&secret=${CANARY_DJ}\n`,
    uidBase: 49100,
  },
  {
    id: 'biggy',
    pubkey: '2'.repeat(64),
    signerPk: 'e'.repeat(64),
    relays: ['wss://nos.lol', 'wss://relay.ditto.pub', 'wss://relay.primal.net'],
    bunkerUri: `bunker://${'e'.repeat(64)}?relay=wss%3A%2F%2Fnos.lol&relay=wss%3A%2F%2Frelay.ditto.pub&relay=wss%3A%2F%2Frelay.primal.net\n`,
    uidBase: 49200,
  },
  {
    id: 'waggle-dev',
    pubkey: '3'.repeat(64),
    signerPk: 'f'.repeat(64),
    relays: ['wss://nos.lol', 'wss://relay.ditto.pub'],
    bunkerUri: `bunker://${'f'.repeat(64)}?secret=${CANARY_WD}&relay=wss%3A%2F%2Fnos.lol&relay=wss%3A%2F%2Frelay.nave.pub\n`,
    uidBase: 49300,
  },
]

const initialDigests = {}
for (const s of seats) {
  for (const sub of ['state', 'run', 'spool']) mkdirSync(join(work, `${sub}-${s.id}`), { mode: 0o755 })
  const bunkerPath = join(creds, `${s.id}.bunker-uri`)
  const clientPath = join(creds, `${s.id}.nip46-client`)
  writeFileSync(bunkerPath, s.bunkerUri, { mode: 0o600 })
  chmodSync(bunkerPath, 0o600)
  writeFileSync(clientPath, '9'.repeat(64) + '\n', { mode: 0o600 })
  chmodSync(clientPath, 0o600)

  const manifest = {
    version: 1,
    id: s.id,
    pubkey: s.pubkey,
    grantors: ['4'.repeat(64)],
    relays: s.relays,
    state_dir: join(work, `state-${s.id}`),
    runtime_dir: join(work, `run-${s.id}`),
    spool_dir: join(work, `spool-${s.id}`),
    bunker_uri_ref: bunkerPath,
    bunker_client_ref: clientPath,
    broker_adapter_gid: s.uidBase + 1,
    worker_handoff_gid: s.uidBase + 2,
    watcher_uid: s.uidBase + 11,
    broker_uid: s.uidBase + 12,
    adapter_uid: s.uidBase + 13,
    worker_uid: s.uidBase + 14,
    worker_enabled: false,
    delivery_mode: 'notify_only',
  }
  const mBytes = JSON.stringify(manifest, null, 2) + '\n'
  writeFileSync(join(instances, `${s.id}.json`), mBytes, { mode: 0o644 })
  initialDigests[s.id] = createHash('sha256').update(mBytes).digest('hex')

  const composeText = [
    `name: nvoy-${s.id}`,
    'services:',
    `  init:\n    image: "${runtimeImage}"`,
    `  watcher:\n    image: "${runtimeImage}"`,
    `  broker:\n    image: "${runtimeImage}"`,
    `  adapter:\n    image: "${runtimeImage}"`,
    '',
  ].join('\n')
  writeFileSync(join(instances, `${s.id}.compose.yml`), composeText, { mode: 0o644 })
  writeFileSync(join(candidateDir, `${s.id}.compose.yml`), composeText, { mode: 0o600 })
}

writeFileSync(join(state, 'DEPLOYED_SHA'), `${sha}\n`, { mode: 0o644 })
writeFileSync(join(state, 'DEPLOYED_RUNTIME_IMAGE'), `${runtimeImage}\n`, { mode: 0o644 })
writeFileSync(join(state, 'DEPLOYED_WORKER_IMAGE'), `${workerImage}\n`, { mode: 0o644 })
writeFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), JSON.stringify(initialDigests, null, 2) + '\n', { mode: 0o644 })

const baseEnv = {
  ...process.env,
  NVOY_INSTANCE_ROOT: instances,
  NVOY_DEPLOY_STATE: state,
  NVOY_RELAY_BACKUPS: backups,
  NVOY_DOCKER: join(bin, 'fake-docker'),
  NVOY_SETTLE_MS: '0',
}

const runReplace = (args, extraEnv = {}) =>
  spawnSync('python3', ['deploy/replace-instance-relay.py', ...args], {
    cwd: repo,
    encoding: 'utf8',
    env: { ...baseEnv, ...extraEnv },
  })

const noLeak = (res) => {
  const combined = `${res.stdout || ''}\n${res.stderr || ''}`
  return (
    !combined.includes(CANARY_DJ) &&
    !combined.includes(CANARY_WD) &&
    !combined.includes(CANARY_BAD) &&
    !combined.includes('bunker://') &&
    !combined.includes('secret=')
  )
}

try {
  // 1. Dry-run on dj-codex first: validates in container, changes nothing, leaks nothing.
  const djManifestBefore = readFileSync(join(instances, 'dj-codex.json'), 'utf8')
  const djBunkerBefore = readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8')
  writeFileSync(calls, '')
  const dry = runReplace(['--instance', 'dj-codex'])
  ok('dry-run dj-codex exits 0', dry.status === 0, dry.stderr)
  ok('dry-run emits zero secrets or bunker URIs', noLeak(dry))
  const dryJson = JSON.parse(dry.stdout)
  ok('dry-run reports deduplicated relay replacement for dj-codex',
    dryJson.mode === 'dry-run' &&
    dryJson.changed_count === 1 &&
    JSON.stringify(dryJson.seats[0].manifest_relays_after) === JSON.stringify(['wss://relay.nave.pub']) &&
    JSON.stringify(dryJson.seats[0].signer_relays_after) === JSON.stringify(['wss://relay.nave.pub']))
  ok('dry-run leaves manifest, credential, backups, and compose untouched',
    readFileSync(join(instances, 'dj-codex.json'), 'utf8') === djManifestBefore &&
    readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8') === djBunkerBefore &&
    !existsSync(backups) &&
    !/^docker compose /m.test(readFileSync(calls, 'utf8')))

  // 2. Staged canary apply: --instance dj-codex --apply.
  writeFileSync(calls, '')
  const djApply = runReplace(['--instance', 'dj-codex', '--apply'])
  ok('dj-codex --apply exits 0', djApply.status === 0, djApply.stderr)
  ok('dj-codex --apply emits zero secrets or bunker URIs', noLeak(djApply))
  const djApplyJson = JSON.parse(djApply.stdout)
  ok('dj-codex --apply recreates dj-codex and creates private 0700 backup',
    djApplyJson.changed_count === 1 &&
    djApplyJson.seats[0].recreated === true &&
    existsSync(djApplyJson.backup_dir) &&
    (lstatSync(djApplyJson.backup_dir).mode & 0o777) === 0o700)

  const djBunkerAfter = readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8')
  ok('dj-codex bunker URI deduplicates relay.nave.pub and preserves secret= byte-for-byte at mode 0600',
    djBunkerAfter === `bunker://${'d'.repeat(64)}?relay=wss%3A%2F%2Frelay.nave.pub&secret=${CANARY_DJ}\n` &&
    (lstatSync(join(creds, 'dj-codex.bunker-uri')).mode & 0o777) === 0o600)

  const djCalls = readFileSync(calls, 'utf8')
  const djComposeLines = djCalls.split('\n').filter(line => line.startsWith('docker compose '))
  ok('dj-codex --apply recreates only dj-codex without down or -v, leaving other seats untouched',
    djCalls.includes(`compose -f ${join(instances, 'dj-codex.compose.yml')} up -d --remove-orphans --force-recreate`) &&
    !djCalls.includes('biggy.compose.yml') &&
    !djCalls.includes('waggle-dev.compose.yml') &&
    djComposeLines.length > 0 &&
    djComposeLines.every(line => !/\bdown\b|\s-v\b|--volumes\b/.test(line)) &&
    readFileSync(join(creds, 'biggy.bunker-uri'), 'utf8').includes('nos.lol'))

  // 3. Rewritten dj-codex manifest and bunker URI satisfy real nvoy runtime parsers with zero nos.lol.
  const loadedManifest = readManifest(instances, 'dj-codex')
  ok('rewritten dj-codex manifest loads via readManifest with zero nos.lol relays',
    JSON.stringify(loadedManifest.relays) === JSON.stringify(['wss://relay.nave.pub']))
  const loadedUri = loadBunkerUri({ NVOY_BUNKER_URI_FILE: join(creds, 'dj-codex.bunker-uri') })
  ok('rewritten dj-codex bunker file passes loadBunkerUri 0600 descriptor checks',
    loadedUri === djBunkerAfter.trim())

  const subscribedRelays = []
  const fakePool = {
    subscribeMany(relays) {
      subscribedRelays.push(relays)
      return { close() {} }
    },
    publish(relays) {
      return relays.map(() => new Promise(() => {}))
    },
    close() {},
  }
  const clientHex = Buffer.from(generateSecretKey()).toString('hex')
  const signer = makeBunkerSigner(loadedUri, clientHex, { pool: fakePool })
  const pendingPk = signer.getPublicKey().catch(() => {})
  signer.close()
  await pendingPk
  ok('makeBunkerSigner subscribes exclusively to wss://relay.nave.pub with zero nos.lol',
    subscribedRelays.length === 1 &&
    JSON.stringify(subscribedRelays[0]) === JSON.stringify(['wss://relay.nave.pub']))

  // 4. Real runtime-deploy-runner.py sees DEPLOYED_MANIFESTS.json converged and performs zero redundant recreate.
  writeFileSync(calls, '')
  const runnerRes = spawnSync('python3', ['deploy/runtime-deploy-runner.py'], {
    cwd: repo,
    encoding: 'utf8',
    env: {
      ...baseEnv,
      NVOY_RELEASE_SHA: sha,
      NVOY_TEST_RELEASE_SHA: sha,
      NVOY_DEPLOY_HUB: repo,
      NVOY_GIT: join(bin, 'fake-git'),
      NVOY_RETRY_AFTER_S: '0',
    },
  })
  ok('runtime-deploy-runner.py converges cleanly without re-recreating dj-codex',
    runnerRes.status === 0 &&
    !existsSync(join(state, '.deploy-lock')) &&
    !/up -d/.test(readFileSync(calls, 'utf8')),
    runnerRes.stderr)

  // 5. Roll out remaining fleet seats via --all --apply: skips dj-codex idempotently, updates biggy & waggle-dev.
  writeFileSync(calls, '')
  const allApply = runReplace(['--all', '--apply'])
  ok('--all --apply exits 0 and emits zero secrets', allApply.status === 0 && noLeak(allApply), allApply.stderr)
  const allJson = JSON.parse(allApply.stdout)
  const bySeat = Object.fromEntries(allJson.seats.map(s => [s.id, s]))
  ok('--all --apply skips already-migrated dj-codex and recreates only biggy and waggle-dev',
    allJson.changed_count === 2 &&
    bySeat['dj-codex'].recreated === false &&
    bySeat['biggy'].recreated === true &&
    bySeat['waggle-dev'].recreated === true &&
    !readFileSync(calls, 'utf8').includes('dj-codex.compose.yml up'))
  ok('biggy 3-relay no-secret URI and waggle-dev leading-secret URI are rewritten accurately',
    readFileSync(join(creds, 'biggy.bunker-uri'), 'utf8') ===
      `bunker://${'e'.repeat(64)}?relay=wss%3A%2F%2Frelay.nave.pub&relay=wss%3A%2F%2Frelay.ditto.pub&relay=wss%3A%2F%2Frelay.primal.net\n` &&
    readFileSync(join(creds, 'waggle-dev.bunker-uri'), 'utf8') ===
      `bunker://${'f'.repeat(64)}?secret=${CANARY_WD}&relay=wss%3A%2F%2Frelay.nave.pub\n`)

  // 6. Repeat --all --apply is a complete no-op.
  writeFileSync(calls, '')
  const noopApply = runReplace(['--all', '--apply'])
  ok('repeat --all --apply is idempotent (changed_count 0, zero docker calls)',
    noopApply.status === 0 &&
    JSON.parse(noopApply.stdout).changed_count === 0 &&
    readFileSync(calls, 'utf8').trim() === '')

  // 7. Negative controls: bad mode, symlink, malformed URI with secret, .deploy-lock, drifted compose.
  chmodSync(join(creds, 'dj-codex.bunker-uri'), 0o644)
  const badMode = runReplace(['--instance', 'dj-codex'])
  chmodSync(join(creds, 'dj-codex.bunker-uri'), 0o600)
  ok('0644 credential file is refused without leaking secret',
    badMode.status !== 0 && /mode 0600/.test(badMode.stderr) && noLeak(badMode))

  const savedBiggy = readFileSync(join(creds, 'biggy.bunker-uri'))
  unlinkSync(join(creds, 'biggy.bunker-uri'))
  symlinkSync(join(creds, 'dj-codex.bunker-uri'), join(creds, 'biggy.bunker-uri'))
  const symlinkRes = runReplace(['--instance', 'biggy'])
  unlinkSync(join(creds, 'biggy.bunker-uri'))
  writeFileSync(join(creds, 'biggy.bunker-uri'), savedBiggy, { mode: 0o600 })
  chmodSync(join(creds, 'biggy.bunker-uri'), 0o600)
  ok('symlinked credential file is refused via O_NOFOLLOW without leaking secret',
    symlinkRes.status !== 0 && /non-symlink/.test(symlinkRes.stderr) && noLeak(symlinkRes))

  writeFileSync(join(creds, 'biggy.bunker-uri'), `not-bunker://bad?secret=${CANARY_BAD}&relay=wss%3A%2F%2Fnos.lol\n`, { mode: 0o600 })
  chmodSync(join(creds, 'biggy.bunker-uri'), 0o600)
  const malformedRes = runReplace(['--instance', 'biggy'])
  writeFileSync(join(creds, 'biggy.bunker-uri'), savedBiggy, { mode: 0o600 })
  chmodSync(join(creds, 'biggy.bunker-uri'), 0o600)
  ok('malformed credential file is refused without echoing URI or canary secret',
    malformedRes.status !== 0 && /invalid bunker URI/.test(malformedRes.stderr) && noLeak(malformedRes))

  mkdirSync(join(state, '.deploy-lock'), { mode: 0o700 })
  const lockedRes = runReplace(['--instance', 'dj-codex', '--apply'])
  rmSync(join(state, '.deploy-lock'), { recursive: true, force: true })
  ok('active .deploy-lock refuses --apply before mutation',
    lockedRes.status !== 0 && /deploy runner is active/.test(lockedRes.stderr) && noLeak(lockedRes))

  // 8. Rollback on recreate failure vs .deploy-lock retention on unverified rollback.
  const preRollbackManifest = readFileSync(join(instances, 'dj-codex.json'), 'utf8')
  const preRollbackBunker = readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8')
  const preRollbackRecorded = readFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), 'utf8')
  const marker = join(work, 'fail-once.marker')
  const rbRes = runReplace(
    ['--instance', 'dj-codex', '--from-relay', 'wss://relay.nave.pub', '--to-relay', 'wss://relay.ditto.pub', '--apply'],
    { FAKE_UP_FAIL_MODE: 'once', FAKE_FAIL_MARKER: marker },
  )
  ok('compose recreate failure rolls back manifest and credential, keeps DEPLOYED_MANIFESTS, and releases lock',
    rbRes.status !== 0 &&
    /restored original files/.test(rbRes.stderr) &&
    noLeak(rbRes) &&
    !existsSync(join(state, '.deploy-lock')) &&
    readFileSync(join(instances, 'dj-codex.json'), 'utf8') === preRollbackManifest &&
    readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8') === preRollbackBunker &&
    readFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), 'utf8') === preRollbackRecorded)

  const unsafeRes = runReplace(
    ['--instance', 'dj-codex', '--from-relay', 'wss://relay.nave.pub', '--to-relay', 'wss://relay.ditto.pub', '--apply'],
    { FAKE_UP_FAIL_MODE: 'always' },
  )
  ok('double failure during rollback retains .deploy-lock with UNSAFE warning and leaks zero secrets',
    unsafeRes.status !== 0 &&
    /UNSAFE: rollback incomplete/.test(unsafeRes.stderr) &&
    !/restored original files/.test(unsafeRes.stderr) &&
    noLeak(unsafeRes) &&
    existsSync(join(state, '.deploy-lock')) &&
    readFileSync(join(instances, 'dj-codex.json'), 'utf8') === preRollbackManifest &&
    readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8') === preRollbackBunker)
  rmSync(join(state, '.deploy-lock'), { recursive: true, force: true })

  // 9. Post-os.replace directory-fsync fault injection across credential, manifest, and DEPLOYED_MANIFESTS.json.
  const faultHookDir = join(work, 'fault-hook')
  mkdirSync(faultHookDir, { mode: 0o700 })
  writeFileSync(join(faultHookDir, 'sitecustomize.py'), `
import errno
import json
import os
from pathlib import Path

_TARGET = os.environ.get("NVOY_TEST_FAULT_TARGET", "")
_MODE = os.environ.get("NVOY_TEST_FAULT_MODE", "")
_OBS = os.environ.get("NVOY_TEST_FAULT_OBS", "")
_ORIG = Path(_TARGET).read_bytes() if _TARGET and Path(_TARGET).exists() else b""

_real_open = os.open
_real_close = os.close
_real_replace = os.replace
_real_fsync = os.fsync

_dir_fds = {}
_armed_fds = set()
_calls = 0

def _open(path, flags, *args, **kwargs):
    fd = _real_open(path, flags, *args, **kwargs)
    if (flags & getattr(os, "O_DIRECTORY", 0)) and kwargs.get("dir_fd") is None:
        try:
            _dir_fds[fd] = str(Path(os.fsdecode(path)).resolve())
        except Exception:
            pass
    return fd

def _close(fd):
    _dir_fds.pop(fd, None)
    _armed_fds.discard(fd)
    return _real_close(fd)

def _replace(src, dst, *args, **kwargs):
    res = _real_replace(src, dst, *args, **kwargs)
    dst_dir_fd = kwargs.get("dst_dir_fd")
    if dst_dir_fd in _dir_fds and _TARGET:
        candidate = str(Path(_dir_fds[dst_dir_fd]) / os.fsdecode(dst))
        if candidate == str(Path(_TARGET).resolve()):
            _armed_fds.add(dst_dir_fd)
    return res

def _fsync(fd):
    global _calls
    if fd in _armed_fds:
        _armed_fds.discard(fd)
        _calls += 1
        cur = Path(_TARGET).read_bytes()
        obs = {}
        if _OBS and Path(_OBS).exists():
            try:
                obs = json.loads(Path(_OBS).read_text("utf-8"))
            except Exception:
                obs = {}
        obs["post_replace_calls"] = _calls
        if _calls == 1:
            obs["mutated_at_first_fault"] = (cur != _ORIG)
        if _OBS:
            Path(_OBS).write_text(json.dumps(obs), "utf-8")
        if _MODE == "once" and _calls == 1:
            raise OSError(errno.EIO, "injected post-replace dir fsync fault")
        if _MODE == "always":
            raise OSError(errno.EIO, "injected persistent post-replace dir fsync fault")
        if _MODE == "corrupt_restore":
            if _calls == 1:
                raise OSError(errno.EIO, "injected post-replace dir fsync fault")
            if _calls == 2:
                res = _real_fsync(fd)
                os.chmod(_TARGET, 0o600 if _TARGET.endswith(".bunker-uri") else 0o644)
                Path(_TARGET).write_bytes(cur + b" ")
                return res
        if _MODE == "drift_mode_restore":
            if _calls == 1:
                raise OSError(errno.EIO, "injected post-replace dir fsync fault")
            if _calls == 2:
                res = _real_fsync(fd)
                os.chmod(_TARGET, 0o600)
                return res
    return _real_fsync(fd)

if _TARGET and _MODE:
    os.open = _open
    os.close = _close
    os.replace = _replace
    os.fsync = _fsync
`, { mode: 0o600 })

  const restoreCleanSnapshot = () => {
    writeFileSync(join(instances, 'dj-codex.json'), preRollbackManifest, { mode: 0o644 })
    if (existsSync(join(creds, 'dj-codex.bunker-uri'))) {
      chmodSync(join(creds, 'dj-codex.bunker-uri'), 0o600)
    }
    writeFileSync(join(creds, 'dj-codex.bunker-uri'), preRollbackBunker, { mode: 0o600 })
    chmodSync(join(creds, 'dj-codex.bunker-uri'), 0o600)
    writeFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), preRollbackRecorded, { mode: 0o644 })
    rmSync(join(state, '.deploy-lock'), { recursive: true, force: true })
  }

  const runFaultCase = (targetPath, mode) => {
    const obsPath = join(work, `fault-obs-${Date.now()}-${Math.random().toString(16).slice(2)}.json`)
    const existingPyPath = process.env.PYTHONPATH ? `${faultHookDir}:${process.env.PYTHONPATH}` : faultHookDir
    const res = runReplace(
      ['--instance', 'dj-codex', '--from-relay', 'wss://relay.nave.pub', '--to-relay', 'wss://relay.ditto.pub', '--apply'],
      {
        PYTHONPATH: existingPyPath,
        NVOY_TEST_FAULT_TARGET: targetPath,
        NVOY_TEST_FAULT_MODE: mode,
        NVOY_TEST_FAULT_OBS: obsPath,
      },
    )
    const obs = existsSync(obsPath) ? JSON.parse(readFileSync(obsPath, 'utf8')) : {}
    return { res, obs }
  }

  // 9a. Credential post-replace dir-fsync fault (transient -> restored; persistent -> lock retained).
  {
    const { res, obs } = runFaultCase(join(creds, 'dj-codex.bunker-uri'), 'once')
    ok('credential post-replace fsync fault (once) restores mutated 0600 credential, reports restored truthfully, and clears lock',
      res.status !== 0 &&
      obs.mutated_at_first_fault === true &&
      obs.post_replace_calls === 2 &&
      /restored original files/.test(res.stderr) &&
      !/UNSAFE: rollback incomplete/.test(res.stderr) &&
      noLeak(res) &&
      !existsSync(join(state, '.deploy-lock')) &&
      readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8') === preRollbackBunker &&
      (lstatSync(join(creds, 'dj-codex.bunker-uri')).mode & 0o777) === 0o600 &&
      readFileSync(join(instances, 'dj-codex.json'), 'utf8') === preRollbackManifest &&
      readFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), 'utf8') === preRollbackRecorded,
      res.stderr)
  }
  {
    const { res, obs } = runFaultCase(join(creds, 'dj-codex.bunker-uri'), 'always')
    ok('credential post-replace fsync fault (persistent) retains .deploy-lock, omits restored message, and leaks zero secrets',
      res.status !== 0 &&
      obs.mutated_at_first_fault === true &&
      /UNSAFE: rollback incomplete/.test(res.stderr) &&
      !/restored original files/.test(res.stderr) &&
      noLeak(res) &&
      existsSync(join(state, '.deploy-lock')),
      res.stderr)
    restoreCleanSnapshot()
  }

  // 9b. Manifest post-replace dir-fsync fault (transient -> restored; persistent -> lock retained).
  {
    const { res, obs } = runFaultCase(join(instances, 'dj-codex.json'), 'once')
    ok('manifest post-replace fsync fault (once) restores mutated manifest and prior credential, reports restored truthfully, and clears lock',
      res.status !== 0 &&
      obs.mutated_at_first_fault === true &&
      obs.post_replace_calls === 2 &&
      /restored original files/.test(res.stderr) &&
      !/UNSAFE: rollback incomplete/.test(res.stderr) &&
      noLeak(res) &&
      !existsSync(join(state, '.deploy-lock')) &&
      readFileSync(join(instances, 'dj-codex.json'), 'utf8') === preRollbackManifest &&
      readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8') === preRollbackBunker &&
      readFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), 'utf8') === preRollbackRecorded,
      res.stderr)
  }
  {
    const { res, obs } = runFaultCase(join(instances, 'dj-codex.json'), 'always')
    ok('manifest post-replace fsync fault (persistent) retains .deploy-lock and omits restored message',
      res.status !== 0 &&
      obs.mutated_at_first_fault === true &&
      /UNSAFE: rollback incomplete/.test(res.stderr) &&
      !/restored original files/.test(res.stderr) &&
      noLeak(res) &&
      existsSync(join(state, '.deploy-lock')),
      res.stderr)
    restoreCleanSnapshot()
  }

  // 9c. DEPLOYED_MANIFESTS.json post-replace dir-fsync fault (transient -> restored; persistent -> lock retained).
  {
    writeFileSync(calls, '')
    const { res, obs } = runFaultCase(join(state, 'DEPLOYED_MANIFESTS.json'), 'once')
    const upCount = (readFileSync(calls, 'utf8').match(/dj-codex\.compose\.yml up -d/g) || []).length
    ok('DEPLOYED_MANIFESTS post-replace fsync fault (once) restores record, manifest, credential, and compose stack cleanly',
      res.status !== 0 &&
      obs.mutated_at_first_fault === true &&
      obs.post_replace_calls === 2 &&
      upCount === 2 &&
      /restored original files/.test(res.stderr) &&
      !/UNSAFE: rollback incomplete/.test(res.stderr) &&
      noLeak(res) &&
      !existsSync(join(state, '.deploy-lock')) &&
      readFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), 'utf8') === preRollbackRecorded &&
      readFileSync(join(instances, 'dj-codex.json'), 'utf8') === preRollbackManifest &&
      readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8') === preRollbackBunker,
      res.stderr)
  }
  {
    const { res, obs } = runFaultCase(join(state, 'DEPLOYED_MANIFESTS.json'), 'always')
    ok('DEPLOYED_MANIFESTS post-replace fsync fault (persistent) retains .deploy-lock and omits restored message',
      res.status !== 0 &&
      obs.mutated_at_first_fault === true &&
      /UNSAFE: rollback incomplete/.test(res.stderr) &&
      !/restored original files/.test(res.stderr) &&
      noLeak(res) &&
      existsSync(join(state, '.deploy-lock')),
      res.stderr)
    restoreCleanSnapshot()
  }

  // 9d. Post-rollback byte verification catches silent restore drift even when rollback write itself did not raise.
  {
    const { res } = runFaultCase(join(creds, 'dj-codex.bunker-uri'), 'corrupt_restore')
    ok('post-rollback byte verification retains .deploy-lock and omits restored message on unverified disk bytes',
      res.status !== 0 &&
      /UNSAFE: rollback incomplete/.test(res.stderr) &&
      /restored bytes or mode mismatch/.test(res.stderr) &&
      !/restored original files/.test(res.stderr) &&
      noLeak(res) &&
      existsSync(join(state, '.deploy-lock')),
      res.stderr)
    restoreCleanSnapshot()
  }

  // 9e. Accepted 0400 credential mode is preserved across rollback (manifest fault after credential write).
  {
    chmodSync(join(creds, 'dj-codex.bunker-uri'), 0o400)
    const { res, obs } = runFaultCase(join(instances, 'dj-codex.json'), 'once')
    ok('accepted 0400 credential mode is preserved across rollback and verified before clearing .deploy-lock',
      res.status !== 0 &&
      obs.mutated_at_first_fault === true &&
      obs.post_replace_calls === 2 &&
      /restored original files/.test(res.stderr) &&
      !/UNSAFE: rollback incomplete/.test(res.stderr) &&
      noLeak(res) &&
      !existsSync(join(state, '.deploy-lock')) &&
      readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8') === preRollbackBunker &&
      (lstatSync(join(creds, 'dj-codex.bunker-uri')).mode & 0o777) === 0o400 &&
      readFileSync(join(instances, 'dj-codex.json'), 'utf8') === preRollbackManifest,
      res.stderr)
    restoreCleanSnapshot()
  }

  // 9f. Post-rollback mode verification retains .deploy-lock if a 0400 credential drifts to 0600 on restore.
  {
    chmodSync(join(creds, 'dj-codex.bunker-uri'), 0o400)
    const { res } = runFaultCase(join(creds, 'dj-codex.bunker-uri'), 'drift_mode_restore')
    ok('post-rollback mode verification retains .deploy-lock and omits restored message when 0400 credential drifts to 0600',
      res.status !== 0 &&
      /UNSAFE: rollback incomplete/.test(res.stderr) &&
      /restored bytes or mode mismatch/.test(res.stderr) &&
      !/restored original files/.test(res.stderr) &&
      noLeak(res) &&
      existsSync(join(state, '.deploy-lock')),
      res.stderr)
    restoreCleanSnapshot()
  }

  // 9g. Non-standard credential mode (e.g. 0700) is rejected before writing any files.
  {
    chmodSync(join(creds, 'dj-codex.bunker-uri'), 0o700)
    const badMode = runReplace([
      '--instance', 'dj-codex',
      '--from-relay', 'wss://relay.nave.pub',
      '--to-relay', 'wss://relay.ditto.pub',
      '--apply',
    ])
    ok('0700 executable credential mode is rejected safely before mutating files',
      badMode.status !== 0 &&
      /credential file must be mode 0600 or 0400/.test(badMode.stderr) &&
      noLeak(badMode) &&
      !existsSync(join(state, '.deploy-lock')) &&
      readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8') === preRollbackBunker &&
      readFileSync(join(instances, 'dj-codex.json'), 'utf8') === preRollbackManifest,
      badMode.stderr)
    restoreCleanSnapshot()
  }

  // 9h. Accepted 0400 credential mode is preserved across a successful --apply rewrite.
  {
    chmodSync(join(creds, 'dj-codex.bunker-uri'), 0o400)
    const ok0400 = runReplace([
      '--instance', 'dj-codex',
      '--from-relay', 'wss://relay.nave.pub',
      '--to-relay', 'wss://relay.ditto.pub',
      '--apply',
    ])
    const summary0400 = ok0400.status === 0 ? JSON.parse(ok0400.stdout) : null
    ok('accepted 0400 credential mode is preserved as 0400 across successful --apply rewrite',
      ok0400.status === 0 &&
      summary0400?.changed_count === 1 &&
      noLeak(ok0400) &&
      !existsSync(join(state, '.deploy-lock')) &&
      (lstatSync(join(creds, 'dj-codex.bunker-uri')).mode & 0o777) === 0o400 &&
      readFileSync(join(creds, 'dj-codex.bunker-uri'), 'utf8').includes('relay.ditto.pub'),
      ok0400.stderr || ok0400.stdout)
    restoreCleanSnapshot()
  }
} finally {
  rmSync(work, { recursive: true, force: true })
}

if (failures > 0) process.exit(1)
console.log('ALL fleet-relay-replace checks passed')
