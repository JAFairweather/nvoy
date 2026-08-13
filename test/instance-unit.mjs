// A participant identity is ONE deployable unit (#154): the stack and the access surface that
// exposes it are rendered from the same manifest, and what is installed can be checked against it.
//
// The property under test is not "verify refuses bad input". It is that verify can tell the
// difference between a principal that is correct, one that has drifted, and one that was never
// installed — so every refusal below is paired with a legitimate value that must still pass. A
// verifier that rejected everything would satisfy the refusals alone and be useless.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import { readManifest, assertNoCollisions } from '../mcp/tools/runtime_manifest.mjs'
import { forcedCommand, principalLine, parsePrincipal, verifyPrincipal, volumeLifecycle } from '../mcp/tools/participant_unit.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }

const root = mkdtempSync(join(tmpdir(), 'nvoy-unit-'))
const manifestRoot = join(root, 'instances')
mkdirSync(manifestRoot)
const pubkey = getPublicKey(generateSecretKey())
const base = {
  version: 1, id: 'claude-test', pubkey: nip19.npubEncode(pubkey),
  state_dir: join(root, 'state'), runtime_dir: join(root, 'run'), spool_dir: join(root, 'spool'),
  bunker_uri_ref: '/etc/nvoy/credentials/claude-test.bunker', bunker_client_ref: '/etc/nvoy/credentials/claude-test.client',
  broker_adapter_gid: 41001, worker_handoff_gid: 41002,
  watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  delivery_mode: 'notify_only', worker_enabled: false,
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'],
  relays: ['wss://nos.lol'],
}
// Each manifest gets its own state/runtime/spool roots: assertNoCollisions reads EVERY manifest in
// the directory, so a fixture sharing a directory — or a deliberately invalid one — would fail every
// later call rather than the one check it belongs to. Variants therefore live in their own root.
const variantRoot = join(root, 'variants')
mkdirSync(variantRoot)
const write = (id, extra = {}, into = manifestRoot) => {
  const m = { ...base, id, state_dir: join(root, `state-${id}`), runtime_dir: join(root, `run-${id}`), spool_dir: join(root, `spool-${id}`), ...extra }
  writeFileSync(join(into, `${id}.json`), JSON.stringify(m))
  return m
}
write('claude-test')
const keyBody = 'AAAAC3NzaC1lZDI1NTE5AAAA' + 'B'.repeat(20)
const keyFile = join(root, 'channel.pub')
writeFileSync(keyFile, `ssh-ed25519 ${keyBody} operator@example\n`)

const env = { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot }
const unit = (...args) => spawnSync(process.execPath, ['mcp/tools/instance-unit.mjs', ...args], { cwd: resolve('.'), encoding: 'utf8', env })
const keygen = (...args) => spawnSync(process.execPath, ['mcp/tools/instance-claude-channel-authorized-key.mjs', ...args], { cwd: resolve('.'), encoding: 'utf8', env })
const IMAGE = 'registry.example/runtime@sha256:' + 'a'.repeat(64)

// ---- the container name is declared, and the default preserves an existing stack ----
const m = readManifest(manifestRoot, 'claude-test')
ok('an adapter container defaults to exactly the name Compose already generates, so pinning it renames nothing', m.adapterContainer === 'nvoy-claude-test-adapter-1')
write('declared', { adapter_container: 'nvoy-declared-adapter' }, variantRoot)
ok('a manifest may declare its own adapter container name', readManifest(variantRoot, 'declared').adapterContainer === 'nvoy-declared-adapter')
write('badname', { adapter_container: 'not a valid name' }, variantRoot)
let badNameThrew = false
try { readManifest(variantRoot, 'badname') } catch { badNameThrew = true }
ok('a malformed adapter container name is refused rather than shipped into a forced command', badNameThrew)

// ---- render emits the whole unit from one manifest ----
const rendered = unit('render', '--instance', 'claude-test', '--image', IMAGE, '--public-key-file', keyFile)
ok('render emits the Compose stack', rendered.status === 0 && /name: nvoy-claude-test/.test(rendered.stdout))
ok('the rendered adapter pins the manifest container name rather than letting Compose derive it', /container_name: "nvoy-claude-test-adapter-1"/.test(rendered.stdout))
ok('render emits the access surface alongside the stack, so the unit is one artifact', /restrict,command="/.test(rendered.stdout) && rendered.stdout.includes(keyBody))
const withoutKey = unit('render', '--instance', 'claude-test', '--image', IMAGE)
ok('rendering without a public key SAYS the access surface was not rendered rather than quietly omitting it', withoutKey.status === 0 && /access surface was NOT rendered/.test(withoutKey.stderr))
const outDir = join(root, 'out')
mkdirSync(outDir)
const toDisk = unit('render', '--instance', 'claude-test', '--image', IMAGE, '--public-key-file', keyFile, '--out-dir', outDir)
ok('render writes both artifacts to disk', toDisk.status === 0 && existsSync(join(outDir, 'claude-test.compose.yml')) && existsSync(join(outDir, 'claude-test.authorized_key')))

// ---- the generator no longer takes the container name on trust ----
const generated = keygen('--instance', 'claude-test', '--public-key-file', keyFile)
ok('the principal generator takes the container from the manifest, with no --container needed', generated.status === 0 && generated.stdout.includes('nvoy-claude-test-adapter-1'))
const agreeing = keygen('--instance', 'claude-test', '--public-key-file', keyFile, '--container', 'nvoy-claude-test-adapter-1')
ok('a --container that agrees with the manifest is still accepted, so existing call sites keep working', agreeing.status === 0)
const drifted = keygen('--instance', 'claude-test', '--public-key-file', keyFile, '--container', 'nvoy-claude-test-adapter-7')
ok('a --container that disagrees with the manifest is refused instead of silently winning', drifted.status !== 0 && /does not match the manifest/.test(drifted.stderr))

// ---- verify: the installed surface against the manifest ----
const goodLine = principalLine(m, 'ssh-ed25519', keyBody)
const keysFile = join(root, 'authorized_keys')
const verify = (...args) => unit('verify', '--instance', 'claude-test', '--authorized-keys', keysFile, ...args)

writeFileSync(keysFile, `${goodLine}\n`)
const clean = verify()
ok('a correctly installed principal verifies', clean.status === 0 && /verified 8\/8/.test(clean.stdout))

writeFileSync(keysFile, `# a comment\nssh-ed25519 ${keyBody} someone-else@example\n${goodLine}\n`)
ok('unrelated principals in the same file do not disturb the verdict', verify().status === 0)

writeFileSync(keysFile, `${goodLine.replace('nvoy-claude-test-adapter-1', 'nvoy-claude-test-adapter-7')}\n`)
const containerDrift = verify()
ok('a principal whose container drifted from the stack FAILS — the silent-channel case', containerDrift.status === 1 && /FAIL — targets the manifest adapter container/.test(containerDrift.stdout))

writeFileSync(keysFile, `${goodLine.replace('--user 41014:41002', '--user 0:0')}\n`)
const uidDrift = verify()
ok('a principal whose uid:gid drifted from the manifest FAILS', uidDrift.status === 1 && /FAIL — runs as the manifest worker uid:gid/.test(uidDrift.stdout))

writeFileSync(keysFile, `${goodLine.replace('restrict,', '')}\n`)
const noRestrict = verify()
ok('a principal with restrict stripped FAILS', noRestrict.status === 1 && /FAIL — restrict is intact/.test(noRestrict.stdout))

writeFileSync(keysFile, `${goodLine.replace('restrict,', 'restrict,pty,')}\n`)
const reEnabled = verify()
ok('a principal that re-enables a capability restrict had removed FAILS', reEnabled.status === 1 && /FAIL — no restricted capability is re-enabled/.test(reEnabled.stdout))

writeFileSync(keysFile, `${goodLine.replace('claude-channel.mjs', 'instance-broker.mjs')}\n`)
const wrongTool = verify()
ok('a principal pointed at a different tool FAILS', wrongTool.status === 1 && /FAIL — invokes the channel tool and nothing else/.test(wrongTool.stdout))

writeFileSync(keysFile, `ssh-ed25519 ${keyBody} unrelated@example\n`)
const absent = verify()
ok('a principal that was never installed FAILS rather than passing by absence', absent.status === 1 && /no principal for claude-test is installed/.test(absent.stderr))

writeFileSync(keysFile, `${goodLine}\n${goodLine}\n`)
const duplicate = verify()
ok('two principals with the same comment FAIL, because which one authorises is ambiguous', duplicate.status === 1 && /ambiguous/.test(duplicate.stderr))

const missing = unit('verify', '--instance', 'claude-test', '--authorized-keys', join(root, 'no-such-file'))
ok('an unreadable authorized_keys is INCONCLUSIVE (exit 3), never a pass — being unable to check is not being fine', missing.status === 3 && /INCONCLUSIVE/.test(missing.stderr))

// ---- the forced command lives in exactly one place ----
const generatedLine = generated.stdout.trim()
ok('the generator and the verifier agree, because both build the command from one function', verifyPrincipal(m, generatedLine)?.ok === true)
ok('the parser rejects a line that is not a forced-command principal', parsePrincipal(`ssh-ed25519 ${keyBody} plain@example`) === null)
const keygenSource = readFileSync('mcp/tools/instance-claude-channel-authorized-key.mjs', 'utf8')
ok('the generator holds no second copy of the docker exec string', !/docker exec/.test(keygenSource))
ok('the forced command names the manifest container, uid, gid and instance', (() => {
  const c = forcedCommand(m)
  return c.includes('nvoy-claude-test-adapter-1') && c.includes('--user 41014:41002') && c.endsWith('--instance claude-test')
})())

// ---- restart vs destroy: one verb each, never one flag ----
// docker is stubbed so the verbs can be driven without a daemon. The property under test is which
// command each verb WOULD run: `-v` is the whole difference between restarting compute and
// destroying an identity.
const bin = join(root, 'bin')
mkdirSync(bin)
const calls = join(root, 'docker-calls.log')
const fakeDocker = join(bin, 'fake-docker')
writeFileSync(fakeDocker, `#!/bin/sh\nprintf 'docker %s\\n' "$*" >> ${JSON.stringify(calls)}\nexit 0\n`, { mode: 0o755 })
const composeFile = join(root, 'claude-test.compose.yml')
writeFileSync(composeFile, 'name: nvoy-claude-test\nservices: {}\n')
const dockerEnv = { ...env, NVOY_DOCKER: fakeDocker }
const lifecycle = volumeLifecycle(m)
const run = (...args) => spawnSync(process.execPath, ['mcp/tools/instance-unit.mjs', ...args], { cwd: resolve('.'), encoding: 'utf8', env: dockerEnv })
const readCalls = () => (existsSync(calls) ? readFileSync(calls, 'utf8') : '')

ok('a worker-disabled identity has four volumes, not five — the worker credential belongs to a worker', lifecycle.length === 4 && !lifecycle.some(v => v.suffix === 'worker_credentials'))
ok('the Bunker credential volume is marked as NOT re-renderable from the manifest', lifecycle.find(v => v.suffix === 'broker_credentials')?.reRenderable === false)

const restartDry = run('restart', '--instance', 'claude-test', '--compose-file', composeFile, '--dry-run')
ok('restart names every volume it will keep', restartDry.status === 0 && /KEEPS all 4 volumes/.test(restartDry.stdout) && /keep nvoy-claude-test_broker_credentials/.test(restartDry.stdout))
ok('restart would force-recreate the containers', /up -d --force-recreate/.test(restartDry.stdout))
ok('restart NEVER offers to drop a volume — the one-flag difference cannot be reached from this verb', !/ -v\b/.test(restartDry.stdout) && !/\bdown\b/.test(restartDry.stdout))
ok('a dry run executes no docker at all', readCalls() === '')

const restartReal = run('restart', '--instance', 'claude-test', '--compose-file', composeFile)
ok('restart actually invokes compose up, not down', restartReal.status === 0 && /compose -f .* up -d --force-recreate/.test(readCalls()) && !/down/.test(readCalls()))

writeFileSync(calls, '')
const noToken = run('destroy', '--instance', 'claude-test', '--compose-file', composeFile)
ok('destroy without the confirmation token refuses', noToken.status === 1 && /refusing to destroy claude-test/.test(noToken.stderr))
ok('destroy states the Bunker re-pair cost BEFORE it refuses, so the operator learns it from the tool', /BUNKER RE-PAIR/.test(noToken.stderr))
ok('destroy names which volumes cannot be re-rendered from the manifest', /CANNOT be re-rendered/.test(noToken.stderr) && /nvoy-claude-test_broker_credentials/.test(noToken.stderr))
ok('destroy says plainly that this is destroying an identity rather than restarting compute', /destroying an identity, not restarting compute/.test(noToken.stderr))
ok('a refused destroy runs no docker', readCalls() === '')

const wrongToken = run('destroy', '--instance', 'claude-test', '--compose-file', composeFile, '--i-understand-this-destroys', 'some-other-id')
ok('a confirmation token naming a DIFFERENT unit is refused — you cannot confirm a destroy you were not looking at', wrongToken.status === 1 && /refusing to destroy claude-test/.test(wrongToken.stderr))
ok('a mis-confirmed destroy runs no docker', readCalls() === '')

const destroyDry = run('destroy', '--instance', 'claude-test', '--compose-file', composeFile, '--i-understand-this-destroys', 'claude-test', '--dry-run')
ok('a correctly confirmed destroy is accepted, so the guard is not simply refusing everything', destroyDry.status === 0 && /nothing was destroyed/.test(destroyDry.stderr))
ok('a dry-run destroy still runs no docker', readCalls() === '')

const destroyReal = run('destroy', '--instance', 'claude-test', '--compose-file', composeFile, '--i-understand-this-destroys', 'claude-test')
ok('a confirmed destroy invokes compose down WITH -v', destroyReal.status === 0 && /compose -f .* down -v/.test(readCalls()))

const missingCompose = run('restart', '--instance', 'claude-test', '--compose-file', join(root, 'no-such.yml'))
ok('a missing compose file is refused rather than passed to docker', missingCompose.status === 1 && /does not exist/.test(missingCompose.stderr))


// UID AND GID COLLISIONS ACROSS MANIFESTS (#177).
//
// This is a credential boundary, not tidiness. instance-runtime-init.mjs provisions the Bunker URI
// and NIP-46 client key to brokerUid:brokerAdapterGid at mode 0400 — owner-read only. There is no
// useradd in that path, so a duplicate uid is not a name clash that fails loudly; it is a second
// instance whose broker runs as the same OS user and can read the first one's credentials.
//
// Every refusal below is paired with a value that must still pass, because a checker that refused
// every second manifest would satisfy the refusals alone. And each asserts the REASON: the
// operator's next move is to renumber one specific block, which "collision" alone does not locate.
const freshKey = () => nip19.npubEncode(getPublicKey(generateSecretKey()))
const collide = (name, a, b) => {
  const dir = join(root, `collide-${name}`)
  mkdirSync(dir)
  // A distinct pubkey per fixture: `base` carries one, and two manifests sharing it would trip the
  // pubkey check first and report a pass/refusal that says nothing about uids.
  write(`alpha-${name}`, { pubkey: freshKey(), ...a }, dir)
  write(`beta-${name}`, { pubkey: freshKey(), ...b }, dir)
  try { assertNoCollisions(dir, null); return null } catch (e) { return e.message || String(e) }
}

const cleanPair = collide('clean',
  { watcher_uid: 41111, broker_uid: 41112, adapter_uid: 41113, worker_uid: 41114, broker_adapter_gid: 42111, worker_handoff_gid: 42112 },
  { watcher_uid: 41121, broker_uid: 41122, adapter_uid: 41123, worker_uid: 41124, broker_adapter_gid: 42121, worker_handoff_gid: 42122 })
ok('two fully distinct manifests still pass — the check is not refusing every second identity', cleanPair === null, String(cleanPair))

const sameRole = collide('samerole',
  { watcher_uid: 41211, broker_uid: 41212, adapter_uid: 41213, worker_uid: 41214, broker_adapter_gid: 42211, worker_handoff_gid: 42212 },
  { watcher_uid: 41221, broker_uid: 41212, adapter_uid: 41223, worker_uid: 41224, broker_adapter_gid: 42221, worker_handoff_gid: 42222 })
ok('a shared broker_uid is refused — the second broker would read the first one\'s Bunker credential',
  sameRole !== null, String(sameRole))
ok('  ...and the reason names broker_uid and both instances, so the operator knows which block to renumber',
  /broker_uid collision between alpha-samerole and beta-samerole/.test(sameRole || ''), String(sameRole))

// The case that keying by ROLE would have missed: same number, different role. Still one OS user.
const crossRole = collide('crossrole',
  { watcher_uid: 41311, broker_uid: 41312, adapter_uid: 41313, worker_uid: 41314, broker_adapter_gid: 42311, worker_handoff_gid: 42312 },
  { watcher_uid: 41321, broker_uid: 41322, adapter_uid: 41323, worker_uid: 41311, broker_adapter_gid: 42321, worker_handoff_gid: 42322 })
ok('one instance\'s worker_uid equal to another\'s watcher_uid is refused — it is the same OS user either way',
  crossRole !== null, String(crossRole))
ok('  ...and the reason names BOTH roles and the number, because they differ',
  /uid 41311 collision between alpha-crossrole \(watcher_uid\) and beta-crossrole \(worker_uid\)/.test(crossRole || ''),
  String(crossRole))

const sameGid = collide('samegid',
  { watcher_uid: 41411, broker_uid: 41412, adapter_uid: 41413, worker_uid: 41414, broker_adapter_gid: 42411, worker_handoff_gid: 42412 },
  { watcher_uid: 41421, broker_uid: 41422, adapter_uid: 41423, worker_uid: 41424, broker_adapter_gid: 42411, worker_handoff_gid: 42422 })
ok('a shared broker_adapter_gid is refused too', sameGid !== null, String(sameGid))
ok('  ...naming the gid field', /broker_adapter_gid collision/.test(sameGid || ''), String(sameGid))

// Over-broad is its own failure. A uid and a gid are different namespaces on the box, so the same
// NUMBER used as a uid here and a gid there is not a collision and must not be reported as one.
const uidGid = collide('uidgid',
  { watcher_uid: 41511, broker_uid: 41512, adapter_uid: 41513, worker_uid: 41514, broker_adapter_gid: 42511, worker_handoff_gid: 42512 },
  { watcher_uid: 41521, broker_uid: 41522, adapter_uid: 41523, worker_uid: 41524, broker_adapter_gid: 41511, worker_handoff_gid: 42522 })
ok('a number used as a uid in one manifest and a gid in another is NOT a collision — separate namespaces',
  uidGid === null, String(uidGid))

// The deployed fleet must still start. These are the two live allocations as installed — the
// convention this check turns into an invariant. A new rule that rejected the running configuration
// would be found at the worst possible moment, so it is asserted here rather than discovered there.
const live = collide('live',
  { watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014, broker_adapter_gid: 42011, worker_handoff_gid: 42012 },
  { watcher_uid: 41021, broker_uid: 41022, adapter_uid: 41023, worker_uid: 41024, broker_adapter_gid: 42021, worker_handoff_gid: 42022 })
ok('the two allocations currently deployed still pass — this rule breaks nothing already running',
  live === null, String(live))

console.log(fails ? `\ninstance-unit: ${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
