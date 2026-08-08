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
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { forcedCommand, principalLine, parsePrincipal, verifyPrincipal } from '../mcp/tools/participant_unit.mjs'

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

console.log(fails ? `\ninstance-unit: ${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
