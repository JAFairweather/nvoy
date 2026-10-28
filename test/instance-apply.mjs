// instance-apply.mjs — installing a staged identity and seating its channel principal (#273).
//
// Drives the REAL apply sequence against a temporary instance root, with the runner played by the
// injected sleep: it writes what the runner writes, when the runner would. What this suite holds:
//
//   - nothing is installed while authorized_keys already holds a conflicting line for this identity;
//   - the block is recorded before the install, read again first: a block recorded for another
//     identity, an unreadable record or a failed write each stop the apply with nothing installed;
//   - the install never clobbers, and the runner's glob never sees the temporary file;
//   - "deployed" means the runner recorded THIS manifest's digest, not that a tick happened;
//   - a failed tick that saw this manifest withdraws it, a failure from an earlier estate does not,
//     and a timeout leaves it in place and reports INCONCLUSIVE;
//   - the principal is appended once, after the deploy, and a re-run changes nothing;
//   - every state is reported separately, and a failed verify stops before the baseline.
//
//   node test/instance-apply.mjs

import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, existsSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { allocateIdentityBlock, buildParticipantManifest, NUMERIC_FIELDS } from '../mcp/tools/identity_allocation.mjs'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { principalLine } from '../mcp/tools/participant_unit.mjs'
import { applyStaged, deployVerdict, digestOf, estateHash, principalPlan, readPublicKey } from '../mcp/tools/instance_apply.mjs'

let pass = true
const check = (cond, label) => { console.log(`${cond ? 'ok  ' : 'FAIL'} — ${label}`); if (!cond) pass = false }

const KEY = { keyType: 'ssh-ed25519', keyBody: 'AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'a'.repeat(40) }
const OTHER_KEY = { keyType: 'ssh-ed25519', keyBody: 'AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'b'.repeat(40) }

// ── the public key ───────────────────────────────────────────────────────────────────────────────
check(JSON.stringify(readPublicKey(`${KEY.keyType} ${KEY.keyBody} hr@box\n`)) === JSON.stringify(KEY), 'a .pub line yields its type and body; the comment is dropped')
for (const [text, why] of [['-----BEGIN OPENSSH PRIVATE KEY-----', 'a private key'], ['ssh-rsa AAAAB3Nza', 'an unsupported type'],
  [`restrict ${KEY.keyType} ${KEY.keyBody}`, 'an authorized_keys line with options']]) {
  let refused = false
  try { readPublicKey(text) } catch { refused = true }
  check(refused, `refuses ${why}`)
}

const tmp = mkdtempSync(join(tmpdir(), 'nvoy-apply-'))
const staged = join(tmp, 'staged'), creds = join(tmp, 'credentials')
mkdirSync(staged); mkdirSync(creds)
const manifest = (() => {
  const m = buildParticipantManifest(allocateIdentityBlock([], { id: 'hr' }), {
    pubkey: '1'.repeat(64), grantors: ['2'.repeat(64)], relays: ['wss://relay.example'], credentialDir: creds })
  writeFileSync(join(staged, 'hr.json'), JSON.stringify(m, null, 2) + '\n')
  return readManifest(staged, 'hr')
})()
const stagedPath = join(staged, 'hr.json')
const digest = digestOf(readFileSync(stagedPath))

// ── the principal plan ───────────────────────────────────────────────────────────────────────────
const want = principalLine(manifest, KEY.keyType, KEY.keyBody)
const unrelated = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther someone@else'
check(principalPlan(unrelated, manifest, KEY).action === 'append', 'an unrelated principal is left alone and ours is appended')
check(principalPlan(`${unrelated}\n${want}\n`, manifest, KEY).action === 'present', 'our exact line already present: nothing to do')
check(principalPlan(principalLine(manifest, OTHER_KEY.keyType, OTHER_KEY.keyBody), manifest, KEY).action === 'refuse', 'a different key under our comment refuses')
check(principalPlan(`${want}\n${want}\n`, manifest, KEY).action === 'refuse', 'two lines under our comment refuse: which authorises is ambiguous')

// ── the runner's record ──────────────────────────────────────────────────────────────────────────
const base = { id: 'hr', digest, composeExists: true, installedAt: 1000, estate: 'e1' }
check(deployVerdict({ ...base, deployed: { hr: digest } }) === 'deployed', 'deployed: this digest recorded and a compose file beside it')
check(deployVerdict({ ...base, deployed: { hr: 'f'.repeat(64) } }) === 'waiting', 'an older digest for the same id is not this deploy')
check(deployVerdict({ ...base, deployed: { hr: digest }, composeExists: false }) === 'waiting', 'a record without its compose file is not a deploy')
check(deployVerdict({ ...base, failed: { attempt: 'sha e1', at: 1001 } }) === 'failed', 'a failed tick that saw this estate is a failure')
check(deployVerdict({ ...base, failed: { attempt: 'sha e0', at: 1001 } }) === 'waiting', 'a failed tick over a different estate is not')
check(deployVerdict({ ...base, failed: { attempt: 'sha e1', at: 999 } }) === 'waiting', 'nor is one recorded before the install')

// ── the sequence ─────────────────────────────────────────────────────────────────────────────────
let n = 0
const scenario = ({ keys = `${unrelated}\n`, runner, verifyStatus = 0, preinstall = false, waitMs = 20000, record, ledger }) => {
  const dir = join(tmp, `s${++n}`), root = join(dir, 'instances'), state = join(dir, 'state'), keysPath = join(dir, 'authorized_keys')
  mkdirSync(root, { recursive: true }); mkdirSync(state)
  writeFileSync(join(root, 'pi-dog.json'), '{"id":"pi-dog"}\n')
  if (preinstall) writeFileSync(join(root, 'hr.json'), '{"id":"someone else"}\n')
  writeFileSync(keysPath, keys)
  const calls = []
  let clock = 2_000_000
  const ctx = { root, state, keysPath, calls }
  ctx.ledger = ledger || join(dir, 'identity-blocks.jsonl')
  if (record !== undefined) writeFileSync(ctx.ledger, record)
  return { ctx, go: () => applyStaged({ manifest, stagedPath, root, stateDir: state, keysPath, publicKey: KEY, waitMs, pollMs: 5000, ledgerPath: ctx.ledger,
    now: () => clock, sleep: async ms => { clock += ms; runner?.(ctx, clock / 1000) },
    run: argv => { calls.push(argv[0]); return argv[0] === 'verify' ? { status: verifyStatus, stdout: 'verified', stderr: verifyStatus ? 'FAIL — forced command' : '' } : { status: 0, stdout: 'baselined 3', stderr: '' } } }) }
}
const deploys = ({ root, state }) => {
  writeFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), JSON.stringify({ 'pi-dog': 'x', hr: digest }))
  writeFileSync(join(root, 'hr.compose.yml'), 'services: {}\n')
}
const states = r => r.states.map(s => `${s.state}:${s.ok}`).join(' ')

{
  const { ctx, go } = scenario({ runner: deploys })
  const r = await go()
  check(r.ok && states(r) === 'principal planned:true block recorded:true installed:true deployed:true principal seated:true principal verified:true baselined:true', `the whole sequence, each state reported: ${states(r)}`)
  check(readFileSync(join(ctx.root, 'hr.json')).equals(readFileSync(stagedPath)), 'the installed bytes are the staged bytes')
  check(readdirSync(ctx.root).sort().join(',') === 'hr.compose.yml,hr.json,pi-dog.json', 'no temporary file is left behind in the instance root')
  const lines = readFileSync(ctx.keysPath, 'utf8').split('\n').filter(Boolean)
  check(lines.length === 2 && lines[0] === unrelated && lines[1] === want, 'the principal is appended once, after the unrelated line it found')
  check(ctx.calls.join(',') === 'verify,baseline', 'instance-unit verify runs, then the baseline')
  const rec = JSON.parse(readFileSync(ctx.ledger, 'utf8'))
  check(rec.id === 'hr' && rec.watcherUid === manifest.watcherUid && rec.workerHandoffGid === manifest.workerHandoffGid, 'the block is recorded in identity-blocks.jsonl')
  check(principalPlan(readFileSync(ctx.keysPath, 'utf8'), manifest, KEY).action === 'present', 'a re-run would find the principal present and add nothing')
}
{
  const { ctx, go } = scenario({ keys: principalLine(manifest, OTHER_KEY.keyType, OTHER_KEY.keyBody) + '\n', runner: deploys })
  const r = await go()
  check(!r.ok && states(r) === 'principal planned:false' && !existsSync(join(ctx.root, 'hr.json')) && !existsSync(ctx.ledger), 'a conflicting principal refuses BEFORE anything is installed or recorded')
}
{
  const { ctx, go } = scenario({ preinstall: true, runner: deploys })
  const r = await go()
  check(!r.ok && /appeared since the check/.test(r.states.at(-1).detail) && /someone else/.test(readFileSync(join(ctx.root, 'hr.json'), 'utf8')),
    'an identity that appeared since the check is not clobbered')
  check(JSON.parse(readFileSync(ctx.ledger, 'utf8')).id === 'hr' && /reservation/.test(r.states.at(-1).detail), 'and the block it reserved stays recorded, and says so')
}
const blockOf = (id, m = manifest) => JSON.stringify({ id, ...Object.fromEntries(NUMERIC_FIELDS.map(f => [f, m[f]])) }) + '\n'
{
  const { ctx, go } = scenario({ runner: deploys, record: blockOf('retired-agent') })
  const r = await go()
  check(!r.ok && states(r) === 'principal planned:true block recorded:false' && /retired-agent/.test(r.states.at(-1).detail) && !existsSync(join(ctx.root, 'hr.json')),
    'a block recorded for a retired identity, now gone from the root, refuses before the install')
  check(readFileSync(ctx.ledger, 'utf8') === blockOf('retired-agent'), 'and the record is left as it was')
}
{
  const { ctx, go } = scenario({ runner: deploys, record: '{"id":"half"\n' })
  const r = await go()
  check(!r.ok && states(r).endsWith('block recorded:false') && /not JSON/.test(r.states.at(-1).detail) && !existsSync(join(ctx.root, 'hr.json')),
    'a record that cannot be parsed stops the apply: it cannot vouch that the block is free')
}
{
  const { ctx, go } = scenario({ runner: deploys, record: JSON.stringify({ id: 'odd', watcherUid: 41001 }) + '\n' })
  const r = await go()
  check(!r.ok && /has no integer/.test(r.states.at(-1).detail) && !existsSync(join(ctx.root, 'hr.json')), 'an entry missing a numeric field is refused, not read as clear')
}
{
  const { ctx, go } = scenario({ runner: deploys, ledger: join(tmp, 'no-such-dir', 'identity-blocks.jsonl') })
  const r = await go()
  check(!r.ok && states(r) === 'principal planned:true block recorded:false' && /nothing was installed/.test(r.states.at(-1).detail) && !existsSync(join(ctx.root, 'hr.json')),
    'a record that cannot be written stops the apply before the deploy trigger')
}
{
  const { ctx, go } = scenario({ runner: deploys, record: blockOf('hr') })
  const r = await go()
  check(r.ok && /already in/.test(r.states[1].detail) && readFileSync(ctx.ledger, 'utf8') === blockOf('hr'),
    'the same identity re-applied with the same block (after a withdrawal) is its own record, not a clash, and is not duplicated')
}
{
  const { ctx, go } = scenario({ runner: ({ root, state }) => writeFileSync(join(state, 'FAILED_ATTEMPT.json'), JSON.stringify({ attempt: `abc ${estateHash(root)}`, at: Date.now() })) })
  // `at` is wall-clock in the runner; the injected clock starts at 2 000 s, so any real time is after the install.
  const r = await go()
  check(!r.ok && states(r).endsWith('deployed:false') && !existsSync(join(ctx.root, 'hr.json')) && /withdrawn/.test(r.states.at(-1).detail),
    'a failed tick that saw this manifest: it is withdrawn, so the estate-wide rollback does not repeat')
  check(readFileSync(ctx.keysPath, 'utf8') === `${unrelated}\n`, 'and no principal was seated for an agent that never started')
  check(existsSync(ctx.ledger) && JSON.parse(readFileSync(ctx.ledger, 'utf8')).id === 'hr', 'but its block stays recorded: a container may have written files as those numbers')
}
{
  const { ctx, go } = scenario({ waitMs: 15000, runner: ({ state }) => writeFileSync(join(state, 'FAILED_ATTEMPT.json'), JSON.stringify({ attempt: 'abc not-this-estate', at: Date.now() })) })
  const r = await go()
  check(!r.ok && r.inconclusive && r.states.at(-1).ok === null && existsSync(join(ctx.root, 'hr.json')),
    'an unrelated failure, then no record: INCONCLUSIVE, and the manifest stays because the deploy may still be running')
}
{
  const { ctx, go } = scenario({ verifyStatus: 1, runner: deploys })
  const r = await go()
  check(!r.ok && states(r).endsWith('principal verified:false') && ctx.calls.join(',') === 'verify' && /forced command/.test(r.states.at(-1).detail),
    'a failed verify stops before the baseline and says why')
}

// ── the CLI gate: apply runs check first and installs nothing when it fails ─────────────────────
{
  const { spawnSync } = await import('node:child_process')
  const root = join(tmp, 'cli-root'), keysPath = join(tmp, 'cli-keys'), pub = join(tmp, 'hr.pub')
  mkdirSync(root)
  writeFileSync(keysPath, ''); writeFileSync(pub, `${KEY.keyType} ${KEY.keyBody}\n`, { mode: 0o644 })
  const r = spawnSync(process.execPath, [new URL('../mcp/tools/instance-identity.mjs', import.meta.url).pathname, 'apply', '--id', 'hr',
    '--public-key-file', pub, '--authorized-keys', keysPath, '--instance-root', root, '--out', staged], { encoding: 'utf8' })
  check(r.status === 1 && /FAIL {2}.*hr\.bunker-uri does not exist/.test(r.stdout) && /apply refused/.test(r.stderr) && !existsSync(join(root, 'hr.json')),
    'apply with unseated credentials: the check fails, apply refuses, and the instance root is untouched')
  const checkArgs = ['check', '--id', 'hr', '--instance-root', root, '--out', staged]
  const cli = args => spawnSync(process.execPath, [new URL('../mcp/tools/instance-identity.mjs', import.meta.url).pathname, ...args], { encoding: 'utf8' })
  const record = join(tmp, 'identity-blocks.jsonl')
  writeFileSync(record, blockOf('retired-agent'))
  const c = cli(checkArgs)
  check(c.status === 1 && /FAIL {2}uid\/gid block overlaps retired-agent/.test(c.stdout), 'check: a staged block that reuses a retired identity\'s recorded numbers FAILS')
  writeFileSync(record, 'not json\n')
  check(cli(checkArgs).status === 3, 'check: an unreadable record is INCONCLUSIVE (exit 3)')
  rmSync(record)
}

rmSync(tmp, { recursive: true, force: true })
console.log(`\n${pass ? 'ALL PASS' : 'FAILURES ABOVE'}`)
process.exit(pass ? 0 : 1)
