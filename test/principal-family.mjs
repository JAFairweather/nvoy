// principal-family.mjs — a Pi or Codex agent is seated with two principals, not one Claude channel.
//
// What this suite holds (nvoy, hosted onboarding route, waggle #721):
//
//   - the harness table: pi and codex need two keys; every other harness keeps the one Claude key;
//   - the codex lines are byte-identical to what instance-codex-channel-authorized-key.mjs prints,
//     for both roles (the generator now calls the same builder, so they cannot drift);
//   - apply plans BOTH lines before it changes anything: a missing, equal or drifted feed key refuses
//     with nothing installed; the Claude family is unchanged, one line and the Claude baseline;
//   - a two-key apply cannot pass verification with only one principal, or with a Claude command;
//   - a partial seat is reported and a re-run is idempotent, appending only what is missing;
//   - the baseline is not the Claude tool for this family, and says why.
//
//   node test/principal-family.mjs

import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, chmodSync, statSync, readdirSync, symlinkSync, lstatSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { allocateIdentityBlock, buildParticipantManifest } from '../mcp/tools/identity_allocation.mjs'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { principalLine } from '../mcp/tools/participant_unit.mjs'
import { applyStaged, digestOf, repairInstalled, replaceFileAtomic } from '../mcp/tools/instance_apply.mjs'
import { familyOf, keysFor, codexPrincipalLine, codexPrincipalPlan, verifyCodexPrincipal, codexForcedCommand, distinctKeys } from '../mcp/tools/principal_family.mjs'

let pass = true
const check = (cond, label) => { console.log(`${cond ? 'ok  ' : 'FAIL'} — ${label}`); if (!cond) pass = false }
const here = dirname(fileURLToPath(import.meta.url)), tools = join(here, '..', 'mcp', 'tools')

const CHANNEL = { keyType: 'ssh-ed25519', keyBody: 'AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'a'.repeat(40) }
const FEED = { keyType: 'ssh-ed25519', keyBody: 'AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'b'.repeat(40) }

// ── the table ─────────────────────────────────────────────────────────────────────────────────────
check(familyOf('pi') === 'codex' && familyOf('codex') === 'codex', 'pi and codex are the two-key family')
check(['claude-code', 'openclaw', 'grokbot', 'hermes', 'antigravity', '', undefined].every(h => familyOf(h) === 'claude'), 'every other harness keeps the Claude channel, as before')
check(keysFor('pi').join() === 'channel,feed' && keysFor('claude-code').join() === 'channel', 'two keys for pi, one for the rest')
check(distinctKeys(CHANNEL, FEED) && !distinctKeys(CHANNEL, CHANNEL) && !distinctKeys(CHANNEL, null), 'distinct keys: equal or missing is not a pair')

// ── a manifest, staged ───────────────────────────────────────────────────────────────────────────
const tmp = mkdtempSync(join(tmpdir(), 'nvoy-family-'))
const creds = join(tmp, 'credentials'), staged = join(tmp, 'staged')
mkdirSync(creds); mkdirSync(staged)
const raw = buildParticipantManifest(allocateIdentityBlock([], { id: 'hr' }), { pubkey: '1'.repeat(64), grantors: ['2'.repeat(64)], relays: ['wss://relay.example'], credentialDir: creds })
const stagedPath = join(staged, 'hr.json')
writeFileSync(stagedPath, JSON.stringify(raw, null, 2) + '\n')
const manifest = readManifest(staged, 'hr')
const digest = digestOf(readFileSync(stagedPath))

// ── the lines are what the existing generator prints ─────────────────────────────────────────────
{
  const root = join(tmp, 'gen-root'); mkdirSync(root)
  writeFileSync(join(root, 'hr.json'), JSON.stringify(raw, null, 2) + '\n')
  for (const [role, key] of [['channel', CHANNEL], ['feed', FEED]]) {
    const keyFile = join(tmp, `${role}.pub`)
    writeFileSync(keyFile, `${key.keyType} ${key.keyBody} somebody@box\n`)
    const out = spawnSync(process.execPath, [join(tools, 'instance-codex-channel-authorized-key.mjs'), '--instance', 'hr', '--public-key-file', keyFile, '--container', manifest.adapterContainer, '--mode', role],
      { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: root } })
    check(out.status === 0 && out.stdout.trimEnd() === codexPrincipalLine(manifest, role, key.keyType, key.keyBody),
      `${role}: the generator's line and the shared builder's line are the same bytes`)
  }
  check(codexPrincipalLine(manifest, 'channel', CHANNEL.keyType, CHANNEL.keyBody).includes('/codex-channel-mcp.mjs --instance hr')
    && codexPrincipalLine(manifest, 'feed', FEED.keyType, FEED.keyBody).includes('/codex-channel-feed.mjs --instance hr')
    && codexPrincipalLine(manifest, 'channel', CHANNEL.keyType, CHANNEL.keyBody).endsWith(' nvoy-codex-channel-hr')
    && codexPrincipalLine(manifest, 'feed', FEED.keyType, FEED.keyBody).endsWith(' nvoy-codex-feed-hr'), 'each role runs its own program under its own comment')
}

// ── per-role plans and checks ────────────────────────────────────────────────────────────────────
const channelLine = codexPrincipalLine(manifest, 'channel', CHANNEL.keyType, CHANNEL.keyBody)
const feedLine = codexPrincipalLine(manifest, 'feed', FEED.keyType, FEED.keyBody)
check(codexPrincipalPlan('', manifest, 'feed', FEED).action === 'append' && codexPrincipalPlan(`${feedLine}\n`, manifest, 'feed', FEED).action === 'present', 'plan: append when absent, present when exact')
check(codexPrincipalPlan(codexPrincipalLine(manifest, 'feed', CHANNEL.keyType, CHANNEL.keyBody), manifest, 'feed', FEED).action === 'refuse', 'plan: a different key under the feed comment refuses')
check(codexPrincipalPlan(`${feedLine}\n${feedLine}\n`, manifest, 'feed', FEED).action === 'refuse', 'plan: two feed lines refuse as ambiguous')
check(verifyCodexPrincipal(manifest, 'channel', channelLine).ok && verifyCodexPrincipal(manifest, 'feed', feedLine).ok, 'verify: both exact lines pass')
check(channelLine.includes(' --key-fp SHA256:') && !feedLine.includes('--key-fp'), 'only the channel line names its key fingerprint')
check(verifyCodexPrincipal(manifest, 'channel', channelLine).fingerprint === 'bound', 'verify: the tagged channel line is bound to its key')
check(verifyCodexPrincipal(manifest, 'channel', channelLine.replace(/ --key-fp [^"]+/, '')).fingerprint === 'untagged', 'verify: an older untagged channel line still verifies, as untagged')
check(!verifyCodexPrincipal(manifest, 'channel', channelLine.replace(/--key-fp SHA256:\S{43}/, 'SHA256:' + 'A'.repeat(43)).replace('SHA256:' + 'A'.repeat(43), '--key-fp SHA256:' + 'A'.repeat(43))).ok, 'verify: a channel line naming another key fails')
check(codexPrincipalPlan(channelLine.replace(/ --key-fp [^"]+/, ''), manifest, 'channel', CHANNEL).action === 'upgrade', 'plan: the same key seated untagged upgrades')
check(codexPrincipalPlan(codexPrincipalLine(manifest, 'channel', FEED.keyType, FEED.keyBody).replace(/ --key-fp [^"]+/, ''), manifest, 'channel', CHANNEL).action === 'refuse', 'plan: a different key seated untagged still refuses')
const claude = principalLine(manifest, CHANNEL.keyType, CHANNEL.keyBody)
check(!verifyCodexPrincipal(manifest, 'channel', claude).ok, 'verify: the Claude command is not a channel principal for this family')
check(!verifyCodexPrincipal(manifest, 'channel', feedLine.replace('nvoy-codex-feed-hr', 'nvoy-codex-channel-hr')).ok, 'verify: the feed program under the channel comment is refused')
check(!verifyCodexPrincipal(manifest, 'feed', channelLine.replace('nvoy-codex-channel-hr', 'nvoy-codex-feed-hr')).ok, 'verify: the channel program under the feed comment is refused')
check(!verifyCodexPrincipal(manifest, 'channel', channelLine.replace('restrict,', 'restrict,pty,')).ok, 'verify: a re-enabled capability is refused')

// ── instance-unit verify --family codex, as the operator runs it ─────────────────────────────────
{
  const root = join(tmp, 'unit-root'); mkdirSync(root)
  writeFileSync(join(root, 'hr.json'), JSON.stringify(raw, null, 2) + '\n')
  const verify = lines => {
    const keys = join(tmp, `ak-${Math.random().toString(16).slice(2)}`); writeFileSync(keys, lines.join('\n') + '\n')
    return spawnSync(process.execPath, [join(tools, 'instance-unit.mjs'), 'verify', '--instance', 'hr', '--authorized-keys', keys, '--family', 'codex'],
      { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: root } }).status
  }
  check(verify([channelLine, feedLine]) === 0, 'unit verify: both principals present and exact passes')
  check(verify([channelLine]) !== 0, 'unit verify: only the channel principal fails')
  check(verify([feedLine]) !== 0, 'unit verify: only the feed principal fails')
  check(verify([claude, feedLine]) !== 0, 'unit verify: a Claude command in place of the channel principal fails')
  check(verify([channelLine, feedLine.replace('codex-channel-feed.mjs', 'codex-channel-mcp.mjs')]) !== 0, 'unit verify: the channel program on the feed key fails')
  {
    const keys = join(tmp, 'ak-hint'); writeFileSync(keys, feedLine + '\n')
    const out = spawnSync(process.execPath, [join(tools, 'instance-unit.mjs'), 'verify', '--instance', 'hr', '--authorized-keys', keys, '--family', 'codex'],
      { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: root } })
    check(/expected command: .*codex-channel-mcp\.mjs --instance hr --key-fp <SHA256/.test(out.stderr), 'unit verify: a missing channel principal is hinted with its --key-fp, as it is now seated')
  }
}

// ── the apply sequence ───────────────────────────────────────────────────────────────────────────
let n = 0
const scenario = ({ keys = '', feedKey = FEED, publicKey = CHANNEL, family = 'codex', verifyStatus = 0, preinstall = false }) => {
  const dir = join(tmp, `s${++n}`), root = join(dir, 'instances'), state = join(dir, 'state'), keysPath = join(dir, 'authorized_keys')
  mkdirSync(root, { recursive: true }); mkdirSync(state)
  writeFileSync(join(root, 'pi-dog.json'), '{"id":"pi-dog"}\n')
  if (preinstall) writeFileSync(join(root, 'hr.json'), '{"id":"someone else"}\n')
  writeFileSync(keysPath, keys)
  const calls = []
  let clock = 2_000_000
  const ctx = { root, state, keysPath, calls, ledger: join(dir, 'identity-blocks.jsonl') }
  const runner = () => { writeFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), JSON.stringify({ 'pi-dog': 'x', hr: digest })); writeFileSync(join(root, 'hr.compose.yml'), 'services: {}\n') }
  return { ctx, go: () => applyStaged({ manifest, stagedPath, root, stateDir: state, keysPath, publicKey, family, feedKey, waitMs: 20000, pollMs: 5000, ledgerPath: ctx.ledger,
    now: () => clock, sleep: async ms => { clock += ms; runner() },
    run: argv => { calls.push(argv); return argv[0] === 'verify' ? { status: verifyStatus, stdout: 'verified', stderr: verifyStatus ? 'FAIL' : '' } : { status: 0, stdout: 'baselined 3', stderr: '' } } }) }
}
const states = r => r.states.map(s => `${s.state}:${s.ok}`).join(' ')
const lines = path => readFileSync(path, 'utf8').split('\n').filter(Boolean)

{
  const { ctx, go } = scenario({})
  const r = await go()
  check(r.ok && states(r) === 'principal planned:true block recorded:true installed:true deployed:true principal seated:true principal verified:true baselined:true', `two-key apply, every state reported: ${states(r)}`)
  check(lines(ctx.keysPath).join('\n') === `${channelLine}\n${feedLine}`, 'both principals were seated: the channel line, then the feed line, exact bytes')
  const verify = ctx.calls.find(c => c[0] === 'verify')
  check(verify && verify.includes('--family') && verify[verify.indexOf('--family') + 1] === 'codex', 'verification was asked for the codex family')
  check(!ctx.calls.some(c => c[0] === 'baseline') && /feed baselines on its first start/.test(r.states.at(-1).detail), 'the Claude baseline is not run, and the state says why')
}
{
  const { ctx, go } = scenario({ feedKey: null })
  const r = await go()
  check(!r.ok && states(r) === 'principal planned:false' && /no feed key/.test(r.states[0].detail), 'a two-key bind without a feed key refuses at the plan')
  check(lines(ctx.keysPath).length === 0 && !ctx.calls.length, 'and nothing was seated, installed or run')
}
{
  const { ctx, go } = scenario({ feedKey: CHANNEL })
  const r = await go()
  check(!r.ok && /same key/.test(r.states[0].detail) && lines(ctx.keysPath).length === 0, 'equal channel and feed keys refuse before anything changes')
}
{
  const swapped = scenario({ publicKey: FEED, feedKey: CHANNEL })
  const r = await swapped.go()
  check(r.ok && lines(swapped.ctx.keysPath).join('\n') === `${codexPrincipalLine(manifest, 'channel', FEED.keyType, FEED.keyBody)}\n${codexPrincipalLine(manifest, 'feed', CHANNEL.keyType, CHANNEL.keyBody)}`,
    'keys are seated by role, so the roles in the bind decide which program each key reaches')
}
{
  const drifted = codexPrincipalLine(manifest, 'feed', CHANNEL.keyType, CHANNEL.keyBody)
  const { ctx, go } = scenario({ keys: `${drifted}\n` })
  const r = await go()
  check(!r.ok && states(r) === 'principal planned:false' && /nvoy-codex-feed-hr/.test(r.states[0].detail), 'a different key already under the feed comment refuses at the plan')
  check(lines(ctx.keysPath).join('\n') === drifted && !ctx.calls.length, 'and neither line was added')
}
{
  const { ctx, go } = scenario({ keys: `${channelLine}\n` })
  const r = await go()
  check(r.ok && /channel already present, feed appended/.test(r.states.find(s => s.state === 'principal seated').detail), 'a partial seat (channel there, feed missing) appends only the feed, and says so')
  check(lines(ctx.keysPath).join('\n') === `${channelLine}\n${feedLine}`, 'ending with exactly one of each')
}
{
  const { ctx, go } = scenario({ keys: `${channelLine}\n${feedLine}\n` })
  const r = await go()
  check(r.ok && lines(ctx.keysPath).length === 2 && /already present, unchanged/.test(r.states[0].detail), 'a re-run with both present changes nothing')
}
{
  const { ctx, go } = scenario({ verifyStatus: 1 })
  const r = await go()
  check(!r.ok && states(r).endsWith('principal seated:true principal verified:false') && !r.states.some(s => s.state === 'baselined'), 'a failed verify stops the apply: no baseline step, not ok')
}
{
  const { ctx, go } = scenario({})
  chmodSync(ctx.keysPath, 0o444)
  const r = process.getuid?.() === 0 ? null : await go()
  check(r === null || (!r.ok && /stopped at/.test(r.states.at(-1).detail) && /run again to seat the rest/.test(r.states.at(-1).detail)), 'a write failure while seating reports what was and was not seated and how to retry (skipped as root)')
}
{
  const { ctx, go } = scenario({ family: 'claude', feedKey: null })
  const r = await go()
  check(r.ok && lines(ctx.keysPath).length === 1 && lines(ctx.keysPath)[0] === principalLine(manifest, CHANNEL.keyType, CHANNEL.keyBody)
    && ctx.calls.some(c => c[0] === 'baseline') && !ctx.calls.find(c => c[0] === 'verify').includes('--family'), 'the Claude family is unchanged: one principal, the Claude verify, the Claude baseline')
}

// ── repair: an install that stopped after the manifest went in ───────────────────────────────────
// apply refuses an id already installed, so a retry after a failed seat or verify needs its own path. It installs
// nothing, checks the runner recorded exactly the installed bytes, then seats and verifies as apply does.
{
  const repairScenario = ({ keys = '', family = 'codex', feedKey = FEED, deployed = true, verifyStatus = 0, link = false }) => {
    const dir = join(tmp, `r${++n}`), root = join(dir, 'instances'), state = join(dir, 'state'), keysPath = join(dir, 'authorized_keys')
    mkdirSync(root, { recursive: true }); mkdirSync(state)
    writeFileSync(join(root, 'hr.json'), readFileSync(stagedPath))
    if (deployed) { writeFileSync(join(state, 'DEPLOYED_MANIFESTS.json'), JSON.stringify({ hr: digest })); writeFileSync(join(root, 'hr.compose.yml'), 'services: {}\n') }
    writeFileSync(keysPath, keys)
    const calls = []
    return { keysPath, calls, go: () => repairInstalled({ manifest, root, stateDir: state, keysPath, publicKey: CHANNEL, family, feedKey,
      run: argv => { calls.push(argv); return argv[0] === 'verify' ? { status: verifyStatus, stdout: 'verified', stderr: verifyStatus ? 'FAIL' : '' } : { status: 0, stdout: 'baselined 3', stderr: '' } } }) }
  }
  {
    // an agent seated before channel lines named their fingerprint: repair upgrades that one line in place
    const untagged = channelLine.replace(/ --key-fp [^"]+/, '')
    const other = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'c'.repeat(40) + ' someone-else'
    const { keysPath, go } = repairScenario({ keys: `${other}\n${untagged}\n${feedLine}\n` })
    chmodSync(keysPath, 0o640)
    const before = statSync(keysPath)
    const r = go()
    const after = statSync(keysPath)
    check(after.ino !== before.ino && (after.mode & 0o7777) === 0o640 && after.uid === before.uid && after.gid === before.gid,
      'the upgrade replaces the file by rename (a new inode), keeping its mode and owner')
    check(readdirSync(dirname(keysPath)).every(f => !f.includes('.nvoy-')), 'and leaves no temp file behind')
    check(r.ok && lines(keysPath).join('\n') === `${other}\n${channelLine}\n${feedLine}`, `repair upgrades an untagged channel line in place, other lines untouched: ${states(r)}`)
    check(/upgraded/.test(r.states.find(st => st.state === 'principal seated').detail), 'and says it upgraded')
    check(go().ok && lines(keysPath).join('\n') === `${other}\n${channelLine}\n${feedLine}`, 'a second repair changes nothing')
  }
  {
    const { keysPath, calls, go } = repairScenario({ keys: `${channelLine}\n` })
    const r = go()
    check(r.ok && states(r) === 'principal planned:true deployed:true principal seated:true principal verified:true baselined:true', `repair of a half-seated agent: ${states(r)}`)
    check(lines(keysPath).join('\n') === `${channelLine}\n${feedLine}` && /channel already present, feed appended/.test(r.states.find(st => st.state === 'principal seated').detail), 'it appends only the missing feed line')
    check(!calls.some(c => c[0] === 'baseline'), 'and runs no Claude baseline for this family')
    check(go().ok && lines(keysPath).length === 2, 'a second repair changes nothing')
  }
  {
    const { keysPath, go } = repairScenario({ keys: '' })
    const r = go()
    check(r.ok && lines(keysPath).join('\n') === `${channelLine}\n${feedLine}`, 'repair seats both lines when neither was seated')
  }
  {
    const { keysPath, calls, go } = repairScenario({ deployed: false })
    const r = go()
    check(!r.ok && r.inconclusive && states(r) === 'principal planned:true deployed:null' && lines(keysPath).length === 0 && !calls.length, 'repair seats nothing while the runner has not recorded the installed manifest')
  }
  {
    const { keysPath, go } = repairScenario({ keys: `${codexPrincipalLine(manifest, 'feed', CHANNEL.keyType, CHANNEL.keyBody)}\n` })
    const r = go()
    check(!r.ok && states(r) === 'principal planned:false' && lines(keysPath).length === 1, 'repair keeps the plan\'s refusals: a different key under the feed comment is not overwritten')
  }
  {
    const { go } = repairScenario({ feedKey: null })
    check(!go().ok, 'repair of a two-key agent without a feed key refuses')
    const r = repairScenario({ verifyStatus: 1 }).go()
    check(!r.ok && states(r).endsWith('principal seated:true principal verified:false'), 'a failed verify is reported and is not ok')
  }
  {
    const { keysPath, calls, go } = repairScenario({ family: 'claude', feedKey: null })
    const r = go()
    check(r.ok && lines(keysPath)[0] === principalLine(manifest, CHANNEL.keyType, CHANNEL.keyBody) && calls.some(c => c[0] === 'baseline'), 'repair of a Claude-family agent seats its one line and baselines, as apply does')
  }
}

// ── replacing a shared authorized_keys: all or nothing ─────────────────────────────────────────────
{
  const dir = join(tmp, 'atomic'); mkdirSync(dir)
  const real = join(dir, 'authorized_keys'), link = join(dir, 'keys-link')
  writeFileSync(real, 'a\nb\n'); chmodSync(real, 0o600); symlinkSync(real, link)
  replaceFileAtomic(link, 'a\nb\n', 'a\nB\n')
  check(lstatSync(link).isSymbolicLink() && readFileSync(real, 'utf8') === 'a\nB\n' && (statSync(real).mode & 0o7777) === 0o600, 'a symlinked path: the target is replaced, the link and the mode survive')
  let threw = ''
  try { replaceFileAtomic(real, 'stale text', 'x\n') } catch (e) { threw = e.message }
  check(/changed while replacing/.test(threw) && readFileSync(real, 'utf8') === 'a\nB\n', 'a file that changed since it was read is refused and left as it is')
  threw = ''
  try { replaceFileAtomic(real, 'a\nB\n', 'half', { hooks: { beforeRename: () => { throw new Error('killed before rename') } } }) } catch (e) { threw = e.message }
  check(threw === 'killed before rename' && readFileSync(real, 'utf8') === 'a\nB\n', 'an interruption before the rename leaves the original whole')
  check(readdirSync(dir).sort().join() === 'authorized_keys,keys-link', 'and no temp file is left behind')
  threw = ''
  try { replaceFileAtomic(real, 'a\nB\n', 'z\n', { hooks: { rename: () => { throw Object.assign(new Error('busy'), { code: 'EBUSY' }) } } }) } catch (e) { threw = e.message }
  check(/bind-mounted; mount its directory instead/.test(threw) && readFileSync(real, 'utf8') === 'a\nB\n' && readdirSync(dir).length === 2, 'a rename refused as busy says the file looks bind-mounted, and leaves the original and no temp')
}

if (!pass) { console.error('principal-family: FAILED'); process.exit(1) }
console.log('principal-family: PASS')
