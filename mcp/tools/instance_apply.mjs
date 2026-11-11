// instance_apply.mjs — install a checked, staged identity and seat its channel principal (#273).
//
// The order is the point, and each state is reported on its own:
//
//   1. principal planned   the authorized_keys line is decided BEFORE anything changes, so a file
//                          already holding a different line under this identity's comment refuses
//                          the whole apply rather than half of it.
//   2. block recorded      under an exclusive lock, the record is read again immediately before the
//                          install; a block it already holds for another identity refuses. The UID/GID block is then
//                          appended and synced BEFORE the deploy trigger, so no container ever runs
//                          as numbers the record lacks. A record that cannot be read or written stops
//                          the apply with nothing installed. A block recorded for an install that then
//                          fails stays recorded: a reservation costs ten numbers, a reuse costs a
//                          security domain.
//   3. installed           the staged bytes land in the instance root under a no-clobber link. That
//                          IS the deploy trigger (see instance-identity.mjs).
//   4. deployed            the runner recorded this exact manifest digest and wrote its compose file.
//                          A FAILED_ATTEMPT naming the estate as installed means a tick that saw
//                          this manifest failed and the runner rolled every identity back; the manifest is then withdrawn, because
//                          leaving it would re-run that estate-wide rollback every RETRY_AFTER_S.
//   5. principal seated    appended only after the deploy: the forced command execs into a container
//                          that does not exist before it.
//   6. principal verified  by instance-unit.mjs verify, the same check an operator runs.
//   7. baselined           claude-channel.mjs --baseline in the adapter, so the agent does not wake
//                          to every envelope admitted before it existed.
//
// A timeout is INCONCLUSIVE, not a failure: the deploy may still be running, so nothing is withdrawn.
//
// It never reads credential contents. The public key is a public key; it is printed by path only.

import { createHash } from 'node:crypto'
import { appendFileSync, closeSync, existsSync, fsyncSync, linkSync, lstatSync, openSync, readdirSync, readFileSync, unlinkSync, writeFileSync, writeSync } from 'node:fs'
import { join } from 'node:path'
import { parsePrincipal, principalComment, principalLine } from './participant_unit.mjs'
import { codexComment, codexManifestRefusal, codexPrincipalPlan, distinctKeys } from './principal_family.mjs'
import { NUMERIC_FIELDS, parseBlockRecord, recordedClashes } from './identity_allocation.mjs'

const KEY_LINE = /^(ssh-ed25519|ecdsa-sha2-nistp256)\s+([A-Za-z0-9+/]+={0,2})(?:\s+\S.*)?$/

export const digestOf = bytes => createHash('sha256').update(bytes).digest('hex')

// The channel key's public half, as the doctor reads it: one line, a supported type, no options.
export function readPublicKey(text) {
  const line = String(text || '').trim()
  if (/PRIVATE KEY|nsec1|bunker:/i.test(line)) throw new Error('that is private key material; give the .pub file')
  if (line.includes('\n')) throw new Error('the public key file must hold one line')
  const m = KEY_LINE.exec(line)
  if (!m) throw new Error('unsupported or malformed OpenSSH public key (ssh-ed25519 or ecdsa-sha2-nistp256, no options)')
  return { keyType: m[1], keyBody: m[2] }
}

// What to do to authorized_keys. Matched on our comment, as instance-unit verify matches, so a line
// whose command has drifted is found and refused rather than duplicated.
export function principalPlan(text, manifest, { keyType, keyBody }) {
  const want = principalLine(manifest, keyType, keyBody)
  const comment = principalComment(manifest)
  const ours = String(text || '').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    .filter(l => { const p = parsePrincipal(l); return p ? p.comment === comment : l.includes(comment) })
  if (!ours.length) return { action: 'append', line: want }
  if (ours.length === 1 && ours[0] === want) return { action: 'present', line: want }
  // An older seat: the same line without the fingerprint argument. It is left exactly as it is; its
  // sessions cannot be attributed to a key, so presence reports it unproven until a controlled migration.
  if (ours.length === 1 && ours[0] === want.replace(/ --key-fp SHA256:[A-Za-z0-9+/]{43}"/, '"')) {
    return { action: 'present', line: ours[0], unproven: true }
  }
  return { action: 'refuse', line: want,
    why: `${ours.length} line(s) already carry ${comment} and ${ours.length > 1 ? 'which one authorises is ambiguous' : 'it is not the line this key and manifest produce'}; resolve by hand` }
}

// The runner names a failed tick by `<release sha> <sha256 of json.dumps(digests, sort_keys=True)>`,
// where digests maps each manifest's stem to the sha256 of its bytes. Recomputing it for the estate
// as installed ties a failure to a tick that saw this manifest, not to one that began before it.
export function estateHash(root) {
  // sort_keys orders by stem, which is not filename order ('a-b.json' sorts before 'a.json').
  const digests = readdirSync(root).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)).sort()
    .map(k => [k, digestOf(readFileSync(join(root, `${k}.json`)))])
  return digestOf(`{${digests.map(([k, v]) => `${JSON.stringify(k)}: ${JSON.stringify(v)}`).join(', ')}}`)
}

// What the family needs, decided before anything changes. Returns { plans } or { error }.
export function planPrincipals(text, manifest, { family = 'claude', publicKey, feedKey = null }) {
  const codex = family === 'codex'
  if (codex) {
    const bad = codexManifestRefusal(manifest)
    if (bad) return { error: bad }
    if (!feedKey) return { error: 'a Pi or Codex agent needs two keys and the bind carries no feed key' }
    if (!distinctKeys(publicKey, feedKey)) return { error: 'the channel key and the feed key are the same key; each forced command admits exactly one' }
  }
  const plans = codex
    ? [codexPrincipalPlan(text, manifest, 'channel', publicKey), codexPrincipalPlan(text, manifest, 'feed', feedKey)]
    : [{ role: 'channel', ...principalPlan(text, manifest, publicKey) }]
  const refused = plans.find(plan => plan.action === 'refuse')
  return refused ? { error: refused.why, plans } : { plans }
}
export const principalCommentOf = (manifest, family, role) => family === 'codex' ? codexComment(manifest, role) : principalComment(manifest)

// Seat the planned principals, then check them as the operator would. Shared by a fresh apply and by the repair of an
// install that stopped after the manifest went in. `done(state, ok, detail)` reports each state as it is observed.
export function seatPrincipals({ manifest, keysPath, publicKey, feedKey = null, family = 'claude', run, done, when = 'the deploy' }) {
  const codex = family === 'codex'
  const id = manifest.id
  const again = planPrincipals(readFileSync(keysPath, 'utf8'), manifest, { family, publicKey, feedKey })
  if (again.error) return done('principal seated', false, `${keysPath} changed during ${when}: ${again.error}`)
  const seated = []
  try {
    for (const plan of again.plans) {
      if (plan.action === 'append') {
        const text = readFileSync(keysPath, 'utf8')
        appendFileSync(keysPath, `${text && !text.endsWith('\n') ? '\n' : ''}${plan.line}\n`)
      } else if (plan.action === 'upgrade') {
        // Replace exactly the one older line for this key (planned from this same read) with the line that
        // names its fingerprint. Nothing else in the file moves.
        const text = readFileSync(keysPath, 'utf8'), lines = text.split('\n')
        const at = lines.map(l => l.trim()).indexOf(plan.old)
        if (at < 0 || lines.map(l => l.trim()).lastIndexOf(plan.old) !== at) throw new Error('the older channel line changed while upgrading it')
        lines[at] = plan.line
        writeFileSync(keysPath, lines.join('\n'))
      }
      seated.push(`${plan.role} ${plan.action === 'append' ? 'appended' : plan.action === 'upgrade' ? 'upgraded to name its key fingerprint' : 'already present'}`)
    }
  } catch (error) {
    // Partial seat: say which lines are in. A re-run plans again, finds them present and appends only the rest.
    return done('principal seated', false, `${seated.join(', ') || 'nothing seated'}; stopped at ${error.message}; run again to seat the rest`)
  }
  done('principal seated', true, codex ? seated.join(', ') : again.plans[0].action === 'present' ? 'already present' : `appended to ${keysPath}`)

  // 6 and 7. The operator's own checks, run as the operator would.
  const verify = run(['verify', '--instance', id, '--authorized-keys', keysPath, ...(codex ? ['--family', 'codex'] : [])])
  if (verify.status !== 0) return done('principal verified', false, (verify.stderr || verify.stdout).trim().split('\n').slice(-3).join(' | '))
  done('principal verified', true, 'instance-unit verify passed')
  // A Pi or Codex agent baselines through its feed: the first start with no cursor begins from now
  // (codex-channel-feed.mjs), so there is no admitted backlog to mark read and no tool to run.
  if (codex) return done('baselined', true, 'not run: the wake feed baselines on its first start (codex-channel-feed.mjs)')
  const baseline = run(['baseline'])
  return done('baselined', baseline.status === 0, (baseline.status === 0 ? baseline.stdout : baseline.stderr || baseline.stdout).trim().split('\n').slice(-1)[0] || `exit ${baseline.status}`)
}

// An install that stopped after the manifest went in (a failed append, a failed verify) is repaired here, not
// re-applied: the identity checks, the block record and the install already ran and are not weakened or repeated.
// The manifest must be the one in the instance root, and the runner must have recorded exactly its bytes.
export function repairInstalled({ manifest, root, stateDir, keysPath, publicKey, feedKey = null, family = 'claude', run, log = () => {} }) {
  const states = []
  const done = (state, ok, detail) => { states.push({ state, ok, detail }); log(state, ok, detail); return { ok, states } }
  const target = join(root, `${manifest.id}.json`), compose = join(root, `${manifest.id}.compose.yml`)
  let keysStat
  try { keysStat = lstatSync(keysPath) } catch { return done('principal planned', false, `${keysPath} does not exist; create the channel account first`) }
  if (!keysStat.isFile() || keysStat.isSymbolicLink()) return done('principal planned', false, `${keysPath} must be a regular file, not a link`)
  const plan = planPrincipals(readFileSync(keysPath, 'utf8'), manifest, { family, publicKey, feedKey })
  if (plan.error) return done('principal planned', false, plan.error)
  done('principal planned', true, plan.plans.every(p => p.action === 'present') ? 'already present, unchanged'
    : `will ${plan.plans.filter(p => p.action !== 'present').map(p => `${p.action === 'upgrade' ? 'upgrade' : 'append'} ${principalCommentOf(manifest, family, p.role)}`).join(' and ')}`)
  const deployed = readJson(join(stateDir, 'DEPLOYED_MANIFESTS.json'))
  if (!existsSync(target) || deployed?.[manifest.id] !== digestOf(readFileSync(target)) || !existsSync(compose))
    return { ...done('deployed', null, 'the runner has not recorded the installed manifest and its compose file yet; nothing was seated'), inconclusive: true }
  done('deployed', true, `the runner recorded the installed manifest and wrote ${compose}`)
  const result = seatPrincipals({ manifest, keysPath, publicKey, feedKey, family, run, done, when: 'the repair' })
  return { ok: states.every(st => st.ok), states }
}

// Read the runner's record for one install. `deployed` is DEPLOYED_MANIFESTS.json, `failed` is
// FAILED_ATTEMPT.json ({ attempt, at } with `at` in seconds), `installedAt` is in seconds.
export function deployVerdict({ id, digest, deployed, failed, composeExists, installedAt, estate }) {
  if (deployed?.[id] === digest && composeExists) return 'deployed'
  if (failed && Number(failed.at) >= installedAt && String(failed.attempt || '').endsWith(` ${estate}`)) return 'failed'
  return 'waiting'
}

const readJson = path => { try { return JSON.parse(readFileSync(path, 'utf8')) } catch { return null } }

// Read the record, refuse a clash, append and fsync: one step, under an exclusive lock beside the
// record, so two applies cannot both read it clear and both take the same block. The lock is
// created O_EXCL and never waited on: a held lock refuses, and the operator re-runs.
export function reserveBlock(ledgerPath, manifest, now = () => Date.now()) {
  if (!ledgerPath) return { ok: false, detail: 'no block record path was given' }
  const lock = `${ledgerPath}.lock`
  let lockFd
  try { lockFd = openSync(lock, 'wx', 0o644); writeSync(lockFd, `${process.pid}\n`) } catch (e) {
    if (lockFd !== undefined) { closeSync(lockFd); unlinkSync(lock) }
    return { ok: false, detail: e.code === 'EEXIST'
      ? `${lock} is held: another apply is reserving a block. Re-run when it finishes; if none is running, an apply died holding it, so check the record, then remove the lock`
      : `${lock}: ${e.message}` }
  }
  try {
    let record
    try { record = existsSync(ledgerPath) ? parseBlockRecord(readFileSync(ledgerPath, 'utf8')) : [] }
    catch (e) { return { ok: false, detail: `${ledgerPath}: ${e.message}` } }
    const clashes = recordedClashes(record, manifest)
    if (clashes.length) return { ok: false, detail: `the block overlaps ${[...new Set(clashes.map(e => e.id))].join(', ')} in ${ledgerPath}, numbers once installed` }
    if (record.some(e => e.id === manifest.id && NUMERIC_FIELDS.every(f => e[f] === manifest[f]))) return { ok: true, detail: `already in ${ledgerPath} for ${manifest.id}` }
    const block = Object.fromEntries(NUMERIC_FIELDS.map(f => [f, manifest[f]]))
    let fd
    try {
      fd = openSync(ledgerPath, 'a', 0o644)
      writeSync(fd, JSON.stringify({ id: manifest.id, ...block, recorded_at: Math.floor(now() / 1000) }) + '\n')
      fsyncSync(fd)
    } catch (e) { return { ok: false, detail: `${ledgerPath}: ${e.message}` } }
    finally { if (fd !== undefined) closeSync(fd) }
    return { ok: true, detail: `appended to ${ledgerPath}` }
  } finally { closeSync(lockFd); unlinkSync(lock) }
}

// `run(argv)` returns { status, stdout, stderr }. `sleep` and `now` (ms) are injected for the suite.
export async function applyStaged({ manifest, stagedPath, root, stateDir, keysPath, publicKey, family = 'claude', feedKey = null, run, ledgerPath, waitMs = 600000, pollMs = 5000,
  sleep = ms => new Promise(r => setTimeout(r, ms)), now = () => Date.now(), log = () => {} }) {
  const states = []
  const done = (state, ok, detail) => { states.push({ state, ok, detail }); log(state, ok, detail); return { ok, states } }
  const id = manifest.id

  // 1. Decide the principal before touching anything.
  let keysStat
  try { keysStat = lstatSync(keysPath) } catch { return done('principal planned', false, `${keysPath} does not exist; create the channel account first`) }
  if (!keysStat.isFile() || keysStat.isSymbolicLink()) return done('principal planned', false, `${keysPath} must be a regular file, not a link`)
  // The plan covers every key the family needs, and is decided whole: one refused line refuses the apply
  // before anything changes, so a two-key agent is never half-seated by a plan it could have rejected.
  const codex = family === 'codex'
  const plan = planPrincipals(readFileSync(keysPath, 'utf8'), manifest, { family, publicKey, feedKey })
  if (plan.error) return done('principal planned', false, plan.error)
  done('principal planned', true, plan.plans.every(p => p.action === 'present') ? 'already present, unchanged'
    : `will ${plan.plans.filter(p => p.action !== 'present').map(p => `${p.action === 'upgrade' ? 'upgrade' : 'append'} ${principalCommentOf(manifest, family, p.role)}`).join(' and ')}`)

  // 2. Reserve the block in the record, as the record is now, before anything can run as it.
  const reserved = reserveBlock(ledgerPath, manifest, now)
  if (!reserved.ok) return done('block recorded', false, `${reserved.detail}; nothing was installed`)
  done('block recorded', true, reserved.detail)

  // 3. Install: write beside the target (same filesystem), then a no-clobber link. A name not ending
  //    in .json is invisible to the runner's glob.
  const bytes = readFileSync(stagedPath)
  const digest = digestOf(bytes)
  const target = join(root, `${id}.json`)
  const temp = join(root, `.${id}.json.apply-${process.pid}`)
  writeFileSync(temp, bytes, { mode: 0o644, flag: 'wx' })
  const installedAt = now() / 1000
  try { linkSync(temp, target) } catch (e) {
    unlinkSync(temp)
    return done('installed', false, `${e.code === 'EEXIST' ? `${target} appeared since the check; nothing was installed` : e.message}. The block stays recorded as a reservation`)
  }
  unlinkSync(temp)
  done('installed', true, `${target} (sha256 ${digest.slice(0, 12)}…)`)
  const estate = estateHash(root)

  // 4. Wait for the runner to record exactly this manifest.
  const compose = join(root, `${id}.compose.yml`)
  let verdict = 'waiting'
  for (const start = now(); now() - start < waitMs;) {
    verdict = deployVerdict({ id, digest, deployed: readJson(join(stateDir, 'DEPLOYED_MANIFESTS.json')),
      failed: readJson(join(stateDir, 'FAILED_ATTEMPT.json')), composeExists: existsSync(compose), installedAt, estate })
    if (verdict !== 'waiting') break
    await sleep(pollMs)
  }
  if (verdict === 'waiting') return { ...done('deployed', null, `no runner record within ${Math.round(waitMs / 1000)} s; the deploy may still be running, so the manifest stays. Read journalctl -u nvoy-runtime-deploy`), inconclusive: true }
  if (verdict === 'failed') {
    const ours = existsSync(target) && digestOf(readFileSync(target)) === digest
    if (ours) unlinkSync(target)
    return done('deployed', false, `the runner's tick failed and rolled the estate back. ${ours ? 'The manifest was withdrawn so the rollback does not repeat.' : 'The manifest had changed since the install and was left in place.'} Read journalctl -u nvoy-runtime-deploy`)
  }
  done('deployed', true, `the runner recorded this manifest and wrote ${compose}`)

  // 5-7. Seat the principals, re-planned against the file as it is now, then verify and baseline.
  seatPrincipals({ manifest, keysPath, publicKey, feedKey, family, run, done })
  return { ok: states.every(st => st.ok), states }
}
