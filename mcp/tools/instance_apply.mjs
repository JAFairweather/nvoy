// instance_apply.mjs — install a checked, staged identity and seat its channel principal (#273).
//
// The order is the point, and each state is reported on its own:
//
//   1. principal planned   the authorized_keys line is decided BEFORE anything changes, so a file
//                          already holding a different line under this identity's comment refuses
//                          the whole apply rather than half of it.
//   2. block recorded      the record is read again here, immediately before the install; a block it
//                          already holds for another identity refuses. The UID/GID block is then
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

// Read the runner's record for one install. `deployed` is DEPLOYED_MANIFESTS.json, `failed` is
// FAILED_ATTEMPT.json ({ attempt, at } with `at` in seconds), `installedAt` is in seconds.
export function deployVerdict({ id, digest, deployed, failed, composeExists, installedAt, estate }) {
  if (deployed?.[id] === digest && composeExists) return 'deployed'
  if (failed && Number(failed.at) >= installedAt && String(failed.attempt || '').endsWith(` ${estate}`)) return 'failed'
  return 'waiting'
}

const readJson = path => { try { return JSON.parse(readFileSync(path, 'utf8')) } catch { return null } }

// `run(argv)` returns { status, stdout, stderr }. `sleep` and `now` (ms) are injected for the suite.
export async function applyStaged({ manifest, stagedPath, root, stateDir, keysPath, publicKey, run, ledgerPath, waitMs = 600000, pollMs = 5000,
  sleep = ms => new Promise(r => setTimeout(r, ms)), now = () => Date.now(), log = () => {} }) {
  const states = []
  const done = (state, ok, detail) => { states.push({ state, ok, detail }); log(state, ok, detail); return { ok, states } }
  const id = manifest.id

  // 1. Decide the principal before touching anything.
  let keysStat
  try { keysStat = lstatSync(keysPath) } catch { return done('principal planned', false, `${keysPath} does not exist; create the channel account first`) }
  if (!keysStat.isFile() || keysStat.isSymbolicLink()) return done('principal planned', false, `${keysPath} must be a regular file, not a link`)
  const plan = principalPlan(readFileSync(keysPath, 'utf8'), manifest, publicKey)
  if (plan.action === 'refuse') return done('principal planned', false, plan.why)
  done('principal planned', true, plan.action === 'present' ? 'already present, unchanged' : `will append ${principalComment(manifest)}`)

  // 2. Reserve the block in the record, as the record is now, before anything can run as it.
  if (!ledgerPath) return done('block recorded', false, 'no block record path was given; nothing was installed')
  let record
  try { record = existsSync(ledgerPath) ? parseBlockRecord(readFileSync(ledgerPath, 'utf8')) : [] }
  catch (e) { return done('block recorded', false, `${ledgerPath}: ${e.message}; nothing was installed`) }
  const clashes = recordedClashes(record, manifest)
  if (clashes.length) return done('block recorded', false, `the block overlaps ${[...new Set(clashes.map(e => e.id))].join(', ')} in ${ledgerPath}, numbers once installed; nothing was installed`)
  const already = record.some(e => e.id === id && NUMERIC_FIELDS.every(f => e[f] === manifest[f]))
  if (!already) {
    const block = Object.fromEntries(NUMERIC_FIELDS.map(f => [f, manifest[f]]))
    let fd
    try {
      fd = openSync(ledgerPath, 'a', 0o644)
      writeSync(fd, JSON.stringify({ id, ...block, recorded_at: Math.floor(now() / 1000) }) + '\n')
      fsyncSync(fd)
    } catch (e) { return done('block recorded', false, `${ledgerPath}: ${e.message}; nothing was installed`) }
    finally { if (fd !== undefined) closeSync(fd) }
  }
  done('block recorded', true, already ? `already in ${ledgerPath} for ${id}` : `appended to ${ledgerPath}`)

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

  // 5. Seat the principal, re-planned against the file as it is now.
  const again = principalPlan(readFileSync(keysPath, 'utf8'), manifest, publicKey)
  if (again.action === 'refuse') return done('principal seated', false, `${keysPath} changed during the deploy: ${again.why}`)
  if (again.action === 'append') {
    const text = readFileSync(keysPath, 'utf8')
    appendFileSync(keysPath, `${text && !text.endsWith('\n') ? '\n' : ''}${again.line}\n`)
  }
  done('principal seated', true, again.action === 'present' ? 'already present' : `appended to ${keysPath}`)

  // 6 and 7. The operator's own checks, run as the operator would.
  const verify = run(['verify', '--instance', id, '--authorized-keys', keysPath])
  if (verify.status !== 0) return done('principal verified', false, (verify.stderr || verify.stdout).trim().split('\n').slice(-3).join(' | '))
  done('principal verified', true, 'instance-unit verify passed')
  const baseline = run(['baseline'])
  done('baselined', baseline.status === 0, (baseline.status === 0 ? baseline.stdout : baseline.stderr || baseline.stdout).trim().split('\n').slice(-1)[0] || `exit ${baseline.status}`)
  return { ok: states.every(st => st.ok), states }
}
