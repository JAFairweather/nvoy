#!/usr/bin/env node
// instance-unit.mjs — treat a participant identity as ONE deployable unit rather than a rendered
// stack plus a step someone has to remember.
//
// Before this, "deploy a participant" meant: render the Compose file from the manifest, then
// separately generate an SSH principal and hand-install it. Nothing tied the two together and
// nothing ever checked the installed principal against the manifest it came from, so the access
// surface could drift — or be missing entirely — and the only symptom was a channel that went
// quiet. A silent channel is the worst shape a fault can take here (#154).
//
//   render  — emit every artifact the unit consists of, from the one manifest
//   verify  — check what is actually installed against that manifest
//
// Exit codes follow the house convention: 0 verified, 1 a real mismatch, 3 INCONCLUSIVE — could
// not see enough to judge. Being unable to check is not the same as being fine.

import { spawnSync } from 'node:child_process'
import { lstatSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { principalLine, principalComment, forcedCommand, verifyPrincipal, parsePrincipal, volumeLifecycle } from './participant_unit.mjs'

const TOOL = 'instance-unit'
const die = m => { console.error(`${TOOL}: ${m}`); process.exit(1) }
const inconclusive = m => { console.error(`${TOOL}: INCONCLUSIVE — ${m}`); process.exit(3) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const has = n => process.argv.includes(n)

const verb = process.argv[2] || ''
if (!['render', 'verify', 'restart', 'destroy'].includes(verb)) {
  die('usage: instance-unit.mjs render  --instance <id> --image <ref> [--public-key-file <p>] [--out-dir <d>]\n' +
      '       instance-unit.mjs verify  --instance <id> --authorized-keys <path>\n' +
      '       instance-unit.mjs restart --instance <id> --compose-file <path> [--dry-run]\n' +
      '       instance-unit.mjs destroy --instance <id> --compose-file <path> --i-understand-this-destroys <id> [--dry-run]')
}
const id = flag('--instance')
if (!id) die('--instance is required')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }

const boundedFile = (path, label, max = 512 * 1024) => {
  let st
  try { st = lstatSync(path) } catch { return { missing: true } }
  if (!st.isFile() || st.isSymbolicLink()) inconclusive(`${label} must be a regular non-symlink file`)
  if (st.size > max) inconclusive(`${label} is larger than ${max} bytes`)
  return { text: readFileSync(path, 'utf8') }
}

if (verb === 'render') {
  const image = flag('--image')
  if (!image) die('--image is required to render the unit')
  // One renderer, not two. Shelling out to the existing tool keeps the Compose contract in exactly
  // one place; a second copy of that substitution table is the drift this unit exists to remove.
  const renderer = resolve(new URL('./render-instance-compose.mjs', import.meta.url).pathname)
  const args = [renderer, '--instance', manifest.id, '--image', image]
  if (flag('--worker-image')) args.push('--worker-image', flag('--worker-image'))
  const rendered = spawnSync(process.execPath, args, { encoding: 'utf8', env: process.env })
  if (rendered.status !== 0) die(`compose render failed: ${(rendered.stderr || rendered.stdout || '').trim()}`)

  let principal = ''
  const keyFile = flag('--public-key-file')
  if (keyFile) {
    const key = boundedFile(keyFile, 'public key file', 16 * 1024)
    if (key.missing) die('public key file is missing')
    const fields = key.text.trim().split(/\s+/)
    if (!/^(ssh-ed25519|ecdsa-sha2-nistp256)$/.test(fields[0] || '') || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1] || '')) {
      die('unsupported or malformed OpenSSH public key')
    }
    if (manifest.brokerMode !== 'local' || manifest.deliveryMode !== 'notify_only' || manifest.workerEnabled) {
      die('a channel principal requires a local-broker, worker-disabled notify_only instance')
    }
    principal = principalLine(manifest, fields[0], fields[1])
  }

  const outDir = flag('--out-dir')
  if (!outDir) {
    process.stdout.write(rendered.stdout)
    if (principal) process.stdout.write(`\n# --- channel principal (install into the channel account's authorized_keys) ---\n${principal}\n`)
    if (!principal) console.error(`${TOOL}: no --public-key-file given, so the unit's access surface was NOT rendered`)
    process.exit(0)
  }
  const composePath = join(resolve(outDir), `${manifest.id}.compose.yml`)
  writeFileSync(composePath, rendered.stdout, { mode: 0o644 })
  const written = [composePath]
  if (principal) {
    const principalPath = join(resolve(outDir), `${manifest.id}.authorized_key`)
    writeFileSync(principalPath, `${principal}\n`, { mode: 0o600 })
    written.push(principalPath)
  }
  console.log(`${TOOL}: rendered ${written.length} artifact(s) for ${manifest.id}`)
  for (const p of written) console.log(`  ${p}`)
  console.log(`  adapter container: ${manifest.adapterContainer}`)
  if (!principal) console.error(`${TOOL}: no --public-key-file given, so the unit's access surface was NOT rendered`)
  process.exit(0)
}

if (verb === 'restart' || verb === 'destroy') {
  // Two named verbs instead of one flag. `docker compose down` and `docker compose down -v` differ
  // by one character and by whether the identity survives, so the difference is put in the verb
  // where it cannot be fat-fingered, and the cost is printed at the point of use rather than left
  // in a document someone is expected to have read (#155).
  const composeFile = flag('--compose-file')
  if (!composeFile) die(`--compose-file <path> is required to ${verb} the unit`)
  const compose = boundedFile(composeFile, 'compose file', 1024 * 1024)
  if (compose.missing) die(`compose file ${composeFile} does not exist`)
  const docker = process.env.NVOY_DOCKER || 'docker'
  const dryRun = has('--dry-run')
  const lifecycle = volumeLifecycle(manifest)

  if (verb === 'restart') {
    // Containers are cattle: recreate them and keep every volume. Nothing here may take `-v`.
    const args = ['compose', '-f', resolve(composeFile), 'up', '-d', '--force-recreate']
    console.log(`${TOOL}: restart ${manifest.id} — recreates containers, KEEPS all ${lifecycle.length} volumes`)
    for (const v of lifecycle) console.log(`  keep ${v.volume}`)
    console.log(`  ${docker} ${args.join(' ')}`)
    if (dryRun) process.exit(0)
    const result = spawnSync(docker, args, { stdio: 'inherit', env: process.env })
    process.exit(result.status === 0 ? 0 : 1)
  }

  // destroy — the irreversible one.
  console.error(`${TOOL}: destroy ${manifest.id} would DROP ${lifecycle.length} volume(s):`)
  for (const v of lifecycle) {
    console.error(`  ${v.volume}`)
    console.error(`    holds: ${v.holds}`)
    console.error(`    losing it: ${v.losing}`)
  }
  const unrecoverable = lifecycle.filter(v => !v.reRenderable)
  if (unrecoverable.length) {
    console.error(`${TOOL}: ${unrecoverable.length} of these CANNOT be re-rendered from the manifest:`)
    for (const v of unrecoverable) console.error(`  ${v.volume}`)
    console.error(`${TOOL}: this is destroying an identity, not restarting compute. Use \`restart\` to recreate containers.`)
  }
  // The token has to be the instance id, so an operator cannot confirm a destroy they were not
  // looking at — a bare --yes would confirm whichever unit the shell history happened to name.
  const token = flag('--i-understand-this-destroys')
  if (token !== manifest.id) {
    die(`refusing to destroy ${manifest.id}: pass --i-understand-this-destroys ${manifest.id}`)
  }
  const args = ['compose', '-f', resolve(composeFile), 'down', '-v']
  console.error(`  ${docker} ${args.join(' ')}`)
  if (dryRun) { console.error(`${TOOL}: --dry-run, nothing was destroyed`); process.exit(0) }
  const result = spawnSync(docker, args, { stdio: 'inherit', env: process.env })
  process.exit(result.status === 0 ? 0 : 1)
}

// verify
const keysPath = flag('--authorized-keys') || process.env.NVOY_AUTHORIZED_KEYS || ''
if (!keysPath) die('--authorized-keys <path> is required to verify the installed access surface')
const file = boundedFile(keysPath, 'authorized_keys')
if (file.missing) inconclusive(`authorized_keys ${keysPath} does not exist — cannot tell "never installed" from "cannot read"`)

const comment = principalComment(manifest)
// Match on our own comment rather than on the command, so a principal whose command has drifted is
// still FOUND and then reported as wrong. Matching on the command would make a drifted principal
// indistinguishable from an absent one.
const ours = file.text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
  .filter(l => { const p = parsePrincipal(l); return p ? p.comment === comment : l.includes(comment) })

if (!ours.length) {
  console.error(`${TOOL}: FAIL — no principal for ${manifest.id} is installed in ${keysPath}`)
  console.error(`  expected comment: ${comment}`)
  console.error(`  expected command: ${forcedCommand(manifest)}`)
  process.exit(1)
}
if (ours.length > 1) {
  console.error(`${TOOL}: FAIL — ${ours.length} principals carry the comment ${comment}; which one authorises is ambiguous`)
  process.exit(1)
}
const result = verifyPrincipal(manifest, ours[0])
if (!result) {
  console.error(`${TOOL}: FAIL — the installed line for ${manifest.id} is not a parseable forced-command principal`)
  process.exit(1)
}
for (const f of result.findings) console.log(`${f.ok ? 'ok  ' : 'FAIL'} — ${f.label}${f.detail ? `: ${f.detail}` : ''}`)
console.log(`${TOOL}: ${result.ok ? 'verified' : 'FAILED'} ${result.findings.filter(f => f.ok).length}/${result.findings.length} for ${manifest.id}`)
process.exit(result.ok ? 0 : 1)
