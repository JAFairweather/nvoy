#!/usr/bin/env node
// instance-identity.mjs — audit the identity blocks in use, and allocate one for a new participant.
//
//   instance-identity.mjs audit [--instance-root <dir>]
//   instance-identity.mjs allocate --id <name> --pubkey <npub|hex> --grantor <npub|hex> \
//                                  [--relay wss://…]… [--out <dir>] [--instance-root <dir>]
//
// All policy lives in `identity_allocation.mjs`, which is pure and carries its own suite. This file
// reads manifests and prints; it decides nothing.
//
// `allocate` writes the manifest to a STAGING directory and never to the live instance root. That is
// the safety property, not a convenience: `runtime-deploy-runner.py` globs the instance root every
// tick and starts whatever it finds, so installing a manifest IS the deploy trigger. A manifest that
// lands before its credentials exist fails to start — and a failed start rolls back every identity
// touched in that tick, including healthy ones. The operator installs it, after the credentials.
//
// It never reads, writes, prints or transmits credential material. It emits credential PATHS.
//
// Exit: 0 clean · 1 a real fault (collision, refusal) · 3 INCONCLUSIVE — a manifest it could not read.

import { readdirSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { readManifest } from './runtime_manifest.mjs'
import { auditIdentityBlocks, allocateIdentityBlock, buildParticipantManifest, seatingPlan,
  NUMERIC_FIELDS } from './identity_allocation.mjs'

const argv = process.argv.slice(2)
const verb = argv[0]
const flag = n => { const i = argv.indexOf(n); return i < 0 ? '' : argv[i + 1] || '' }
const all = n => argv.reduce((acc, a, i) => (a === n && argv[i + 1] ? [...acc, argv[i + 1]] : acc), [])
const die = m => { console.error(`instance-identity: ${m}`); process.exit(1) }
const root = resolve(flag('--instance-root') || process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances')

if (!['audit', 'allocate'].includes(verb)) {
  die('usage: audit | allocate --id <name> --pubkey <npub|hex> --grantor <npub|hex> [--relay wss://…]')
}

// ---- read the estate ----------------------------------------------------------------------------
// A manifest we cannot read is INCONCLUSIVE, never "not there". Treating an unreadable sibling as
// absent is how an allocator hands out a block that is already in use.
if (!existsSync(root)) die(`instance root ${root} does not exist — pass --instance-root`)
const manifests = [], unreadable = []
let names = []
try { names = readdirSync(root).filter(f => f.endsWith('.json')) } catch (e) { die(`cannot read ${root}: ${e.message}`) }
for (const name of names) {
  const id = name.slice(0, -5)
  try { manifests.push(readManifest(root, id)) } catch (e) { unreadable.push({ id, why: e.message }) }
}

console.log(`\ninstance root ${root} — ${manifests.length} readable identity(s)${unreadable.length ? `, ${unreadable.length} unreadable` : ''}\n`)
for (const m of manifests) {
  const u = [m.watcherUid, m.brokerUid, m.adapterUid, m.workerUid]
  console.log(`  ${String(m.id).padEnd(18)} uid ${Math.min(...u)}-${Math.max(...u)}   gid ${m.brokerAdapterGid},${m.workerHandoffGid}`)
}
for (const u of unreadable) console.log(`  ${u.id.padEnd(18)} UNREADABLE — ${u.why}`)

const audit = auditIdentityBlocks(manifests)
if (audit.collisions.length) {
  console.log('\nCOLLISIONS — two identities share a number, so they share a security domain:')
  for (const c of audit.collisions) {
    console.log(`  ${c.kind} ${c.value}: held by ${c.held_by} (${c.held_field}), also claimed by ${c.wanted_by} (${c.wanted_field})`)
  }
  console.log('\nNothing in runtime_manifest.mjs checks this (#165). Resolve before deploying either identity.')
} else {
  console.log(`\nno ${NUMERIC_FIELDS.length}-field collisions across ${manifests.length} identity(s)`)
}

if (verb === 'audit') {
  if (audit.collisions.length) process.exit(1)
  if (unreadable.length) {
    console.log('\nINCONCLUSIVE — a manifest could not be read, so this audit did not see the whole estate.')
    process.exit(3)
  }
  process.exit(0)
}

// ---- allocate ------------------------------------------------------------------------------------
if (unreadable.length) {
  console.error('\ninstance-identity: refusing to allocate without seeing every manifest — an unreadable sibling may already hold the block')
  process.exit(3)
}

const id = flag('--id')
const relays = all('--relay')
const grantors = all('--grantor')
let allocation, manifest
try {
  allocation = allocateIdentityBlock(manifests, { id })
  manifest = buildParticipantManifest(allocation, {
    pubkey: flag('--pubkey'),
    grantors: grantors.length ? grantors : manifests[0]?.grantors || [],
    relays: relays.length ? relays : manifests[0]?.relays || [],
  })
} catch (e) { die(e.message) }

const outDir = resolve(flag('--out') || join(process.env.HOME || '/tmp', '.nvoy', 'staged'))
if (resolve(outDir) === root) die('--out must not be the live instance root; installing the manifest is the deploy trigger')
mkdirSync(outDir, { recursive: true })
const staged = join(outDir, `${manifest.id}.json`)
writeFileSync(staged, JSON.stringify(manifest, null, 2) + '\n', { mode: 0o644 })

console.log(`\nallocated ${manifest.id}: uid ${allocation.uid_range.join('-')}  gid ${allocation.gid_range.join('-')}`)
console.log(`  allocated around: ${allocation.neighbours.join(', ') || '(first identity on this host)'}`)
console.log(`\nSTAGED (not installed): ${staged}`)
console.log('  It is NOT in the instance root. Placing it there starts a deploy within one tick.\n')

console.log('NEXT — in this order:\n')
for (const s of seatingPlan(manifest)) {
  console.log(`  ${s.step}. ${s.what}${s.automatable ? '' : '   [manual]'}`)
  console.log(`     ${s.why}\n`)
}
process.exit(0)
