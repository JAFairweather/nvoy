// identity-allocation.mjs — the cross-identity UID/GID check (#165) and the allocator (#166).
//
// Drives the REAL policy module. What this suite is for:
//
//   - the collision check actually catches the thing `assertNoCollisions` misses, and does NOT
//     fire on a legitimately disjoint second identity;
//   - uids and gids are separate namespaces — a uid 42011 beside a gid 42011 is not a collision,
//     and reporting it as one would train an operator to ignore the tool;
//   - the allocator refuses rather than guesses: it will not allocate onto an inconsistent estate,
//     and it will not recycle a retired identity's numbers;
//   - nothing it emits can carry a credential, and nothing it emits lands in the live instance root.
//
// Every refusal is paired with a case that must still get through.
//
//   node test/identity-allocation.mjs

import { auditIdentityBlocks, allocateIdentityBlock, buildParticipantManifest, seatingPlan,
  occupiedNumbers, UID_ROLES, GID_ROLES, UID_BASE, GID_BASE } from '../mcp/tools/identity_allocation.mjs'

let pass = true
const check = (cond, label) => { console.log(`${cond ? 'ok  ' : 'FAIL'} — ${label}`); if (!cond) pass = false }
const refuses = (fn, label, want) => {
  try { fn(); check(false, `${label} (no refusal)`) } catch (e) {
    const named = e.message.startsWith('identity-allocation: ') && e.message.includes(want)
    check(named, named ? label : `${label} — wrong error: ${e.message}`)
  }
}

const block = (u, g) => ({ watcherUid: u, brokerUid: u + 1, adapterUid: u + 2, workerUid: u + 3,
  brokerAdapterGid: g, workerHandoffGid: g + 1 })
const identity = (id, u, g) => ({ id, pubkey: 'a'.repeat(64), ...block(u, g) })

// The live estate as it stands today: one participant.
const codex = identity('codex-jaf', 41011, 42011)
const HEX = 'c'.repeat(64)

// ---- the audit catches what assertNoCollisions does not -----------------------------------------
const clean = auditIdentityBlocks([codex, identity('claude-jaf', 41021, 42021)])
check(clean.ok && clean.collisions.length === 0, 'two identities on disjoint blocks audit clean')
check(clean.identities === 2, 'and the audit reports how many it actually looked at')

const shared = auditIdentityBlocks([codex, identity('claude-jaf', 41011, 42021)])
check(!shared.ok, 'two identities sharing a uid FAIL the audit — the #165 gap')
const c = shared.collisions[0]
check(c.kind === 'uid' && c.value === 41011, 'the collision names the exact number')
check(c.held_by === 'codex-jaf' && c.wanted_by === 'claude-jaf',
  'and names BOTH identities — the operator\'s next question is always which one to move')
check(c.held_field === 'watcherUid' && c.wanted_field === 'watcherUid', 'and which field on each')

// A partial overlap: only the broker uid collides. Easy to miss by eye, which is the point.
const partial = auditIdentityBlocks([codex, identity('claude-jaf', 41012, 42021)])
check(!partial.ok && partial.collisions.length >= 1, 'a PARTIAL block overlap is caught, not just an identical block')

// ---- uids and gids are separate namespaces -------------------------------------------------------
// A gid numerically equal to another identity's uid is not a collision. Reporting it as one would
// make the tool cry wolf, and an alarm that always fires is one nobody reads.
const crossNamespace = auditIdentityBlocks([
  { id: 'a', watcherUid: 41011, brokerUid: 41012, adapterUid: 41013, workerUid: 41014, brokerAdapterGid: 50001, workerHandoffGid: 50002 },
  { id: 'b', watcherUid: 41021, brokerUid: 41022, adapterUid: 41023, workerUid: 41024, brokerAdapterGid: 41011, workerHandoffGid: 41012 },
])
check(crossNamespace.ok, 'a gid equal to another identity\'s uid is NOT reported as a collision')
// PAIR: two identities sharing a GID *is* caught, so the gid half is not simply unchecked.
const gidClash = auditIdentityBlocks([codex, identity('claude-jaf', 41021, 42011)])
check(!gidClash.ok && gidClash.collisions.some(x => x.kind === 'gid'), 'PAIR: a shared GID IS caught')

// ---- an identity does not collide with itself ----------------------------------------------------
check(auditIdentityBlocks([codex]).ok, 'a single identity never collides with itself')
check(auditIdentityBlocks([]).ok && auditIdentityBlocks([]).identities === 0, 'an empty estate audits clean')

// ---- allocation --------------------------------------------------------------------------------
const first = allocateIdentityBlock([], { id: 'codex-jaf' })
check(first.block.watcherUid === UID_BASE && first.block.brokerAdapterGid === GID_BASE,
  'the first identity on an empty host gets the base block')

const second = allocateIdentityBlock([codex], { id: 'claude-jaf' })
check(second.block.watcherUid === 41021, 'the second identity gets the next stride, not the next integer')
check(second.block.brokerAdapterGid === 42021, 'and the matching gid stride')
check(auditIdentityBlocks([codex, { id: 'claude-jaf', ...second.block }]).ok,
  'the allocated block audits clean against the estate it was allocated from — the property that matters')

const third = allocateIdentityBlock([codex, { id: 'claude-jaf', ...second.block }], { id: 'oliver' })
check(third.block.watcherUid === 41031, 'a third identity gets the third stride')
check(auditIdentityBlocks([codex, { id: 'claude-jaf', ...second.block }, { id: 'oliver', ...third.block }]).ok,
  'and three identities together still audit clean')
check(third.neighbours.join() === 'claude-jaf,codex-jaf', 'the allocation records who it allocated around')

// ---- it refuses rather than guesses ---------------------------------------------------------------
refuses(() => allocateIdentityBlock([codex, identity('claude-jaf', 41011, 42021)], { id: 'oliver' }),
  'REFUSES to allocate onto an estate that already has a collision', 'existing collision')
// PAIR: fix that estate and the same call succeeds — so the refusal is about the fault, not about
// there being three identities.
check(allocateIdentityBlock([codex, identity('claude-jaf', 41021, 42021)], { id: 'oliver' }).block.watcherUid === 41031,
  'PAIR: resolve the collision and the same allocation proceeds')

refuses(() => allocateIdentityBlock([codex], { id: 'codex-jaf' }), 'refuses a name already in use', 'already exists')
refuses(() => allocateIdentityBlock([], { id: 'Not A Valid Id!' }), 'refuses a malformed instance id', 'usable instance id')
refuses(() => allocateIdentityBlock([], {}), 'refuses an allocation with no id', 'usable instance id')
check(allocateIdentityBlock([], { id: 'oliver' }).id === 'oliver', 'PAIR: a well-formed id allocates')

// ---- a retired identity's numbers are NOT recycled -------------------------------------------------
// uids outlive the manifests that named them — files on a volume, entries in a log. Handing a
// retired identity's numbers to a new one makes the old artefacts read as the new agent's.
const afterRetirement = allocateIdentityBlock([{ id: 'oliver', ...third.block }], { id: 'fresh' })
check(afterRetirement.block.watcherUid === UID_BASE,
  'a gap left by a retired identity is filled only when it is the LOWEST free stride')
const gapped = allocateIdentityBlock([codex, { id: 'oliver', ...third.block }], { id: 'fresh' })
check(gapped.block.watcherUid === 41021 && !occupiedNumbers([codex, { id: 'oliver', ...third.block }]).uids.has(41021),
  'allocation lands on a stride boundary, never mid-decade')

// ---- the manifest it builds ------------------------------------------------------------------------
const manifest = buildParticipantManifest(second, { pubkey: HEX, grantors: [HEX], relays: ['wss://relay.example'] })
check(manifest.broker_mode === 'local' && manifest.delivery_mode === 'notify_only' && manifest.worker_enabled === false,
  'the three jointly-required Claude-channel fields are set together')
check(manifest.watcher_uid === 41021 && manifest.broker_adapter_gid === 42021,
  'the allocated block is written in snake_case, as the on-disk manifest expects')
check(manifest.state_dir === '/var/lib/nvoy/claude-jaf' && manifest.spool_dir === '/var/lib/nvoy-watcher/claude-jaf',
  'the three roots are keyed on the instance id')

// The property that matters most: nothing it emits can carry a credential.
const asText = JSON.stringify(manifest)
check(/bunker_uri_ref|bunker_client_ref/.test(asText), 'credentials are REFERENCED by path')
check(!/nsec|bunker:\/\/|BEGIN |[0-9a-f]{64}=/.test(asText.replace(new RegExp(HEX, 'g'), '<pubkey>')),
  'and no credential value, URI or key material appears anywhere in the manifest')
check(manifest.bunker_uri_ref.startsWith('/etc/nvoy/credentials/'), 'the credential paths are absolute')

refuses(() => buildParticipantManifest(second, { pubkey: 'nope', grantors: [HEX], relays: ['wss://r'] }),
  'refuses a pubkey that is not 64-hex', '64-hex')
refuses(() => buildParticipantManifest(second, { pubkey: HEX, grantors: [], relays: ['wss://r'] }),
  'refuses an identity with no grantor', 'grantor')
refuses(() => buildParticipantManifest(second, { pubkey: HEX, grantors: [HEX], relays: ['ws://insecure'] }),
  'refuses a non-wss relay', 'wss://')
refuses(() => buildParticipantManifest(null, { pubkey: HEX, grantors: [HEX], relays: ['wss://r'] }),
  'refuses to build without a valid allocation', 'valid allocation')

// ---- the seating plan ------------------------------------------------------------------------------
const plan = seatingPlan(manifest)
check(plan.length === 7 && plan.every((s, i) => s.step === i + 1), 'the plan is ordered and complete')
const credentialStep = plan.findIndex(s => /Seat .*bunker/i.test(s.what))
const installStep = plan.findIndex(s => /Install the staged manifest/i.test(s.what))
check(credentialStep < installStep,
  'CREDENTIALS ARE SEATED BEFORE THE MANIFEST LANDS — the ordering that makes the deploy tick safe')
check(/STARTS THE DEPLOY/i.test(plan[installStep].why) && /rolled back/i.test(plan[installStep].why),
  'and the install step says plainly that it starts a deploy and can roll back healthy identities')
check(/root:root 0600/.test(plan[credentialStep].why) && /does not exist yet/.test(plan[credentialStep].why),
  'the credential step carries the reason the old chown ordering failed')
check(plan.some(s => /MORE than five minutes/i.test(s.what)), 'the plan ends with the delayed-reply proof')
check(plan.some(s => /read back by id from a fresh connection/i.test(s.what)), 'and requires a cold read-back')
check(plan.filter(s => s.automatable === false).length >= 4,
  'the plan is honest about how much still needs a human')

console.log(`\n${pass ? 'ALL PASS' : 'FAILURES ABOVE'}`)
process.exit(pass ? 0 : 1)
