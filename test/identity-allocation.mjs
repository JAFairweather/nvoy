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

import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { auditIdentityBlocks, allocateIdentityBlock, buildParticipantManifest, seatingPlan,
  occupiedNumbers, policyFromTemplate, auditUniqueFields, credentialVerdict, TEMPLATE_FIELDS,
  UID_ROLES, GID_ROLES, UID_BASE, GID_BASE } from '../mcp/tools/identity_allocation.mjs'

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

// ---- a template: a new agent works like a named live one (waggle#613 M5, nvoy#273) ---------------
const CH = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const NEW = 'd'.repeat(64), OTHER = 'e'.repeat(64), CARRIER = 'f'.repeat(64)
const liveRaw = {
  version: 1, id: 'pi-dog', pubkey: 'b'.repeat(64), grantors: [HEX], relays: ['wss://relay.example'],
  buzz: { relay: 'wss://buzz.example', channels: [CH] },
  may_post: { channels: [CH], per_hour: 30, mention: [{ name: 'newbie', pubkey: NEW }, { name: 'other', pubkey: OTHER }] },
  agent_limits: { max_hops: 10, per_sender_per_hour: 30 }, agent_card: true,
  task_carriers: [{ pubkey: CARRIER, channels: [CH] }],
  wake_webhook: { url: 'https://hook.example/x', credential_ref: '/etc/nvoy/credentials/pi-dog.webhook' },
  may_set_profile: { kind: 0, pubkey: 'b'.repeat(64), grant_id: '1'.repeat(64) },
  bunker_uri_ref: '/etc/nvoy/credentials/pi-dog.bunker-uri',
}
const policy = policyFromTemplate(liveRaw, { pubkey: NEW })
check(JSON.stringify(Object.keys(policy).sort()) === JSON.stringify([...TEMPLATE_FIELDS].sort()),
  'a template copies exactly the policy blocks: buzz, may_post, agent_limits, agent_card, task_carriers')
check(!('wake_webhook' in policy) && !('may_set_profile' in policy) && !('bunker_uri_ref' in policy) && !('pubkey' in policy),
  'and nothing bound to the template agent: not its webhook, profile scope, credentials or key')
check(policy.may_post.mention.length === 1 && policy.may_post.mention[0].pubkey === OTHER,
  "the new agent's own key is dropped from the mention list it inherits")
policy.may_post.per_hour = 1
check(liveRaw.may_post.per_hour === 30, 'the copy is deep: editing it cannot change the live manifest it came from')
refuses(() => buildParticipantManifest(second, { pubkey: NEW, grantors: [HEX], relays: ['wss://r'], policy: { harness: {} } }),
  'a policy block outside the template fields is refused', 'harness')
{
  const m = buildParticipantManifest(second, { pubkey: NEW, grantors: [HEX], relays: ['wss://r'], policy: policyFromTemplate(liveRaw, { pubkey: NEW }) })
  check(m.watcher_uid === second.block.watcherUid && m.pubkey === NEW && m.state_dir.endsWith(second.id),
    'identity fields come from the allocation, never from the template')
}

// ---- the unique-field audit -------------------------------------------------------------------------
const named = (id, extra = {}) => ({ id, pubkey: id.padEnd(64, '0').slice(0, 64), stateDir: `/s/${id}`, runtimeDir: `/r/${id}`, spoolDir: `/p/${id}`, adapterContainer: `nvoy-${id}-adapter-1`, ...extra })
check(auditUniqueFields([named('a'), named('b')]).ok, 'two identities with their own key, directories and container audit clean')
{
  const r = auditUniqueFields([named('a'), named('b', { adapterContainer: 'nvoy-a-adapter-1' })])
  check(!r.ok && r.collisions[0].field === 'adapterContainer' && r.collisions[0].held_by === 'a',
    'a shared adapter container is caught: two principals would exec into one container')
}
check(!auditUniqueFields([named('a'), named('b', { pubkey: named('a').pubkey })]).ok, 'a shared key is caught')

// ---- the credential verdict (lstat only) ------------------------------------------------------------
const st = (o = {}) => ({ isSymbolicLink: () => !!o.link, isFile: () => o.file !== false, uid: o.uid ?? 0, mode: o.mode ?? 0o100600 })
check(credentialVerdict('/c', st()) === null, 'root:root 0600 regular file passes')
check(/does not exist/.test(credentialVerdict('/c', null)), 'a missing file fails')
check(/symlink/.test(credentialVerdict('/c', st({ link: true }))), 'a symlink fails')
check(/uid 501/.test(credentialVerdict('/c', st({ uid: 501 }))), 'a file not owned by root fails')
check(/0640/.test(credentialVerdict('/c', st({ mode: 0o100640 }))), 'a group-readable file fails, naming its mode')
check(credentialVerdict('/c', st({ mode: 0o100400 })) === null, 'a tighter 0400 still passes')

// ---- the CLI, against a temporary instance root -----------------------------------------------------
{
  const CLI = join(dirname(fileURLToPath(import.meta.url)), '../mcp/tools/instance-identity.mjs')
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-identity-'))
  const root = join(tmp, 'instances'), out = join(tmp, 'staged'), creds = join(tmp, 'credentials')
  mkdirSync(root); mkdirSync(creds)
  const live = { ...liveRaw, broker_mode: 'local', delivery_mode: 'notify_only', worker_enabled: false,
    state_dir: join(tmp, 'state/pi-dog'), runtime_dir: join(tmp, 'run/pi-dog'), spool_dir: join(tmp, 'spool/pi-dog'),
    bunker_uri_ref: join(creds, 'pi-dog.bunker-uri'), bunker_client_ref: join(creds, 'pi-dog.nip46-client'),
    watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014, broker_adapter_gid: 42011, worker_handoff_gid: 42012 }
  delete live.wake_webhook; delete live.may_set_profile
  writeFileSync(join(root, 'pi-dog.json'), JSON.stringify(live))
  const run = (...args) => spawnSync(process.execPath, [CLI, ...args, '--instance-root', root, '--out', out], { encoding: 'utf8' })

  const bare = run('allocate', '--id', 'hr', '--pubkey', NEW)
  check(bare.status === 1 && /give --grantor and --relay, or --like/.test(bare.stderr),
    'without --like or --grantor/--relay, allocate refuses rather than borrowing the first manifest it read')

  const made = run('allocate', '--id', 'hr', '--pubkey', NEW, '--like', 'pi-dog', '--credential-dir', creds)
  const staged = made.status === 0 ? JSON.parse(readFileSync(join(out, 'hr.json'), 'utf8')) : {}
  check(made.status === 0 && staged.watcher_uid === 41021 && staged.may_post?.per_hour === 30 && staged.agent_card === true,
    `allocate --like stages a manifest with the next block and the template's policy (exit ${made.status}${made.stderr ? `: ${made.stderr.trim()}` : ''})`)
  check(/policy copied from pi-dog: buzz, may_post, agent_limits, agent_card, task_carriers/.test(made.stdout),
    'and says which blocks it copied')
  check(staged.grantors?.[0] === HEX && staged.relays?.[0] === 'wss://relay.example', 'grantors and relays come from the named template')

  const unseated = run('check', '--id', 'hr')
  check(unseated.status === 1 && /PASS {2}uid\/gid block is clear/.test(unseated.stdout) && /PASS {2}key, directories and adapter container/.test(unseated.stdout)
    && /FAIL {2}.*hr\.bunker-uri does not exist/.test(unseated.stdout), 'check passes the estate audits and fails on unseated credentials')
  check(/NOT CHECKED/.test(unseated.stdout), 'and says plainly that the Bunker pairing is not something it proved')

  const SENTINEL = 'bunker://sentinel-never-printed'
  writeFileSync(join(creds, 'hr.bunker-uri'), SENTINEL, { mode: 0o600 }); writeFileSync(join(creds, 'hr.nip46-client'), SENTINEL, { mode: 0o600 })
  const owned = run('check', '--id', 'hr')
  const asRoot = process.getuid?.() === 0
  check(asRoot ? owned.status === 0 : owned.status === 1 && /not root/.test(owned.stdout),
    asRoot ? 'seated 0600 by root: check passes' : 'seated 0600 by a non-root user: check fails on ownership, as the init container would')

  // A staged manifest that collides with the estate.
  writeFileSync(join(out, 'clash.json'), JSON.stringify({ ...live, id: 'clash', pubkey: OTHER,
    state_dir: join(tmp, 'state/clash'), runtime_dir: join(tmp, 'run/clash'), spool_dir: join(tmp, 'spool/clash') }))
  const clash = run('check', '--id', 'clash')
  check(clash.status === 1 && /FAIL {2}uid 41011 is held by pi-dog/.test(clash.stdout), 'check fails a staged manifest whose block another identity holds')
  const already = run('check', '--id', 'pi-dog')
  check(already.status === 1 && /already in the instance root/.test(already.stderr), 'check refuses an identity that is already installed')
  check(![made, unseated, owned, clash].some(r => (r.stdout + r.stderr).includes(SENTINEL)), 'no output ever carries a credential file\'s contents')
  rmSync(tmp, { recursive: true, force: true })
}

console.log(`\n${pass ? 'ALL PASS' : 'FAILURES ABOVE'}`)
process.exit(pass ? 0 : 1)
