// identity_allocation.mjs — pick a UID/GID block for a new participant, and audit the ones in use (#166).
//
// PURE. No filesystem, no clock, no network: it is handed the manifests that already exist and
// returns a decision. That is what lets the allocation policy be asserted in full without a host,
// and it is the half worth testing — the CLI around it only reads files and prints.
//
// Why this exists (#165): `assertNoCollisions` refuses duplicate pubkey, state_dir, runtime_dir and
// spool_dir across identities, and does NOT look at the six numeric identity fields. Two identities
// sharing uid 41011 validate, render and deploy cleanly while silently sharing a security domain —
// which is exactly the isolation the four-distinct-UID rule exists to provide.
//
// The design rule here: an allocator that GUESSES is worse than no allocator. Every refusal below
// is a refusal to invent a value the operator would then have to un-invent on a live host.

export const ALLOCATION_VERSION = 1

// The established stride, read off the live estate rather than off the documentation — the worked
// example in RUNTIME_SUPERVISOR.md and the boundary-test fixture BOTH use blocks that are not what
// is deployed, and copying either of them is how a collision gets introduced deliberately.
export const UID_BASE = 41011      // codex-jaf holds 41011-41014
export const GID_BASE = 42011      // codex-jaf holds 42011-42012
export const UID_STRIDE = 10       // one decade per identity: room to grow without touching a neighbour
export const GID_STRIDE = 10
// Hard ceiling. Beyond this a host is into ranges a distribution may hand out to real accounts, and
// an allocator that wandered there would collide with something no manifest can see.
export const UID_CEILING = 49999

export const UID_ROLES = Object.freeze(['watcherUid', 'brokerUid', 'adapterUid', 'workerUid'])
export const GID_ROLES = Object.freeze(['brokerAdapterGid', 'workerHandoffGid'])
export const NUMERIC_FIELDS = Object.freeze([...UID_ROLES, ...GID_ROLES])

const fail = message => { throw new Error(`identity-allocation: ${message}`) }
const ID = /^[a-z0-9][a-z0-9._-]{1,63}$/i

/**
 * Audit the identity fields across every manifest — the check #165 says is missing.
 *
 * `manifests` is an array of already-parsed manifests (camelCase, as `readManifest` returns them).
 * Returns a frozen report; it never throws on a collision, because the caller needs to print ALL of
 * them rather than the first. A collision names both identities and the field, since the operator's
 * next question is always which one to move.
 */
export function auditIdentityBlocks(manifests) {
  if (!Array.isArray(manifests)) fail('manifests must be an array')
  const collisions = []
  const holders = new Map()   // "field-kind:value" -> [{ id, field }]

  for (const m of manifests) {
    if (!m || typeof m !== 'object') fail('every manifest must be an object')
    const id = String(m.id || '<unnamed>')
    for (const field of NUMERIC_FIELDS) {
      const value = m[field]
      if (!Number.isInteger(value)) continue   // per-manifest validation owns shape; this owns overlap
      // UIDs and GIDs are separate namespaces. A uid 42011 and a gid 42011 are not a collision, and
      // reporting them as one would train an operator to ignore this tool.
      const kind = UID_ROLES.includes(field) ? 'uid' : 'gid'
      const key = `${kind}:${value}`
      const prior = holders.get(key)
      if (prior) {
        // Same identity reusing a number across its own roles is caught by per-manifest validation
        // (four UIDs must be mutually distinct); this is only about CROSS-identity overlap.
        if (prior.id !== id) collisions.push(Object.freeze({ kind, value, held_by: prior.id, held_field: prior.field, wanted_by: id, wanted_field: field }))
      } else {
        holders.set(key, { id, field })
      }
    }
  }

  return Object.freeze({
    version: ALLOCATION_VERSION,
    identities: manifests.length,
    collisions: Object.freeze(collisions),
    ok: collisions.length === 0,
  })
}

/** Every uid and gid currently spoken for, as two sets. */
export function occupiedNumbers(manifests) {
  const uids = new Set(), gids = new Set()
  for (const m of manifests || []) {
    for (const f of UID_ROLES) if (Number.isInteger(m?.[f])) uids.add(m[f])
    for (const f of GID_ROLES) if (Number.isInteger(m?.[f])) gids.add(m[f])
  }
  return { uids, gids }
}

/**
 * Choose the next block: the first stride ABOVE the highest number ever used.
 *
 * Never a gap. uids outlive the manifests that named them — files on a volume, entries in a log —
 * and handing a retired identity's numbers to a new one makes the old artefacts read as the new
 * agent's. Scanning for the first free decade does exactly that the moment an identity is removed,
 * so the floor is the high-water mark, not the lowest hole. The installed manifests alone forget a
 * retired top identity, so `used` carries the durable record: every block ever installed
 * (identity-blocks.jsonl, appended by `apply`). Reuse is an operator decision with evidence behind
 * it, made by hand, never something an allocator does to save integers.
 */
export function allocateIdentityBlock(manifests, { id, uidBase = UID_BASE, gidBase = GID_BASE, used = [] } = {}) {
  if (!ID.test(String(id || ''))) fail('a usable instance id is required')
  if ((manifests || []).some(m => String(m?.id) === String(id))) fail(`an identity named ${id} already exists`)

  const audit = auditIdentityBlocks(manifests || [])
  if (!audit.ok) {
    // Refuse to allocate on top of an estate that is already inconsistent. Adding a correct third
    // identity to two that overlap would bury the existing fault under new work.
    fail(`refusing to allocate while ${audit.collisions.length} existing collision(s) stand — run the audit and resolve them first`)
  }

  const { uids, gids } = occupiedNumbers([...(manifests || []), ...(used || [])])
  const above = (base, stride, span, taken) => {
    const high = Math.max(base - 1, ...taken)
    const start = base + Math.ceil((high + 1 - base) / stride) * stride
    return start + span - 1 <= UID_CEILING ? start : null
  }
  const uidStart = above(uidBase, UID_STRIDE, UID_ROLES.length, uids)
  const gidStart = above(gidBase, GID_STRIDE, GID_ROLES.length, gids)
  if (uidStart === null || gidStart === null) fail('no block left below the ceiling — allocate by hand and record why')

  const block = {}
  UID_ROLES.forEach((f, i) => { block[f] = uidStart + i })
  GID_ROLES.forEach((f, i) => { block[f] = gidStart + i })

  return Object.freeze({
    version: ALLOCATION_VERSION,
    id: String(id),
    block: Object.freeze(block),
    uid_range: Object.freeze([uidStart, uidStart + UID_ROLES.length - 1]),
    gid_range: Object.freeze([gidStart, gidStart + GID_ROLES.length - 1]),
    neighbours: Object.freeze((manifests || []).map(m => String(m.id)).sort()),
  })
}

/**
 * Build the manifest body for a Claude-channel participant.
 *
 * Returns the object only — writing it is the caller's business, and deliberately NOT into the live
 * instance root. `runtime-deploy-runner.py` gates on the release SHA and returns early when it is
 * already current, but it health-checks every globbed manifest before doing so; one with no compose
 * file beside it fails that check and forces an estate-wide reconcile as soon as the file lands. So a
 * manifest that lands before its credentials exist fails to start, and that failure rolls back every
 * identity touched in the reconcile — including healthy ones. The ordering is the safety property,
 * so the tool stages. See the header of instance-identity.mjs for the mechanism in full.
 */
export function buildParticipantManifest(allocation, { pubkey, grantors, relays, taskCarriers = [], policy = {}, credentialDir = '/etc/nvoy/credentials' } = {}) {
  if (!allocation || allocation.version !== ALLOCATION_VERSION) fail('a valid allocation is required')
  const id = allocation.id
  const hex = (v, label) => {
    const s = String(v || '').toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(s)) fail(`${label} must be a 64-hex public key (decode an npub first)`)
    return s
  }
  if (!Array.isArray(grantors) || !grantors.length) fail('at least one grantor is required')
  if (!Array.isArray(relays) || !relays.length) fail('at least one relay is required')
  for (const r of relays) if (!String(r).startsWith('wss://')) fail(`relay ${r} must be wss://`)
  const stray = Object.keys(policy).filter(k => !TEMPLATE_FIELDS.includes(k))
  if (stray.length) fail(`a template may carry only ${TEMPLATE_FIELDS.join(', ')}, not ${stray.join(', ')}`)

  return Object.freeze({
    version: 1,
    id,
    pubkey: hex(pubkey, 'pubkey'),
    // These three are jointly required by the unit renderer, the doctor and the key renderer, each
    // of which checks them independently. A Claude channel identity is always this shape.
    broker_mode: 'local',
    delivery_mode: 'notify_only',
    worker_enabled: false,
    state_dir: `/var/lib/nvoy/${id}`,
    runtime_dir: `/run/nvoy/${id}`,
    spool_dir: `/var/lib/nvoy-watcher/${id}`,
    // Referenced, never read by this tool. The values are seated by the operator; nothing here
    // handles a credential, and nothing here should ever be able to print one.
    bunker_uri_ref: `${credentialDir}/${id}.bunker-uri`,
    bunker_client_ref: `${credentialDir}/${id}.nip46-client`,
    grantors: grantors.map((g, i) => hex(g, `grantors[${i}]`)),
    relays: [...new Set(relays.map(String))],
    task_carriers: taskCarriers,
    ...policy,
    ...allocation.block_snake ?? snakeBlock(allocation.block),
  })
}

// What a new agent copies from a named live one (`--like`). These are the policy blocks every hive
// agent carries: where it listens, where and how often it may post, its limits, its card, and who
// carries tasks to it. Nothing identity-bound is copied: not the key, the uids, the directories, the
// credentials, a webhook or door (each names its own secret), nor may_set_profile (scoped to one key).
export const TEMPLATE_FIELDS = Object.freeze(['buzz', 'may_post', 'agent_limits', 'agent_card', 'task_carriers'])

/**
 * The policy blocks of one raw (snake_case) manifest, for a new agent with `pubkey`. Copying is a
 * choice the operator names, not a default: the template is whichever agent they say the new one
 * should work like. The new agent's own key is dropped from the mention list, since mentioning
 * yourself is not a use the manifest allows for.
 */
export function policyFromTemplate(raw, { pubkey } = {}) {
  if (!raw || typeof raw !== 'object') fail('a template manifest is required')
  const self = String(pubkey || '').toLowerCase()
  const policy = {}
  for (const k of TEMPLATE_FIELDS) if (raw[k] !== undefined) policy[k] = JSON.parse(JSON.stringify(raw[k]))
  if (Array.isArray(policy.may_post?.mention)) {
    policy.may_post.mention = policy.may_post.mention.filter(m => String(typeof m === 'object' ? m?.pubkey : m).toLowerCase() !== self)
  }
  if (Array.isArray(policy.task_carriers)) policy.task_carriers = policy.task_carriers.filter(c => String(c?.pubkey).toLowerCase() !== self)
  return policy
}

/**
 * The values no two identities may share, beyond the uid/gid block: the key, the three directories
 * and the adapter container the channel principal names. `assertNoCollisions` covers the first four
 * for manifests already in the instance root; this covers a staged one against that root before it
 * lands, and adds the container. Takes manifests as `readManifest` returns them.
 */
export const UNIQUE_FIELDS = Object.freeze(['pubkey', 'stateDir', 'runtimeDir', 'spoolDir', 'adapterContainer'])
export function auditUniqueFields(manifests) {
  const seen = new Map(), collisions = []
  for (const m of manifests || []) for (const field of UNIQUE_FIELDS) {
    const value = m?.[field]
    if (!value) continue
    const key = `${field}:${value}`
    if (seen.has(key) && seen.get(key) !== m.id) collisions.push(Object.freeze({ field, held_by: seen.get(key), wanted_by: m.id }))
    else seen.set(key, m.id)
  }
  return Object.freeze({ collisions: Object.freeze(collisions), ok: collisions.length === 0 })
}

/**
 * Whether a credential file is seated as the init container expects: present, a regular file and
 * not a symlink, owned by root, and unreadable by group or world. `st` is an lstat result, or null
 * when the file does not exist. The file's contents are never needed and never read.
 */
export function credentialVerdict(path, st) {
  if (!st) return `${path} does not exist`
  if (st.isSymbolicLink()) return `${path} is a symlink; seat the file itself`
  if (!st.isFile()) return `${path} is not a regular file`
  if (st.uid !== 0) return `${path} is owned by uid ${st.uid}, not root`
  if (st.mode & 0o077) return `${path} is mode ${(st.mode & 0o777).toString(8).padStart(4, '0')}; it must be 0600 (no group or world access)`
  return null
}

// The manifest on disk is snake_case; `readManifest` hands back camelCase. Converting in one named
// place keeps the two spellings from being hand-mapped at each call site.
function snakeBlock(block) {
  return {
    broker_adapter_gid: block.brokerAdapterGid,
    worker_handoff_gid: block.workerHandoffGid,
    watcher_uid: block.watcherUid,
    broker_uid: block.brokerUid,
    adapter_uid: block.adapterUid,
    worker_uid: block.workerUid,
  }
}

/**
 * The ordered operator steps. Emitted as data rather than prose so the CLI cannot drift from the
 * ordering, and so the ordering itself can be asserted — it has already failed once in production
 * (a chown issued before the account existed).
 */
export function seatingPlan(manifest) {
  const id = manifest.id
  return Object.freeze([
    Object.freeze({ step: 1, actor: 'operator', automatable: false,
      what: `Mint the Bunker identity for ${id} and pair a NIP-46 client`,
      why: 'The pairing secret is effectively single-use, so this cannot be retried idempotently. A spent one presents as "Unknown client", which blames the client key rather than the secret.' }),
    Object.freeze({ step: 2, actor: 'operator', automatable: false,
      what: `Seat ${manifest.bunker_uri_ref} and ${manifest.bunker_client_ref} as root:root 0600`,
      why: 'root:root 0600 is correct AND safe before the instance exists. Do not pre-chown to a broker group — that account does not exist yet, which is the ordering that failed before. The root-only init container transfers ownership later and verifies it.' }),
    Object.freeze({ step: 3, actor: 'operator', automatable: false,
      what: 'Prove the pairing read-only: resolve the public key through the credential and match it to the manifest pubkey',
      why: 'Possessing a URI is not proof of control. This signs nothing and publishes nothing. Note that Bunker permissions are per-method — a sign_event denial is byte-identical to an empty inbox (nvoy#142).' }),
    Object.freeze({ step: 4, actor: 'operator', automatable: true,
      what: `Install the staged manifest at /etc/nvoy/instances/${id}.json (root:root 0644)`,
      why: 'THIS STARTS THE DEPLOY, at once: nvoy-runtime-deploy.path fires on any change to the instance root (and the 30 s timer would within a tick). The runner health-checks every manifest it globs, and one with no compose file beside it fails that check and forces an estate-wide reconcile. If this identity then fails to start, every identity touched in that reconcile is rolled back — including healthy ones. Do not place it until steps 2 and 3 are done.' }),
    Object.freeze({ step: 5, actor: 'operator', automatable: true,
      what: `Render and install the SSH principal, then verify it landed`,
      why: 'The renderer writes a .authorized_key file; nothing installs it. Verify reports an absent principal as FAIL rather than pass, and matches on the comment so a drifted one is reported wrong rather than missing.' }),
    Object.freeze({ step: 6, actor: 'operator', automatable: false,
      what: 'Baseline once, before enabling the client key',
      why: 'Re-running against the same volume is harmless. Baselining after a lost read cursor is not — it marks records read without ever exposing them, and nothing refuses a second run.' }),
    Object.freeze({ step: 7, actor: 'operator', automatable: false,
      what: 'Cutover proof: wake, wait MORE than five minutes, reply, then read back by id from a fresh connection',
      why: 'A fast reply proves nothing — fast replies always worked. A relay OK is not proof; relays return OK and drop.' }),
  ])
}
