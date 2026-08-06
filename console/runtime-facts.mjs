// runtime-facts.mjs — the runtime manifest, projected into what a UI may show.
//
// `/etc/nvoy/instances/<id>.json` holds ~20 fields describing how one agent's runtime is wired, and no
// console has ever shown any of them. So "is this agent alive, and where does it run?" — decision D7 in
// the refactor spec — had no surface at all, and the Ledger's answer was a collapsed `<details>` three
// levels deep showing the agent's own outbox.
//
// AD-12 ruling: the manifest is AUTHORITY for runtime facts and does NOT merge into the registry. Different
// lifetime, different writer, different secrecy class. The console gets a READ-ONLY view of a subset.
//
// THE SUBSET IS THE WHOLE POINT, AND IT IS AN ALLOWLIST BY CONSTRUCTION.
//
// STANDARDS forbids keys, IPs, and service-account identifiers in a UI, and this manifest is full of them:
// `watcher_uid`, `broker_uid`, `adapter_uid`, `worker_uid`, `key_ref`, `bunker_uri_ref`,
// `bunker_client_ref`, `worker_credential_ref`, `ssh_target`, `state_dir`, `runtime_dir`, `spool_dir`.
// A DENYLIST would be the obvious approach and the wrong one: the manifest gains fields over time, and a
// denylist silently passes every field nobody has thought to deny yet. So only named fields survive, and a
// field added upstream is invisible here until someone deliberately admits it.
//
// The refused fields are COUNTED and their categories NAMED, because a panel that quietly showed a subset
// would let a reader believe they were seeing the runtime. They are not shown, and that is said out loud.
//
// Pure and DOM-free so test/runtime-facts.mjs can drive it.

/**
 * What a UI may show, and what each field MEANS to a reader. A field absent from this map cannot reach a
 * screen through this module — that is the security property, not a convention.
 */
export const SHOWABLE = {
  instance: 'which runtime this is',
  agent_pub: 'the agent it runs as — the join key (AD-12 ruling 1)',
  broker_mode: 'how credentials reach it',
  delivery_mode: 'how its output leaves',
  worker_runner: 'what kind of worker it runs',
  worker_enabled: 'whether a worker is running at all',
  relays: 'which relays it speaks to',
  updated_at: 'when this manifest last changed',
}

/**
 * Categories of refused field, so the panel can say WHAT it is withholding without naming instances of it.
 * Naming the category is disclosure; naming the value would be the leak.
 */
const DENY_CATEGORY = [
  [/_uid$|_gid$/, 'service-account identifiers'],
  [/_ref$/, 'credential locations'],
  [/_dir$|^cwd$/, 'filesystem paths'],
  [/^ssh_|_target$/, 'host addresses'],
  [/image$/, 'image digests'],
]

const categoryOf = (key) => {
  for (const [re, label] of DENY_CATEGORY) if (re.test(key)) return label
  return 'other operational detail'
}

/**
 * Project one manifest.
 *
 * @returns {{ shown: object, withheld: {count:number, categories:string[]}, fields: Array }}
 *   `shown` carries only allowlisted keys that are actually present. `withheld` describes the rest.
 */
export function projectManifest(manifest) {
  const src = (manifest && typeof manifest === 'object') ? manifest : {}
  const shown = {}
  const fields = []
  for (const [key, meaning] of Object.entries(SHOWABLE)) {
    if (!(key in src)) continue
    const v = src[key]
    if (v === null || v === undefined) continue
    shown[key] = v
    fields.push({ key, meaning, value: v })
  }
  const withheldKeys = Object.keys(src).filter(k => !(k in SHOWABLE))
  const categories = [...new Set(withheldKeys.map(categoryOf))].sort()
  return { shown, fields, withheld: { count: withheldKeys.length, categories } }
}

/**
 * The sentence the panel owes the reader about what it is not showing. Returns null when there is nothing
 * withheld — never a reassuring "everything is shown", because that would be a claim about a manifest
 * shape this build cannot predict.
 */
export function withheldNote({ count, categories }) {
  if (!count) return null
  return `${count} further field${count === 1 ? '' : 's'} in this runtime's manifest `
    + `${count === 1 ? 'is' : 'are'} deliberately not shown here — ${categories.join(', ')}. `
    + 'A control plane does not display credential locations, host addresses or service-account ids, and '
    + 'this panel is an allowlist, so a field added to the manifest later stays hidden until someone '
    + 'admits it on purpose.'
}

/**
 * The three-state source stamp for the panel, matching the agent page's contract.
 *
 * `null` manifest means the endpoint did not answer. That is NOT "no runtime": the manifest lives on a box
 * this console reaches over an authenticated endpoint, and being unable to ask is not evidence of absence.
 */
export function runtimeState(manifest, { reachable = true } = {}) {
  if (!reachable) {
    return {
      state: 'silent',
      note: 'The runtime endpoint did not answer. Nothing is shown because nothing could be verified — '
        + 'this is not the same as "this agent has no runtime."',
    }
  }
  if (!manifest) {
    return {
      state: 'empty',
      note: 'No runtime manifest exists for this agent. It can still hold grants — a grant is authority, '
        + 'not a process.',
    }
  }
  return { state: 'answered', note: null }
}
