// The runtime manifest projection — an allowlist that CANNOT leak, proven with a real manifest shape.
//
//   node test/runtime-facts.mjs
//
// `/etc/nvoy/instances/<id>.json` holds ~20 fields and no console has ever shown any of them, so
// "is this agent alive, and where does it run?" had no surface. AD-12 makes the manifest authority for
// runtime facts that does NOT merge into the registry, with a read-only console view of a subset.
//
// THE SUBSET IS THE SECURITY PROPERTY. STANDARDS forbids keys, IPs and service-account identifiers in a UI,
// and this manifest is full of them: watcher_uid, broker_uid, adapter_uid, worker_uid, key_ref,
// bunker_uri_ref, bunker_client_ref, worker_credential_ref, ssh_target, state_dir, runtime_dir, spool_dir.
//
// A DENYLIST would be the obvious approach and the wrong one: the manifest gains fields over time, and a
// denylist silently passes every field nobody has thought to deny yet. So the decisive assertion here is
// not "these fields are hidden" — it is that an UNKNOWN field is hidden too, which is what makes the
// property hold against a manifest this build has never seen.
//
// The fixture is copied from test/instance-runtime.mjs so it is the real shape, not a convenient one.

import assert from 'node:assert'
import { projectManifest, withheldNote, runtimeState, SHOWABLE } from '../console/runtime-facts.mjs'

let pass = 0, fail = 0
const t = (name, fn) => {
  try { fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

// The real manifest shape, from test/instance-runtime.mjs's fixture.
const MANIFEST = {
  instance: 'codex-test',
  agent_pub: 'a'.repeat(64),
  broker_mode: 'grant',
  delivery_mode: 'ssh',
  worker_runner: 'codex',
  worker_enabled: true,
  relays: ['wss://nos.lol'],
  updated_at: 1785900000,
  // everything below must never reach a screen
  state_dir: '/srv/nvoy/state-codex',
  runtime_dir: '/run/nvoy/codex',
  spool_dir: '/srv/nvoy/spool-codex',
  key_ref: '/etc/nvoy/credentials/codex-test.nsec',
  bunker_uri_ref: '/etc/nvoy/credentials/codex-test.bunker',
  bunker_client_ref: '/etc/nvoy/credentials/codex-test.client',
  worker_credential_ref: '/etc/nvoy/credentials/codex-test.provider',
  worker_image: 'registry.example/codex-worker@sha256:' + 'd'.repeat(64),
  ssh_target: 'deploy@10.0.0.4',
  watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  broker_adapter_gid: 41020, worker_handoff_gid: 41021,
  cwd: '/srv/nvoy',
}

const SECRETS = ['/etc/nvoy', '/srv/nvoy', '/run/nvoy', '10.0.0.4', 'deploy@', '41011', '41012', '41013',
  '41014', '41020', '41021', 'sha256:', '.nsec', '.bunker', '.client', '.provider']

t('the allowlisted fields are shown', () => {
  const { shown } = projectManifest(MANIFEST)
  assert.equal(shown.instance, 'codex-test')
  assert.equal(shown.agent_pub, 'a'.repeat(64))
  assert.equal(shown.worker_enabled, true)
})

t('THE PROPERTY: nothing sensitive survives the projection, checked by SERIALISING the output', () => {
  // Asserting per-field would miss a leak through a nested value. Serialising the whole result and
  // searching for every sensitive substring is the check that actually holds.
  const json = JSON.stringify(projectManifest(MANIFEST))
  for (const s of SECRETS) assert.ok(!json.includes(s), `leaked ${s}`)
})

t('AN UNKNOWN FIELD IS HIDDEN TOO — the reason this is an allowlist', () => {
  // A denylist would pass this. The manifest gains fields over time and nobody updates a denylist in the
  // same commit; this is the assertion that makes the property survive a manifest we have never seen.
  const { shown, withheld } = projectManifest({ ...MANIFEST, some_future_secret: 'hunter2' })
  assert.equal('some_future_secret' in shown, false)
  assert.ok(!JSON.stringify(shown).includes('hunter2'))
  assert.ok(withheld.count > 0)
})

t('the withheld fields are COUNTED, so the panel cannot imply completeness', () => {
  const { withheld } = projectManifest(MANIFEST)
  const expected = Object.keys(MANIFEST).filter(k => !(k in SHOWABLE)).length
  assert.equal(withheld.count, expected)
  assert.ok(expected >= 15, 'the fixture must actually exercise a full manifest')
})

t('…and their CATEGORIES are named, which is disclosure without being a leak', () => {
  const { withheld } = projectManifest(MANIFEST)
  for (const c of ['service-account identifiers', 'credential locations', 'filesystem paths', 'host addresses'])
    assert.ok(withheld.categories.includes(c), `missing category: ${c}`)
})

t('the note names the categories and explains the allowlist', () => {
  const note = withheldNote(projectManifest(MANIFEST).withheld)
  assert.match(note, /deliberately not shown/)
  assert.match(note, /service-account ids/)
  assert.match(note, /allowlist/)
  // And it must not itself leak while explaining.
  for (const s of SECRETS) assert.ok(!note.includes(s), `the note leaked ${s}`)
})

t('nothing withheld yields NO note — never a claim that everything is shown', () => {
  // "Everything is shown" would be a claim about a manifest shape this build cannot predict.
  assert.equal(withheldNote({ count: 0, categories: [] }), null)
})

t('an absent allowlisted field is omitted rather than rendered empty', () => {
  const { shown, fields } = projectManifest({ instance: 'x' })
  assert.deepEqual(Object.keys(shown), ['instance'])
  assert.equal(fields.length, 1)
})

t('a null value is omitted — null is not a fact worth a row', () => {
  assert.equal('broker_mode' in projectManifest({ instance: 'x', broker_mode: null }).shown, false)
})

t('garbage input does not throw inside a console render', () => {
  for (const bad of [null, undefined, 'nope', 42, []]) {
    const r = projectManifest(bad)
    assert.deepEqual(r.shown, {})
    assert.equal(r.withheld.count, 0)
  }
})

t('every showable field carries a MEANING, not just a name', () => {
  // A row reading `delivery_mode: ssh` teaches nothing; the panel must say what the field is for.
  for (const [k, v] of Object.entries(SHOWABLE)) assert.ok(v && v.length > 8, `${k} has no meaning`)
})

// ── the three-state stamp, matching the agent page's contract ───────────────
t('an unreachable endpoint is SILENT and refuses the wrong conclusion by name', () => {
  const s = runtimeState(null, { reachable: false })
  assert.equal(s.state, 'silent')
  assert.match(s.note, /not the same as "this agent has no runtime\."/)
})
t('reachable-but-no-manifest is EMPTY, and says a grant is not a process', () => {
  const s = runtimeState(null, { reachable: true })
  assert.equal(s.state, 'empty')
  assert.match(s.note, /a grant is authority, not a process/)
})
t('a manifest answers, with no excuse attached', () => {
  const s = runtimeState(MANIFEST)
  assert.equal(s.state, 'answered')
  assert.equal(s.note, null)
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
