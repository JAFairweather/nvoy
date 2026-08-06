// registry.mjs — the projected roster, and the divergence rows it makes possible.
//
//   node test/registry.mjs
//
// THE ACCEPTANCE TEST FOR THE DIRECTOR'S ACTUAL COMPLAINT lives here. He reported that some agents
// show in Nvoy and not in Nact. The mechanism was fixed in nact#57 (the join key is the hex pubkey on
// both sides), but a join needs two sets and Nact could not read Nvoy's — the roster is encrypted to
// the Director. So the roster is projected as a scoped dataset, and the mismatch becomes a VISIBLE
// ROW instead of an unobservable absence.
//
// The property that matters most is the third state. "The projection was never read" is not
// "Nvoy does not know this key" — and a classifier that collapsed them would recreate the original
// bug wearing a fix's clothing, because a box-only row would then be asserted rather than admitted.

import assert from 'node:assert'
import {
  REGISTRY_SCOPE, REGISTRY_VERSION, buildProjection, projectionChanged, diffRosters, divergenceNote,
  enrol, ENROL_REASONS,
} from '../console/registry.mjs'

let pass = 0, fail = 0
const t = (name, fn) => {
  try { fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

const A = 'a'.repeat(64), B = 'b'.repeat(64), C = 'c'.repeat(64)
const ME = 'd'.repeat(64)
const idx = (agents) => ({ nvoy_agents: agents })

// ── the scope name obeys AD-8, so the Ledger's Type facet can classify it ────
t('the scope is namespaced `data:` so the Type facet reads it as data, not a guess', () => {
  assert.match(REGISTRY_SCOPE, /^data:/)
})

// ── building the projection: normalise, dedupe, and never invent ─────────────
t('a roster row projects to its join key', () => {
  const { payload } = buildProjection(idx([{ pub: A, added_at: 5 }]))
  assert.deepEqual(payload.agents, [{ pub: A, added_at: 5 }])
  assert.equal(payload.v, REGISTRY_VERSION)
})
t('a pubkey is lowercased — one key must not appear as two agents', () => {
  const { payload } = buildProjection(idx([{ pub: A.toUpperCase() }]))
  assert.equal(payload.agents[0].pub, A)
})
t('a duplicate key is dropped: one key, one Agent (ruling 1)', () => {
  const { payload, dropped } = buildProjection(idx([{ pub: A }, { pub: A.toUpperCase() }]))
  assert.equal(payload.agents.length, 1)
  assert.equal(dropped, 1)
})
t('a malformed row is dropped and COUNTED, never silently shortened', () => {
  // A quietly shorter roster handed to a slice IS the original bug, moved one layer out.
  const { payload, dropped } = buildProjection(idx([{ pub: A }, { pub: 'nope' }, null, {}, { pub: 42 }]))
  assert.equal(payload.agents.length, 1)
  assert.equal(dropped, 4)
})
t('no field is invented — a handle the registry lacks does not appear', () => {
  const { payload } = buildProjection(idx([{ pub: A }]))
  assert.deepEqual(Object.keys(payload.agents[0]), ['pub'], 'only what the registry actually holds')
})
t('a missing added_at is omitted rather than zeroed — 0 would read as 1970', () => {
  const { payload } = buildProjection(idx([{ pub: A, added_at: 'soon' }]))
  assert.equal('added_at' in payload.agents[0], false)
})
t('the payload states that it is a stale copy and not authority', () => {
  const { payload } = buildProjection(idx([]), { now: 100 })
  assert.equal(payload.generated_at, 100)
  assert.match(payload.note, /copy, not a live view/)
  assert.match(payload.note, /Never authority/)
})
t('no roster is an empty projection, not an error', () => {
  assert.deepEqual(buildProjection({}).payload.agents, [])
  assert.deepEqual(buildProjection(undefined).payload.agents, [])
})
t('ordering is stable, so an unchanged roster projects identically', () => {
  const one = buildProjection(idx([{ pub: B }, { pub: A }])).payload
  const two = buildProjection(idx([{ pub: A }, { pub: B }])).payload
  assert.deepEqual(one.agents, two.agents)
})

// ── republishing costs every grantee a re-delivery, so refuse a no-op ───────
t('an unchanged roster reports no change', () => {
  const a = buildProjection(idx([{ pub: A }]), { now: 1 }).payload
  const b = buildProjection(idx([{ pub: A }]), { now: 999 }).payload
  assert.equal(projectionChanged(a, b), false, 'a new timestamp alone is not a change')
})
t('an added agent reports a change', () => {
  const a = buildProjection(idx([{ pub: A }])).payload
  const b = buildProjection(idx([{ pub: A }, { pub: B }])).payload
  assert.equal(projectionChanged(a, b), true)
})
t('a version bump reports a change even when the roster is identical', () => {
  assert.equal(projectionChanged({ v: 0, agents: [{ pub: A }] }, { v: 1, agents: [{ pub: A }] }), true)
})
t('no previous projection reports a change', () => {
  assert.equal(projectionChanged(null, buildProjection(idx([{ pub: A }])).payload), true)
})

// ── THE DIVERGENCE ROWS: the Director's complaint, made visible ─────────────
t('an agent in both stores is in `both`', () => {
  const d = diffRosters({ registry: [{ pub: A }], box: [A] })
  assert.deepEqual(d.both, [A]); assert.deepEqual(d.onlyRegistry, []); assert.deepEqual(d.onlyBox, [])
})
t('THE REPORTED SYMPTOM: registered in Nvoy, no key on the box → onlyRegistry', () => {
  const d = diffRosters({ registry: [{ pub: A }, { pub: B }], box: [A] })
  assert.deepEqual(d.onlyRegistry, [B])
  assert.match(divergenceNote('onlyRegistry'), /known only to Nvoy/)
  assert.match(divergenceNote('onlyRegistry'), /no key slot for it exists on the box/)
})
t('THE CONVERSE: a key on the box with no registry row → onlyBox, and is not an agent', () => {
  const d = diffRosters({ registry: [{ pub: A }], box: [A, C] })
  assert.deepEqual(d.onlyBox, [C])
  assert.match(divergenceNote('onlyBox'), /not an agent until you register it/)
})
t('the diff accepts bare hex or row objects on either side', () => {
  const d = diffRosters({ registry: [A], box: [{ pub: A }] })
  assert.deepEqual(d.both, [A])
})
t('case differences never manufacture a divergence', () => {
  const d = diffRosters({ registry: [A.toUpperCase()], box: [A] })
  assert.deepEqual(d.both, [A]); assert.deepEqual(d.onlyRegistry, []); assert.deepEqual(d.onlyBox, [])
})
t('a malformed key on either side is ignored, not rendered as a divergence', () => {
  const d = diffRosters({ registry: [A, 'garbage'], box: [A, null] })
  assert.deepEqual(d.both, [A]); assert.deepEqual(d.onlyRegistry, []); assert.deepEqual(d.onlyBox, [])
})

// ── the third state, which is the point ────────────────────────────────────
t('an UNREAD projection yields `unverified`, never onlyBox', () => {
  // Collapsing these would assert "Nvoy does not know this key" on the strength of never having
  // asked — the original bug wearing a fix's clothing.
  const d = diffRosters({ registry: null, box: [A, C] })
  assert.equal(d.registryKnown, false)
  assert.deepEqual(d.unverified, [A, C].sort())
  assert.deepEqual(d.onlyBox, [], 'an unread store must not produce a divergence claim')
  assert.deepEqual(d.onlyRegistry, [])
})
t('…and its note refuses the wrong conclusion by name', () => {
  assert.match(divergenceNote('unverified'), /not the same as "Nvoy does not know it\."/)
})
t('an EMPTY projection is different from an unread one', () => {
  const d = diffRosters({ registry: [], box: [A] })
  assert.equal(d.registryKnown, true)
  assert.deepEqual(d.onlyBox, [A], 'an answered-but-empty registry DOES make this a real divergence')
  assert.deepEqual(d.unverified, [])
})
t('both stores empty is a clean, verified answer', () => {
  const d = diffRosters({ registry: [], box: [] })
  assert.equal(d.registryKnown, true)
  assert.deepEqual([d.both, d.onlyBox, d.onlyRegistry, d.unverified], [[], [], [], []])
})
t('an unrecognised state does not get a reassuring sentence', () => {
  assert.match(divergenceNote('whatever'), /unrecognised/)
})

// ── the acceptance test, stated so it can fail ─────────────────────────────
t('ACCEPTANCE: register one agent in Nvoy and it is accounted for on both sides', () => {
  // Register A and B in Nvoy; the box has A and an unregistered C.
  const { payload } = buildProjection(idx([{ pub: A, added_at: 1 }, { pub: B, added_at: 2 }]), { now: 9 })
  const d = diffRosters({ registry: payload.agents, box: [A, C] })
  // Every key is accounted for in exactly one bucket — nothing can be silently absent, which is the
  // property whose absence caused the complaint.
  const all = [...d.both, ...d.onlyRegistry, ...d.onlyBox, ...d.unverified].sort()
  assert.deepEqual(all, [A, B, C].sort())
  assert.equal(new Set(all).size, all.length, 'each key appears exactly once')
})

// ── enrolment: the front door must write the register (AD-12 ruling g) ───────
//
// The symptom the Director reported was "OTHER IDENTITIES · 21 grantees · 27 grants": keys he had
// issued grants to, filed as strangers. The cause was that only two paths ever appended to the
// roster — approving a request, and pasting an npub — and THE GRANT COMPOSER WAS NOT ONE OF THEM.
// So the most direct way to give an agent authority did not make it an agent.
//
// These pin the rule itself. The wiring into the three call sites is covered by console-imports
// (the names resolve) and console-smoke (the render path runs).
t('issuing to a new key enrols it — the defect behind the report', () => {
  const r = enrol(idx([]), A, { me: ME, now: 7 })
  assert.equal(r.added, true)
  assert.deepEqual(r.agents, [{ pub: A, added_at: 7 }])
})
t('enrolling twice is success, not an error — approving a known agent must not fail', () => {
  const r = enrol(idx([{ pub: A, added_at: 1 }]), A, { me: ME, now: 7 })
  assert.equal(r.added, false)
  assert.equal(r.reason, 'duplicate')
  assert.equal(r.agents.length, 1, 'and it does NOT duplicate the row — one key, one Agent')
})
t('the Director is not one of his own agents', () => {
  const r = enrol(idx([]), ME, { me: ME, now: 7 })
  assert.equal(r.added, false)
  assert.equal(r.reason, 'self')
  assert.deepEqual(r.agents, [])
})
t('a malformed key is refused, and says which of the three refusals it is', () => {
  for (const bad of ['', 'npub1nope', 'ZZ' + A.slice(2), null, undefined, A.slice(0, 63)])
    assert.equal(enrol(idx([]), bad, { me: ME }).reason, 'malformed', `accepted ${bad}`)
})
t('the join key is case-folded on BOTH sides, so a mixed-case npub is not a second Agent', () => {
  const r = enrol(idx([{ pub: A, added_at: 1 }]), A.toUpperCase(), { me: ME, now: 7 })
  assert.equal(r.reason, 'duplicate', 'an uppercase copy of a registered key is the same Agent')
  assert.equal(enrol(idx([]), A.toUpperCase(), { me: ME, now: 7 }).agents[0].pub, A,
    'and a new one is stored folded, so the projection joins')
})
t('enrol never mutates the index it was handed — the caller owns the save', () => {
  const index = idx([{ pub: A, added_at: 1 }])
  const before = JSON.stringify(index)
  enrol(index, B, { me: ME, now: 7 })
  assert.equal(JSON.stringify(index), before,
    'a helper that saved by itself would reintroduce the divergence it closes')
})
t('every refusal code is one the callers know how to word', () => {
  for (const code of ['malformed', 'self', 'duplicate']) assert.ok(ENROL_REASONS.includes(code))
})
t('ACCEPTANCE: a key granted from the composer reaches the projection Nact reads', () => {
  // The whole chain the report was about, end to end: enrol -> roster -> projection -> join.
  const { agents } = enrol(idx([]), A, { me: ME, now: 7 })
  const { payload } = buildProjection(idx(agents), { now: 9 })
  const d = diffRosters({ registry: payload.agents, box: [] })
  assert.deepEqual(d.onlyRegistry, [A], 'it must show as known-only-to-Nvoy, never as absent')
})

// ── the three doors must actually go through it ──────────────────────────────
//
// Everything above tests the RULE. None of it fails if someone deletes the call. That is precisely
// how this bug lived: the rule was fine, the composer just never asked. `console-imports` will not
// catch it either — an unused import still resolves. So assert the call sites, statically, and
// accept the cost that renaming the helper means editing this list.
{
  const { readFileSync } = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const { dirname, join } = await import('node:path')
  const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'console')
  for (const [file, door] of [
    ['delegate.mjs', 'issuing a grant'],
    ['requests.mjs', 'approving a request'],
    ['agents.mjs', 'pasting an npub'],
  ]) {
    const src = readFileSync(join(dir, file), 'utf8').replace(/^\s*\/\/.*$/gm, ' ')
    t(`${door} enrols the grantee (console/${file})`, () => {
      assert.match(src, /\benrol\s*\(/, `${file} no longer calls enrol() — the roster will fall behind again`)
      assert.doesNotMatch(src, /nvoy_agents\s*=\s*\[\s*\.\.\./,
        `${file} appends to nvoy_agents directly again, bypassing the one rule`)
    })
  }
}

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
