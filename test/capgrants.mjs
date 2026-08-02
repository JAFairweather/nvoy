// capgrants.mjs — assertions over the universal grant plane (console/capgrants.mjs).
//
// The promise is "Nvoy shows EVERY grant your key signed, from any app." So the tests are about
// two failure modes that would break that promise silently:
//   - a foreign app's grant (a waggle channel admit) NOT being recognised → it vanishes from the plane;
//   - Nvoy's OWN data grant being pulled in here → it double-counts against the private index.
// Every recognition assertion is therefore paired with a rejection, and the fixtures use the real
// wire shapes (da-cap/da-scope; a/30440) rather than toy tags.
//
//   node test/capgrants.mjs

import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools'
import { classifyGrant, readCapabilityGrants, buildExternalRevocation, KIND } from '../console/capgrants.mjs'

let n = 0, pass = 0
const t = (name, cond) => { n++; if (cond) { pass++; console.log(`ok - ${name}`) } else console.error(`FAIL - ${name}`) }

const meSk = generateSecretKey(), mePub = getPublicKey(meSk)
const grantee = getPublicKey(generateSecretKey())

const sign = (tmpl, sk = meSk) => finalizeEvent({ created_at: 1000, content: '', ...tmpl }, sk)

// A real waggle channel admit: p + da-scope(hash,salt) + da-cap:admit, no content.
const admit = sign({ kind: 440, tags: [['p', grantee], ['da-scope', 'a'.repeat(64), 'b'.repeat(32)], ['da-cap', 'admit']] })
// A Nvoy data grant shape: an `a` tag at a 30440 data set.
const dataGrant = sign({ kind: 440, tags: [['p', grantee], ['a', `30440:${mePub}:deadbeef`], ['v', '1']] })
// A future app's unknown capability: just a p tag and some app-specific tag.
const unknown = sign({ kind: 440, tags: [['p', grantee], ['x-someapp', 'whatever']] })
// A tasking grant (another cap the classifier should label).
const task = sign({ kind: 440, tags: [['p', grantee], ['da-scope', 'c'.repeat(64), 'd'.repeat(32)], ['da-cap', 'task']] })

// --- classify: recognise foreign capability, do NOT swallow Nvoy's own data ----------------------
t('a waggle channel admit is classified capability', classifyGrant(admit)?.type === 'capability')
t('  …with a human label', classifyGrant(admit)?.label === 'Channel admission')
t('  …and the grantee extracted', classifyGrant(admit)?.grantee === grantee)
t('  …and the cap', classifyGrant(admit)?.cap === 'admit')
t('a tasking grant labels as tasking authority', classifyGrant(task)?.label === 'Tasking authority')
t('an Nvoy DATA grant is typed data (so the caller skips it — no double count)', classifyGrant(dataGrant)?.type === 'data')
t('an unknown future-app grant is surfaced, not dropped', classifyGrant(unknown)?.type === 'other')
t('a 440 with no grantee classifies to null (nothing to show)', classifyGrant(sign({ kind: 440, tags: [] })) === null)

// --- readCapabilityGrants over an in-memory relay: authorship, revocation, both directions -------
const stranger = generateSecretKey()
const forged = sign({ kind: 440, tags: [['p', grantee], ['da-cap', 'admit']] }, stranger) // someone else signed it
const revocation = sign({ kind: KIND.revocation, created_at: 2000, tags: [['e', task.id]] }) // I revoke the tasking grant

const relay = { async query() { return [admit, dataGrant, unknown, task, forged, revocation] } }
const { rows, skippedData, unverified } = await readCapabilityGrants(relay, mePub)

t('the admit appears on the plane', rows.some(r => r.capId === admit.id && r.status === 'active'))
t('the unknown grant appears on the plane', rows.some(r => r.capId === unknown.id))
t('Nvoy\'s own data grant is NOT on this plane', !rows.some(r => r.capId === dataGrant.id))
t('  …but it is counted, not silently dropped', skippedData === 1)
t('a grant signed by someone else is refused (authorship)', !rows.some(r => r.capId === forged.id))
t('the revoked tasking grant shows revoked, not active', rows.find(r => r.capId === task.id)?.status === 'revoked')
t('  …and the still-good admit stays active (both directions)', rows.find(r => r.capId === admit.id)?.status === 'active')
t('rows carry external:true so revoke routes to a 441, not a scope rotation', rows.every(r => r.external === true))
t('rows are in the deriveDelegations shape (agent/scopeName/status present)',
  rows.every(r => 'agent' in r && 'scopeName' in r && 'status' in r && 'scope' in r))

// --- the revocation this plane issues is a plain, honourable 441 ---------------------------------
const rev = buildExternalRevocation(admit.id, 3000)
t('buildExternalRevocation makes a 441 e-tagging the grant', rev.kind === 441 && rev.tags.some(x => x[0] === 'e' && x[1] === admit.id))
t('  …signed, it verifies and names the target', (() => { const s = finalizeEvent(rev, meSk); return verifyEvent(s) && s.tags[0][1] === admit.id })())

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
