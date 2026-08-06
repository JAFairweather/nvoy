import assert from 'node:assert'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools'
import { readHeldCapabilities } from '../mcp/dist/capabilities.js'

const wire = event => JSON.parse(JSON.stringify(event))
const subject = getPublicKey(generateSecretKey())
const grantorSk = generateSecretKey()
const outsiderSk = generateSecretKey()
const now = 2_000
const grant = (cap, created_at, extra = []) => wire(finalizeEvent({
  kind: 440, created_at, content: '',
  tags: [['p', subject], ['da-scope', String(cap).padEnd(64, 'a').slice(0, 64), '11'.repeat(16)], ['da-cap', cap], ...extra],
}, grantorSk))
const revokedGrant = grant('admit', 1_000)
const activeGrant = grant('future-app-cap', 1_001)
const expiredGrant = grant('task', 1_002, [['expiration', '1999']])
const malformed = wire(finalizeEvent({ kind: 440, created_at: 1_003, content: '', tags: [['p', subject]] }, grantorSk))
const revoke = wire(finalizeEvent({ kind: 441, created_at: 1_010, content: '', tags: [['e', revokedGrant.id]] }, grantorSk))
const forgedRevoke = wire(finalizeEvent({ kind: 441, created_at: 1_011, content: '', tags: [['e', activeGrant.id]] }, outsiderSk))

let pass = 0
const ok = (name, fn) => { fn(); pass++; console.log(`ok   — ${name}`) }
const query = async (url, filter) => {
  if (url === 'wss://silent.example') throw new Error('no EOSE')
  if (filter.kinds.includes(440)) return [revokedGrant, activeGrant, expiredGrant, malformed]
  return [revoke, forgedRevoke]
}

const read = await readHeldCapabilities(['wss://one.example', 'wss://two.example'], subject, query, now)
ok('relay coverage reports completed EOSE reads rather than configured URLs', () => {
  assert.equal(read.verification.configured_relays, 2)
  assert.equal(read.verification.grant_query_answered, 2)
  assert.equal(read.verification.revocation_query_answered, 2)
})
ok('a same-author 441 revokes exactly its grant', () => {
  assert.equal(read.capabilities.find(row => row.grant_id === revokedGrant.id).status, 'revoked')
  assert.equal(read.capabilities.find(row => row.grant_id === revokedGrant.id).revocation_id, revoke.id)
})
ok('a foreign signer cannot revoke another grantor capability', () => {
  assert.equal(read.capabilities.find(row => row.grant_id === activeGrant.id).status, 'active')
})
ok('unknown future capabilities remain visible and human-readable', () => {
  const row = read.capabilities.find(row => row.grant_id === activeGrant.id)
  assert.equal(row.cap, 'future-app-cap')
  assert.equal(row.label, 'Capability: future-app-cap')
})
ok('expiration is reported independently of revocation', () => {
  assert.equal(read.capabilities.find(row => row.grant_id === expiredGrant.id).status, 'expired')
})
ok('a public 440 without one da-cap is not invented into authority', () => {
  assert.equal(read.capabilities.some(row => row.grant_id === malformed.id), false)
})

const silent = await readHeldCapabilities(['wss://silent.example'], subject, query, now)
ok('zero answering relays returns null, never the false claim of an empty list', () => {
  assert.equal(silent.capabilities, null)
  assert.equal(silent.verification.status, 'unverifiable')
})

const empty = await readHeldCapabilities(['wss://one.example'], subject, async () => [], now)
ok('complete configured coverage with no verified grant produces an affirmative empty', () => {
  assert.deepEqual(empty.capabilities, [])
  assert.equal(empty.verification.status, 'verified')
})

const partialEmpty = await readHeldCapabilities(['wss://one.example', 'wss://silent.example'], subject, async (url) => {
  if (url.includes('silent')) throw new Error('no EOSE')
  return []
}, now)
ok('partial grant coverage can never produce a verified absence', () => {
  assert.equal(partialEmpty.capabilities, null)
  assert.equal(partialEmpty.verification.status, 'unverifiable')
  assert.equal(partialEmpty.verification.grant_query_answered, 1)
})

const partialGrant = await readHeldCapabilities(['wss://one.example', 'wss://silent.example'], subject, async (url, filter) => {
  if (url.includes('silent')) throw new Error('no EOSE')
  return filter.kinds.includes(440) ? [activeGrant] : []
}, now)
ok('positive grant evidence remains visible under partial coverage but is never called active', () => {
  assert.equal(partialGrant.verification.status, 'unverifiable')
  assert.equal(partialGrant.capabilities[0].grant_id, activeGrant.id)
  assert.equal(partialGrant.capabilities[0].status, 'unverifiable')
})

const noRevocations = await readHeldCapabilities(['wss://one.example'], subject, async (_url, filter) => {
  if (filter.kinds.includes(440)) return [activeGrant]
  throw new Error('revocation lane unavailable')
}, now)
ok('a failed revocation read never reports a capability as active', () => {
  assert.equal(noRevocations.verification.status, 'unverifiable')
  assert.equal(noRevocations.capabilities[0].status, 'unverifiable')
})

const partialRevocations = await readHeldCapabilities(['wss://one.example', 'wss://silent.example'], subject, async (url, filter) => {
  if (filter.kinds.includes(440)) return [activeGrant]
  if (url.includes('silent')) throw new Error('no revocation EOSE')
  return []
}, now)
ok('one complete revocation query cannot stand in for the configured relay set', () => {
  assert.equal(partialRevocations.verification.revocation_query_answered, 1)
  assert.equal(partialRevocations.verification.status, 'unverifiable')
  assert.equal(partialRevocations.capabilities[0].status, 'unverifiable')
})

console.log(`\n${pass}/${pass} passed`)
