import assert from 'node:assert/strict'
import { generateSecretKey, getEventHash, getPublicKey, finalizeEvent } from 'nostr-tools/pure'
import { approvalBody, approvalTemplate, approvalUrl, verifyOutboundApproval } from '../mcp/tools/outbound_approval.mjs'
import { validateOutboundRecord } from '../mcp/tools/outbound_record.mjs'

let total = 0, passed = 0
const test = (name, fn) => {
  total++
  try { fn(); passed++; console.log(`ok   — ${name}`) }
  catch (error) { console.error(`FAIL — ${name}\n  ${error.stack || error}`) }
}
const sk = generateSecretKey(), approver = getPublicKey(sk)
const foreignSk = generateSecretKey(), foreignApprover = getPublicKey(foreignSk)
const instance = 'codex-jaf', proposalId = 'a'.repeat(32), fingerprint = 'b'.repeat(64)
const nowMs = 1_800_000_000_000
const signed = finalizeEvent(approvalTemplate({ approver, instance, proposalId, fingerprint, createdAt: nowMs / 1000 }), sk)
const verify = event => verifyOutboundApproval(JSON.parse(JSON.stringify(event)), { instance, proposalId, fingerprint, approvers: [approver], nowMs })

test('canonical body and URL bind one proposal and frozen fingerprint', () => {
  assert.equal(approvalUrl(instance, proposalId), `nvoy://outbound/${instance}/${proposalId}`)
  assert.equal(approvalBody(proposalId, fingerprint), JSON.stringify({ proposal_id: proposalId, fingerprint, verb: 'approve' }))
})
test('one fresh exact Director signature opens the approval boundary', () => assert.equal(verify(signed).eventId, signed.id))
test('a frozen unsigned seal is durable proposal state, never publication evidence', () => {
  const seal = { pubkey: 'c'.repeat(64), created_at: 1, kind: 13, tags: [], content: 'ciphertext' }
  const record = { version: 2, request_digest: 'd'.repeat(64), request_id: proposalId,
    fingerprint: getEventHash(seal), unsigned_seal: seal, wrap: null, published: false }
  assert.equal(validateOutboundRecord(record, { requestId: proposalId }).published, false)
  assert.throws(() => validateOutboundRecord({ ...record, published: true }), /claims enactment/)
  assert.throws(() => validateOutboundRecord({ ...record, unsigned_seal: { ...seal, extra: true } }), /exact frozen/)
})
for (const [name, mutate, pattern] of [
  ['foreign signer', () => finalizeEvent(approvalTemplate({ approver: foreignApprover, instance, proposalId, fingerprint, createdAt: nowMs / 1000 }), foreignSk), /authorized approver/],
  ['wrong instance', event => event, /exact approval body/],
  ['wrong proposal', event => event, /exact approval body/],
  ['wrong fingerprint', event => event, /exact approval body/],
  ['stale event', event => event, /stale/],
  ['future event', event => event, /future/],
  ['mutated payload', event => ({ ...event, tags: event.tags.map(tag => tag[0] === 'payload' ? ['payload', '0'.repeat(64)] : tag) }), /exact approval body|signature/],
  ['duplicate tag', event => ({ ...event, tags: [...event.tags, event.tags[0]] }), /tag schema/],
  ['extra event field', event => ({ ...event, approval: true }), /schema is not closed/],
]) test(`${name} fails closed`, () => {
  const event = mutate(JSON.parse(JSON.stringify(signed)))
  const options = { instance, proposalId, fingerprint, approvers: [approver], nowMs }
  if (name === 'wrong instance') options.instance = 'claude-jaf'
  if (name === 'wrong proposal') options.proposalId = 'c'.repeat(32)
  if (name === 'wrong fingerprint') options.fingerprint = 'd'.repeat(64)
  if (name === 'stale event') options.nowMs += 301_000
  if (name === 'future event') options.nowMs -= 31_000
  assert.throws(() => verifyOutboundApproval(event, options), pattern)
})

console.log(`\n${passed}/${total} passed`)
process.exit(passed === total ? 0 : 1)
