import assert from 'node:assert/strict'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { relayAttestation } from '../mcp/tools/relay_attestation.mjs'
import { validateAdmittedTask } from '../mcp/tools/admitted_task.mjs'

const sourceSk = generateSecretKey(), sourcePk = getPublicKey(sourceSk)
const bridgePk = getPublicKey(generateSecretKey())
const source = JSON.parse(JSON.stringify(finalizeEvent({ kind: 9, created_at: 1234,
  tags: [['h', 'a8186b53-537d-46ad-a7e7-b6486c58970e']], content: 'signed channel instruction' }, sourceSk)))
const encoded = Buffer.from(JSON.stringify(source)).toString('base64url')
const rumor = { tags: [['p', 'f'.repeat(64)], ['waggle-source', encoded]], content: 'bridge quotation' }

const valid = relayAttestation(rumor, bridgePk, [bridgePk])
assert.equal(valid.present, true)
assert.deepEqual(valid.message, { from: sourcePk, transport_from: bridgePk, at: 1234,
  content: 'signed channel instruction', event_id: source.id, kind: 9,
  relay_channel: 'a8186b53-537d-46ad-a7e7-b6486c58970e' })

assert.equal(relayAttestation(rumor, bridgePk, []).message, null, 'an unconfigured transport cannot attest')
assert.equal(relayAttestation({ tags: [...rumor.tags, ['waggle-source', encoded]] }, bridgePk, [bridgePk]).message, null, 'ambiguous source tags fail closed')
const forged = { ...source, content: 'forged instruction' }
assert.equal(relayAttestation({ tags: [['waggle-source', Buffer.from(JSON.stringify(forged)).toString('base64url')]] }, bridgePk, [bridgePk]).message, null, 'source signature is independently verified')
assert.equal(relayAttestation({ tags: [] }, bridgePk, [bridgePk]).present, false, 'ordinary direct DMs remain ordinary')
const noChannel = JSON.parse(JSON.stringify(finalizeEvent({ kind: 9, created_at: 1234, tags: [], content: 'no reply route' }, sourceSk)))
assert.equal(relayAttestation({ tags: [['waggle-source', Buffer.from(JSON.stringify(noChannel)).toString('base64url')]] }, bridgePk, [bridgePk]).message, null,
  'a channel carry without one signed reply destination fails closed')

const packet = { type: 'admitted-task', instance: 'codex-test', envelope: 'e'.repeat(64),
  authority: { version: 1, type: 'scoped-instruction', sender: sourcePk, grant_id: 'd'.repeat(64),
    grantor: 'c'.repeat(64), cap: 'task', scope_subject: 'b'.repeat(64), policy_checked_at: 1 },
  messages: [valid.message] }
assert.equal(validateAdmittedTask(packet, { instance: 'codex-test', scopeSubject: 'b'.repeat(64), grantors: ['c'.repeat(64)] }).trustedInstruction, true)
assert.throws(() => validateAdmittedTask({ ...packet, authority: { ...packet.authority, sender: bridgePk } },
  { instance: 'codex-test', scopeSubject: 'b'.repeat(64), grantors: ['c'.repeat(64)] }), /invalid admitted authority/,
'the bridge transport can never replace the original tasking signer')

console.log('relay-attestation: signed source, fixed transport, scoped authority PASS')
