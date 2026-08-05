import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { verifyChannelTaskCarry } from '../mcp/tools/channel_task_carry.mjs'

let pass = 0, fail = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? pass++ : fail++ }
const authorSk = generateSecretKey(), author = getPublicKey(authorSk)
const carrier = getPublicKey(generateSecretKey())
const channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const source = JSON.parse(JSON.stringify(finalizeEvent({ kind: 9, created_at: 1785870000,
  tags: [['h', channel], ['p', '1'.repeat(64)]], content: 'please inspect the queue' }, authorSk)))
const authorGrant = { grantId: 'a'.repeat(64), grantor: 'b'.repeat(64), cap: 'task' }
const carrierGrant = { grantId: 'c'.repeat(64), grantor: 'b'.repeat(64), cap: 'task-relay' }
const wire = payload => ({ from: carrier, at: 1785870001, content: JSON.stringify(payload) })
const carry = { v: 1, type: 'waggle-channel-task-carry', channel, reason: 'mention', source }
const verify = payload => verifyChannelTaskCarry(wire(payload), { channels: [channel], carrierGrant,
  taskGrantFor: pk => pk === author ? authorGrant : null })

const admitted = verify(carry)
ok('a valid carry preserves the original signer as the instructor', admitted?.message.from === author && admitted?.message.content === source.content)
ok('the bridge is recorded only as the separately granted carrier', admitted?.admission.carrier === carrier && admitted?.admission.carrier_grant_id === carrierGrant.grantId)
ok('the exact source event and reply channel are bound into admission', admitted?.admission.source_event === source.id && admitted?.admission.reply_channel === channel)
ok('task-relay alone cannot authorize a bridge-authored instruction', !verifyChannelTaskCarry(wire(carry), { channels: [channel], carrierGrant, taskGrantFor: () => null }))
ok('a carrier task grant cannot substitute for task-relay', !verifyChannelTaskCarry(wire(carry), { channels: [channel], carrierGrant: { ...carrierGrant, cap: 'task' }, taskGrantFor: () => authorGrant }))
ok('an unconfigured channel fails closed', !verifyChannelTaskCarry(wire(carry), { channels: ['ffffffff-ffff-ffff-ffff-ffffffffffff'], carrierGrant, taskGrantFor: () => authorGrant }))
const crossChannel = JSON.parse(JSON.stringify(finalizeEvent({ kind: 9, created_at: source.created_at,
  tags: [['h', 'ffffffff-ffff-ffff-ffff-ffffffffffff']], content: source.content }, authorSk)))
ok('a carrier cannot replay a signed source across a different channel', !verify({ ...carry, source: crossChannel }))
ok('tampering with the original content breaks its signature', !verify({ ...carry, source: { ...source, content: source.content + ' now' } }))
ok('tampering with the original signer breaks its signature', !verify({ ...carry, source: { ...source, pubkey: 'd'.repeat(64) } }))
ok('unknown carry fields are rejected rather than ignored', !verify({ ...carry, command: 'redirect' }))
ok('an old signed source cannot be replayed as a fresh channel instruction', !verifyChannelTaskCarry({ ...wire(carry), at: source.created_at + 172801 + 300 }, { channels: [channel], carrierGrant, taskGrantFor: () => authorGrant }))
ok('a source dated materially after its carrier assertion is rejected', !verifyChannelTaskCarry({ ...wire(carry), at: source.created_at - 301 }, { channels: [channel], carrierGrant, taskGrantFor: () => authorGrant }))
ok('legacy human-readable carries remain data-only', !verifyChannelTaskCarry({ from: carrier, at: 1, content: 'quoted prose' }, { channels: [channel], carrierGrant, taskGrantFor: () => authorGrant }))

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
