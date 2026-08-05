import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { verifyChannelDataCarry } from '../mcp/tools/channel_task_carry.mjs'
import { partitionInboxMessages } from '../mcp/tools/inbox_trust.mjs'

let pass = 0, fail = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? pass++ : fail++ }
const authorSk = generateSecretKey(), author = getPublicKey(authorSk)
const carrier = getPublicKey(generateSecretKey())
const channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const source = JSON.parse(JSON.stringify(finalizeEvent({ kind: 9, created_at: 1785870000,
  tags: [['h', channel]], content: '@codex review: the retry boundary is sound' }, authorSk)))
const carry = { v: 1, type: 'waggle-channel-task-carry', channel, reason: 'mention', source }
const wire = value => ({ from: carrier, at: source.created_at + 1, content: JSON.stringify(value) })
const verify = value => verifyChannelDataCarry(wire(value), { channels: [channel], carriers: [carrier] })

const accepted = verify(carry)
ok('verified-data view attributes content to the signed source rather than the carrier',
  accepted?.message.from === author && accepted?.message.content === source.content)
ok('verified-data provenance records carrier, source id, and signed channel without granting task authority',
  accepted?.provenance.carrier === carrier && accepted?.provenance.source_event === source.id &&
  accepted?.provenance.source_channel === channel && !('grant_id' in accepted.provenance))
ok('a foreign carrier is refused', !verifyChannelDataCarry(wire(carry), { channels: [channel], carriers: [getPublicKey(generateSecretKey())] }))
ok('a foreign channel is refused', !verifyChannelDataCarry(wire(carry), { channels: ['ffffffff-ffff-ffff-ffff-ffffffffffff'], carriers: [carrier] }))
ok('tampering signed content is refused', !verify({ ...carry, source: { ...source, content: source.content + ' changed' } }))
const wrongChannelSource = JSON.parse(JSON.stringify(finalizeEvent({ kind: 9, created_at: source.created_at,
  tags: [['h', 'ffffffff-ffff-ffff-ffff-ffffffffffff']], content: source.content }, authorSk)))
ok('a valid source signed for another channel cannot be relabelled by the carrier', !verify({ ...carry, source: wrongChannelSource }))
ok('unknown carry fields are refused', !verify({ ...carry, authority: 'task' }))

const malformedCarrier = wire({ ...carry, source: { ...source, content: source.content + ' forged' } })
const rejectedCarryFallback = verifyChannelDataCarry(malformedCarrier, { channels: [channel], carriers: [carrier] })?.message || malformedCarrier
const overlap = partitionInboxMessages([rejectedCarryFallback], {
  trusted: { [carrier]: 'waggle' }, carriers: [carrier],
})
ok('a configured carrier can never regain direct authority through trusted-senders overlap',
  rejectedCarryFallback === malformedCarrier && overlap.trustedDirect.length === 0 &&
  overlap.rejectedCarrier[0] === malformedCarrier)
const direct = { from: author, at: source.created_at, content: 'operator direct message' }
const directPartition = partitionInboxMessages([direct], { trusted: { [author]: 'operator' }, carriers: [carrier] })
ok('a non-carrier trusted sender remains in the explicit direct partition',
  directPartition.trustedDirect[0] === direct && directPartition.rejectedCarrier.length === 0)

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
