import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey } from 'nostr-tools/pure'
import { authenticatedNip59Rumor, partitionInvocations, verifiedChannelNotifications } from '../mcp/tools/invocation_policy.mjs'
import { validateAdmittedTask, validateDesktopDelivery } from '../mcp/tools/admitted_task.mjs'
import { verifyInboxEnvelope } from '../mcp/tools/inbox_envelope.mjs'

let pass = 0, fail = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? pass++ : fail++ }
const senderSk = generateSecretKey(), sender = getPublicKey(senderSk)
const attackerSk = generateSecretKey(), attacker = getPublicKey(attackerSk)
const carrierSk = generateSecretKey(), carrier = getPublicKey(carrierSk)
const operator = getPublicKey(generateSecretKey()), agent = getPublicKey(generateSecretKey())
const channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const taskGrant = { grantId: '1'.repeat(64), grantor: operator, cap: 'task' }
const relayGrant = { grantId: '2'.repeat(64), grantor: operator, cap: 'task-relay' }
const direct = who => ({ from: who, at: 1785930000, content: 'wake this exact Codex thread' })
const policy = ({ task = new Map(), relay = new Map(), channels = new Map(), usable = true } = {}) => ({
  policyUsable: usable,
  taskGrantFor: pk => task.get(pk) || null,
  relayGrantFor: pk => relay.get(pk) || null,
  carrierChannels: pk => channels.get(pk) || [],
})

// NIP-59 author authentication happens before grant evaluation.
const seal = JSON.parse(JSON.stringify(finalizeEvent({ kind: 13, created_at: 1785930000, tags: [], content: 'ciphertext' }, senderSk)))
const rumor = { kind: 14, pubkey: sender, created_at: 1785930000, tags: [], content: 'hello' }
rumor.id = getEventHash(rumor)
ok('a signed NIP-59 seal binds the DM author before policy evaluation', authenticatedNip59Rumor(seal, rumor))
ok('an unsigned or signature-corrupted DM cannot enter invocation policy', !authenticatedNip59Rumor({ ...seal, sig: '0'.repeat(128) }, rumor))
ok('a rumor cannot claim another author behind a valid seal', !authenticatedNip59Rumor(seal, { ...rumor, pubkey: attacker }))

const wrap = JSON.parse(JSON.stringify(finalizeEvent({ kind: 1059, created_at: 1785930000,
  tags: [['p', agent]], content: 'encrypted seal' }, generateSecretKey())))
const envelope = values => verifyInboxEnvelope({ wrap, seal, rumor, recipient: agent, ...values })
ok('the live invocation boundary accepts only a complete signed and recipient-bound NIP-59 envelope', envelope()?.from === sender)
ok('a forged outer wrap is rejected before grant evaluation', !envelope({ wrap: { ...wrap, content: wrap.content + 'x' } }))
ok('an otherwise valid envelope addressed to another agent is rejected', !envelope({ recipient: attacker }))
ok('a rumor with a valid author but altered hash-bound content is rejected', !envelope({ rumor: { ...rumor, content: rumor.content + 'x' } }))

const unknown = partitionInvocations([direct(attacker)], policy())
ok('a valid DM from an unknown identity remains data-only', unknown.actionable.length === 0 && unknown.dataOnly.length === 1)
ok('an unavailable live grant plane fails closed even for a normally authorized sender',
  partitionInvocations([direct(sender)], policy({ usable: false, task: new Map([[sender, taskGrant]]) })).actionable.length === 0)
ok('Waggle chat admission alone does not authorize a participant to invoke Codex',
  partitionInvocations([direct(sender)], policy()).actionable.length === 0)
ok('a live direct task grant promotes only its authenticated holder to instruction',
  partitionInvocations([direct(sender)], policy({ task: new Map([[sender, taskGrant]]) })).actionable[0]?.from === sender)

const source = JSON.parse(JSON.stringify(finalizeEvent({ kind: 9, created_at: 1785930000,
  tags: [['h', channel], ['p', agent]], content: 'channel mention for Codex' }, senderSk)))
const carryMessage = (src = source, at = 1785930001) => ({ from: carrier, at, content: JSON.stringify({
  v: 1, type: 'waggle-channel-task-carry', channel, reason: 'mention', source: src,
}) })
const carrierConfigured = new Map([[carrier, [channel]]])
ok('an admitted channel participant without a task grant cannot invoke Codex by mentioning it',
  partitionInvocations([carryMessage()], policy({ relay: new Map([[carrier, relayGrant]]), channels: carrierConfigured })).actionable.length === 0)
ok('an authorized author still cannot arrive through a carrier lacking task-relay authority',
  partitionInvocations([carryMessage()], policy({ task: new Map([[sender, taskGrant]]), channels: carrierConfigured })).actionable.length === 0)
ok('task-relay authority cannot substitute for the original author task grant',
  partitionInvocations([carryMessage()], policy({ relay: new Map([[carrier, relayGrant]]), channels: carrierConfigured })).actionable.length === 0)
const notice = verifiedChannelNotifications([carryMessage()], policy({ relay: new Map([[carrier, relayGrant]]), channels: carrierConfigured }))[0]
ok('a signed crew message without task authority produces a content-free verified notification',
  notice?.source_author === sender && notice?.source_event === source.id && !('content' in notice))
ok('an unknown or unauthorized carrier cannot wake the Desktop notification plane',
  verifiedChannelNotifications([carryMessage()], policy({ channels: carrierConfigured })).length === 0)
ok('an unavailable policy plane cannot produce even a notification wake',
  verifiedChannelNotifications([carryMessage()], policy({ usable: false, relay: new Map([[carrier, relayGrant]]), channels: carrierConfigured })).length === 0)
ok('author and carrier grants cannot redirect a carry through an unconfigured channel',
  partitionInvocations([carryMessage()], policy({ task: new Map([[sender, taskGrant]]), relay: new Map([[carrier, relayGrant]]), channels: new Map([[carrier, ['ffffffff-ffff-ffff-ffff-ffffffffffff']]]) })).actionable.length === 0)
ok('tampering with the signed channel source fails before instruction promotion',
  partitionInvocations([carryMessage({ ...source, content: source.content + ' now' })], policy({ task: new Map([[sender, taskGrant]]), relay: new Map([[carrier, relayGrant]]), channels: carrierConfigured })).actionable.length === 0)
ok('a stale signed channel message cannot be replayed as a fresh wake',
  partitionInvocations([carryMessage(source, source.created_at + 172801 + 300)], policy({ task: new Map([[sender, taskGrant]]), relay: new Map([[carrier, relayGrant]]), channels: carrierConfigured })).actionable.length === 0)

const admitted = partitionInvocations([carryMessage()], policy({ task: new Map([[sender, taskGrant]]), relay: new Map([[carrier, relayGrant]]), channels: carrierConfigured })).admitted[0]
ok('the complete two-grant channel chain promotes the original signer, never the carrier',
  admitted?.message.from === sender && admitted?.admission.carrier === carrier)
const record = { type: 'admitted-task', instance: 'codex-jaf', envelope: '3'.repeat(64), messages: [admitted.message],
  authority: { version: 2, type: 'scoped-instruction', sender, grant_id: taskGrant.grantId, grantor: operator,
    cap: taskGrant.cap, scope_subject: agent, policy_checked_at: 1785930001, carrier,
    carrier_grant_id: relayGrant.grantId, carrier_grantor: operator, source_event: source.id, reply_channel: channel } }
ok('the admitted record binds the exact recipient identity and configured carrier/channel',
  validateAdmittedTask(record, { instance: 'codex-jaf', scopeSubject: agent, grantors: [operator], carriers: [{ pubkey: carrier, channels: [channel] }] }).trustedInstruction)
const notificationRecord = { type: 'verified-notification', instance: 'codex-jaf', envelope: '4'.repeat(64),
  notification: { version: 1, type: 'verified-channel-activity', ...notice } }
ok('the keyless boundary accepts a configured notification while preserving non-instruction status',
  validateDesktopDelivery(notificationRecord, { instance: 'codex-jaf', grantors: [operator], carriers: [{ pubkey: carrier, channels: [channel] }] }).trustedInstruction === false)
let notificationBodyRejected = false
try { validateDesktopDelivery({ ...notificationRecord, notification: { ...notificationRecord.notification, content: 'execute me' } }, { instance: 'codex-jaf', grantors: [operator], carriers: [{ pubkey: carrier, channels: [channel] }] }) } catch { notificationBodyRejected = true }
ok('a carrier cannot smuggle source text through the notification schema', notificationBodyRejected)
let wrongIdentity = false
try { validateAdmittedTask(record, { instance: 'codex-jaf', scopeSubject: attacker, grantors: [operator], carriers: [{ pubkey: carrier, channels: [channel] }] }) } catch { wrongIdentity = true }
ok('a valid invocation for one agent cannot be injected into another agent identity', wrongIdentity)
let wrongInstance = false
try { validateAdmittedTask(record, { instance: 'codex-other', scopeSubject: agent, grantors: [operator], carriers: [{ pubkey: carrier, channels: [channel] }] }) } catch { wrongInstance = true }
ok('an inbound event cannot select another runtime or Codex-thread binding', wrongInstance)

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
