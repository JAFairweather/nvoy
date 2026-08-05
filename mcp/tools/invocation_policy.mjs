// Pure, default-closed invocation policy shared by the live attention reader and its threat
// matrix. Chat membership is deliberately absent: it permits participation in a community, not
// instruction of an agent. A direct task grant, or both an author task grant and carrier
// task-relay grant for a configured channel, is required to promote bytes to instruction.

import { verifyEvent } from 'nostr-tools/pure'
import { verifyChannelDataCarry, verifyChannelTaskCarry } from './channel_task_carry.mjs'

export function authenticatedNip59Rumor(seal, rumor, verify = verifyEvent) {
  if (!seal || seal.kind !== 13 || !rumor || rumor.kind !== 14 || rumor.pubkey !== seal.pubkey) return false
  try { return verify(JSON.parse(JSON.stringify(seal))) } catch { return false }
}

export function partitionInvocations(messages, {
  policyUsable = false,
  taskGrantFor = () => null,
  relayGrantFor = () => null,
  carrierChannels = () => [],
} = {}) {
  const admitted = []
  const admittedRaw = new Set()
  if (policyUsable) for (const message of messages || []) {
    const carried = verifyChannelTaskCarry(message, {
      channels: carrierChannels(message.from),
      carrierGrant: relayGrantFor(message.from),
      taskGrantFor,
    })
    const direct = taskGrantFor(message.from)
    if (carried) admitted.push(carried)
    else if (direct && ['task', 'task+act'].includes(direct.cap)) admitted.push({ message, admission: {
      mode: 'direct', from: message.from, grant_id: direct.grantId,
      grantor: direct.grantor, cap: direct.cap,
    } })
    else continue
    admittedRaw.add(message)
  }
  return {
    admitted,
    actionable: admitted.map(item => item.message),
    admissions: admitted.map(item => item.admission),
    dataOnly: (messages || []).filter(message => !admittedRaw.has(message)),
  }
}

export function verifiedChannelNotifications(messages, {
  policyUsable = false,
  relayGrantFor = () => null,
  carrierChannels = () => [],
} = {}) {
  if (!policyUsable) return []
  const out = []
  for (const raw of messages || []) {
    const carrierGrant = relayGrantFor(raw.from)
    if (!carrierGrant || carrierGrant.cap !== 'task-relay') continue
    const verified = verifyChannelDataCarry(raw, { channels: carrierChannels(raw.from), carriers: [raw.from] })
    if (!verified) continue
    out.push({ source_author: verified.message.from, source_event: verified.message.event_id,
      source_channel: verified.provenance.source_channel, carrier: verified.provenance.carrier,
      carrier_grant_id: carrierGrant.grantId, carrier_grantor: carrierGrant.grantor,
      reason: verified.provenance.reason, observed_at: verified.message.at })
  }
  return out
}
