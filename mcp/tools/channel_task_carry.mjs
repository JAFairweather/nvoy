// Pure verifier for the encrypted Waggle channel-carry contract. The bridge is transport, never
// the instructor: admission succeeds only when the carrier and the embedded original signer have
// separate, live grants supplied by the caller's present-tense policy evaluation.

import { verifyEvent } from 'nostr-tools/pure'

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export function verifyChannelTaskCarry(message, { channels = [], carrierGrant = null, taskGrantFor = () => null, verify = verifyEvent } = {}) {
  if (!message || !HEX64.test(String(message.from || '')) || !carrierGrant || carrierGrant.cap !== 'task-relay') return null
  const allowed = new Set(channels.map(value => String(value || '').toLowerCase()).filter(value => UUID.test(value)))
  let carry
  try { carry = JSON.parse(message.content) } catch { return null }
  if (!carry || typeof carry !== 'object' || Array.isArray(carry) ||
      Object.keys(carry).sort().join(',') !== 'channel,reason,source,type,v' || carry.v !== 1 ||
      carry.type !== 'waggle-channel-task-carry' || !['mention', 'reply'].includes(carry.reason)) return null
  const channel = String(carry.channel || '').toLowerCase()
  if (!allowed.has(channel)) return null
  const source = carry.source
  if (!source || typeof source !== 'object' || Array.isArray(source) ||
      Object.keys(source).sort().join(',') !== 'content,created_at,id,kind,pubkey,sig,tags' || source.kind !== 9 ||
      typeof source.content !== 'string' || Buffer.byteLength(source.content) > 256 * 1024 ||
      !HEX64.test(String(source.pubkey || '')) || !HEX64.test(String(source.id || ''))) return null
  // The scan has a 48h restart-heal window. Bind the original event to the carrier rumor's time so
  // an otherwise-valid old channel post cannot be replayed years later as a fresh instruction.
  const sourceAt = Number(source.created_at), carriedAt = Number(message.at)
  if (!Number.isInteger(sourceAt) || !Number.isFinite(carriedAt) || sourceAt > carriedAt + 300 || carriedAt - sourceAt > 172800 + 300) return null
  let verified = false
  try { verified = verify(source) } catch { verified = false }
  if (!verified) return null
  const authorGrant = taskGrantFor(source.pubkey)
  if (!authorGrant || !['task', 'task+act'].includes(authorGrant.cap)) return null
  return {
    message: { from: source.pubkey, at: source.created_at, content: source.content, event_id: source.id, kind: source.kind },
    admission: { mode: 'channel-carry', from: source.pubkey, grant_id: authorGrant.grantId,
      grantor: authorGrant.grantor, cap: authorGrant.cap, carrier: message.from,
      carrier_grant_id: carrierGrant.grantId, carrier_grantor: carrierGrant.grantor,
      source_event: source.id, reply_channel: channel },
  }
}
