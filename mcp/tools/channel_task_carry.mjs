// Pure verifier for the encrypted Waggle channel-carry contract. The bridge is transport, never
// the instructor: admission succeeds only when the carrier and the embedded original signer have
// separate, live grants supplied by the caller's present-tense policy evaluation.

import { verifyEvent } from 'nostr-tools/pure'

const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function parseChannelCarry(message, { channels = [], carriers = null, verify = verifyEvent } = {}) {
  if (!message || !HEX64.test(String(message.from || ''))) return null
  const carrier = String(message.from).toLowerCase()
  if (carriers) {
    const allowedCarriers = new Set(carriers.map(value => String(value || '').toLowerCase()).filter(value => HEX64.test(value)))
    if (!allowedCarriers.has(carrier)) return null
  }
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
      !HEX64.test(String(source.pubkey || '')) || !HEX64.test(String(source.id || '')) ||
      !HEX128.test(String(source.sig || '')) || !Array.isArray(source.tags) ||
      !source.tags.every(tag => Array.isArray(tag) && tag.every(value => typeof value === 'string'))) return null
  // The carrier cannot choose a different logical channel for a signed source. Kind:9 channel
  // messages bind themselves with exactly one h tag; accepting the carrier's field alone would
  // let a compromised transport replay signed text across an otherwise-authorized channel edge.
  const channelTags = source.tags.filter(tag => tag[0] === 'h')
  if (channelTags.length !== 1 || String(channelTags[0][1] || '').toLowerCase() !== channel) return null
  // The scan has a 48h restart-heal window. Bind the original event to the carrier rumor's time so
  // an otherwise-valid old channel post cannot be replayed years later as a fresh instruction.
  const sourceAt = Number(source.created_at), carriedAt = Number(message.at)
  if (!Number.isInteger(sourceAt) || !Number.isFinite(carriedAt) || sourceAt > carriedAt + 300 || carriedAt - sourceAt > 172800 + 300) return null
  let verified = false
  // Force wire form before verification. nostr-tools may otherwise trust an in-memory symbol left
  // by finalizeEvent, which is not evidence that the bytes received over the relay verify.
  try { verified = verify(JSON.parse(JSON.stringify(source))) } catch { verified = false }
  if (!verified) return null
  return { carry, source, carrier, channel }
}

// Does this message CLAIM to be a channel carry at all?
//
// `verifyChannelDataCarry` returning null answers two very different questions with the
// same value: "this carry failed verification" and "this was never a carry." A
// configured carrier sends both — a malformed carry, and its own ordinary notices (a
// delivery receipt, a reply relayed back out of the community). Collapsing them makes a
// reader call a `{"ok":true}` receipt a rejected carry, which is a false verdict about
// the reader's own mail.
//
// Deliberately shallow: only the envelope's self-declared `type`. Anything deeper would
// start re-deciding validity, which is `parseChannelCarry`'s job — this asks only what
// the sender was attempting, so that a failure can be described honestly.
export function claimsChannelCarry(message) {
  try {
    const body = JSON.parse(message?.content ?? '')
    return !!body && typeof body === 'object' && !Array.isArray(body) &&
      body.type === 'waggle-channel-task-carry'
  } catch { return false }
}

// A cryptographically verified channel item without instruction authority. This is for readers
// and review surfaces: it proves who signed the words and which channel they signed them in, but
// deliberately does not claim a live task grant or make the content actionable.
export function verifyChannelDataCarry(message, { channels = [], carriers = [], verify = verifyEvent } = {}) {
  const parsed = parseChannelCarry(message, { channels, carriers, verify })
  if (!parsed) return null
  const { carry, source, carrier, channel } = parsed
  return {
    message: { from: source.pubkey, at: source.created_at, content: source.content, event_id: source.id, kind: source.kind },
    provenance: { mode: 'verified-channel-data', carrier, source_event: source.id,
      source_channel: channel, reason: carry.reason },
  }
}

export function verifyChannelTaskCarry(message, { channels = [], carrierGrant = null, taskGrantFor = () => null, verify = verifyEvent } = {}) {
  if (!carrierGrant || carrierGrant.cap !== 'task-relay') return null
  const parsed = parseChannelCarry(message, { channels, verify })
  if (!parsed) return null
  const { source, carrier, channel } = parsed
  const authorGrant = taskGrantFor(source.pubkey)
  if (!authorGrant || !['task', 'task+act'].includes(authorGrant.cap)) return null
  return {
    message: { from: source.pubkey, at: source.created_at, content: source.content, event_id: source.id, kind: source.kind },
    admission: { mode: 'channel-carry', from: source.pubkey, grant_id: authorGrant.grantId,
      grantor: authorGrant.grantor, cap: authorGrant.cap, carrier,
      carrier_grant_id: carrierGrant.grantId, carrier_grantor: carrierGrant.grantor,
      source_event: source.id, reply_channel: channel },
  }
}
