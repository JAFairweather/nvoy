// A bridge-carried channel event is useful only if the receiving runtime can prove the original
// signer. The outer NIP-17 sender is transport; this verifier recovers the signed source event
// from the encrypted rumor and never promotes bridge-authored quotation into human authority.

import { verifyEvent } from 'nostr-tools/pure'

const HEX64 = /^[0-9a-f]{64}$/

export function relayAttestation(rumor, sealPubkey, relayAttestors = []) {
  const sourceTags = (rumor?.tags || []).filter(t => t?.[0] === 'waggle-source')
  if (!sourceTags.length) return { present: false, message: null }
  if (sourceTags.length !== 1 || !relayAttestors.includes(sealPubkey)) return { present: true, message: null }
  let source
  try { source = JSON.parse(Buffer.from(String(sourceTags[0][1] || ''), 'base64url').toString('utf8')) } catch { return { present: true, message: null } }
  if (!source || typeof source !== 'object' || Array.isArray(source) ||
      Object.keys(source).sort().join(',') !== 'content,created_at,id,kind,pubkey,sig,tags' ||
      source.kind !== 9 || !HEX64.test(String(source.id || '')) || !HEX64.test(String(source.pubkey || '')) ||
      !Number.isInteger(source.created_at) || source.created_at <= 0 || !Array.isArray(source.tags) ||
      typeof source.content !== 'string' || Buffer.byteLength(JSON.stringify(source)) > 256 * 1024) {
    return { present: true, message: null }
  }
  let verified = false
  try { verified = verifyEvent(source) } catch { verified = false }
  if (!verified) return { present: true, message: null }
  const channelTags = source.tags.filter(t => t?.[0] === 'h' && t[1])
  const relayChannel = String(channelTags[0]?.[1] || '')
  // A channel carry without one unambiguous signed destination could wake the model but could
  // not route its answer safely. Refuse that half-loop before delivery.
  if (channelTags.length !== 1 || !/^[0-9a-f-]{1,128}$/i.test(relayChannel)) return { present: true, message: null }
  return { present: true, message: { from: source.pubkey, transport_from: sealPubkey,
    at: source.created_at, content: source.content, event_id: source.id, kind: source.kind,
    relay_channel: relayChannel } }
}
