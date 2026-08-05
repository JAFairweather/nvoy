// Pure authenticity boundary for a decrypted NIP-17/NIP-59 envelope. Decryption proves only that
// bytes were addressed to this key. It does not authenticate the ephemeral outer wrap, the signed
// seal (the carrier), or the unsigned rumor hash; all three are bound here before inbox policy sees
// a sender or content.

import { getEventHash, verifyEvent } from 'nostr-tools/pure'

const HEX64 = /^[0-9a-f]{64}$/
const WIRE_KEYS = 'content,created_at,id,kind,pubkey,sig,tags'
const RUMOR_KEYS = 'content,created_at,id,kind,pubkey,tags'
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === keys
const tagsValid = tags => Array.isArray(tags) && tags.every(tag =>
  Array.isArray(tag) && tag.every(value => typeof value === 'string'))
const wireVerify = (event, verify) => {
  try { return verify(JSON.parse(JSON.stringify(event))) } catch { return false }
}

export function verifyInboxEnvelope({ wrap, seal, rumor, recipient, verify = verifyEvent } = {}) {
  const to = String(recipient || '').toLowerCase()
  if (!HEX64.test(to) || !exact(wrap, WIRE_KEYS) || wrap.kind !== 1059 || !tagsValid(wrap.tags) ||
      !wireVerify(wrap, verify)) return null
  const recipients = wrap.tags.filter(tag => tag[0] === 'p')
  if (recipients.length !== 1 || String(recipients[0][1] || '').toLowerCase() !== to) return null

  if (!exact(seal, WIRE_KEYS) || seal.kind !== 13 || !tagsValid(seal.tags) ||
      !wireVerify(seal, verify)) return null
  if (!exact(rumor, RUMOR_KEYS) || rumor.kind !== 14 || !tagsValid(rumor.tags) ||
      rumor.pubkey !== seal.pubkey || !HEX64.test(String(rumor.id || '')) ||
      typeof rumor.content !== 'string' || Buffer.byteLength(rumor.content) > 256 * 1024) return null
  let rumorId = ''
  try { rumorId = getEventHash(JSON.parse(JSON.stringify(rumor))) } catch { return null }
  if (rumorId !== rumor.id) return null

  return { from: seal.pubkey, at: rumor.created_at, content: rumor.content }
}
