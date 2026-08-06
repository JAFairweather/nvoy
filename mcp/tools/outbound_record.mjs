// One validator for the broker's persisted outbound reply state and the daemon's completion scan.

import { getEventHash, verifyEvent } from 'nostr-tools/pure'
import { createHash } from 'node:crypto'

const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/

export function replyRequestDigest(request) {
  return createHash('sha256').update(JSON.stringify(request)).digest('hex')
}

export function validateOutboundRecord(record, { requestId = '', requestDigest = '' } = {}) {
  if (record?.version === 2) {
    const allowed = new Set(['version', 'request_digest', 'request_id', 'fingerprint', 'unsigned_seal', 'wrap', 'approval_id', 'published', 'published_at', 'accepted'])
    if (!record || typeof record !== 'object' || Array.isArray(record) || Object.keys(record).some(key => !allowed.has(key)) ||
        !HEX32.test(String(record.request_id || '')) || !HEX64.test(String(record.request_digest || '')) ||
        !HEX64.test(String(record.fingerprint || '')) || typeof record.published !== 'boolean' ||
        (requestId && record.request_id !== requestId) || (requestDigest && record.request_digest !== requestDigest)) {
      throw new Error('outbound proposal does not bind this request')
    }
    const seal = record.unsigned_seal
    const sealKeys = seal && typeof seal === 'object' && !Array.isArray(seal) ? Object.keys(seal).sort() : []
    const expectedSealKeys = ['content', 'created_at', 'kind', 'pubkey', 'tags']
    if (!seal || sealKeys.length !== expectedSealKeys.length || sealKeys.some((key, index) => key !== expectedSealKeys[index]) ||
        seal.kind !== 13 || !HEX64.test(String(seal.pubkey || '')) || !Number.isInteger(seal.created_at) ||
        !Array.isArray(seal.tags) || seal.tags.length !== 0 || typeof seal.content !== 'string' || getEventHash(seal) !== record.fingerprint) {
      throw new Error('outbound proposal does not contain the exact frozen kind:13 seal')
    }
    if (record.wrap == null) {
      if (record.approval_id != null || record.published) throw new Error('unsigned outbound proposal claims enactment')
      return record
    }
    let validWrap = false
    try { validWrap = record.wrap.kind === 1059 && verifyEvent(JSON.parse(JSON.stringify(record.wrap))) } catch { validWrap = false }
    if (!validWrap || !HEX64.test(String(record.approval_id || ''))) throw new Error('enacted outbound proposal lacks a valid wrap or approval')
    if (record.published && (!Number.isInteger(record.accepted) || record.accepted < 1 ||
        !Number.isFinite(Number(record.published_at)) || Number(record.published_at) <= 0)) {
      throw new Error('published outbound record has no verified completion evidence')
    }
    return record
  }
  const allowed = new Set(['version', 'request_digest', 'request_id', 'wrap', 'published', 'published_at', 'accepted'])
  if (!record || typeof record !== 'object' || Array.isArray(record) || Object.keys(record).some(key => !allowed.has(key)) ||
      record.version !== 1 || !HEX32.test(String(record.request_id || '')) ||
      !HEX64.test(String(record.request_digest || '')) || typeof record.published !== 'boolean' ||
      (requestId && record.request_id !== requestId) || (requestDigest && record.request_digest !== requestDigest)) {
    throw new Error('outbound record does not bind this request')
  }
  const wrap = record.wrap
  let validWrap = false
  try { validWrap = wrap?.kind === 1059 && verifyEvent(JSON.parse(JSON.stringify(wrap))) } catch { validWrap = false }
  if (!validWrap) throw new Error('outbound record does not contain a valid signed kind:1059 wrap')
  if (record.published && (!Number.isInteger(record.accepted) || record.accepted < 1 ||
      !Number.isFinite(Number(record.published_at)) || Number(record.published_at) <= 0)) {
    throw new Error('published outbound record has no verified completion evidence')
  }
  return record
}
