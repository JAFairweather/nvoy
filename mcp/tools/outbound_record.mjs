// One validator for the broker's persisted outbound reply state and the daemon's completion scan.

import { verifyEvent } from 'nostr-tools/pure'
import { createHash } from 'node:crypto'

const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/

export function replyRequestDigest(request) {
  return createHash('sha256').update(JSON.stringify(request)).digest('hex')
}

export function validateOutboundRecord(record, { requestId = '', requestDigest = '' } = {}) {
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
