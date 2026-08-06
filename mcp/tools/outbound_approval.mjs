// outbound_approval.mjs — exact, signed, single-action approval atom for AD-12.
//
// The approval is a standard NIP-98 event over a canonical decision body. It authorizes only one
// frozen proposal fingerprint at one immutable runtime endpoint. It never authorizes a class of
// actions and it is not itself the participant signature.

import { createHash } from 'node:crypto'
import { getEventHash, verifyEvent } from 'nostr-tools/pure'

const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/
const fail = message => { throw new Error(`outbound approval: ${message}`) }

export function approvalUrl(instance, proposalId) {
  if (!/^[a-z0-9][a-z0-9._-]{1,63}$/i.test(String(instance || ''))) fail('invalid instance')
  if (!HEX32.test(String(proposalId || ''))) fail('invalid proposal id')
  return `nvoy://outbound/${encodeURIComponent(instance)}/${proposalId}`
}

export function approvalBody(proposalId, fingerprint, verb = 'approve') {
  if (!HEX32.test(String(proposalId || ''))) fail('invalid proposal id')
  if (!HEX64.test(String(fingerprint || ''))) fail('invalid fingerprint')
  if (verb !== 'approve' && verb !== 'reject') fail('invalid verb')
  return JSON.stringify({ proposal_id: proposalId, fingerprint, verb })
}

export function approvalTemplate({ approver, instance, proposalId, fingerprint, verb = 'approve', createdAt = Math.floor(Date.now() / 1000) }) {
  if (!HEX64.test(String(approver || ''))) fail('invalid approver')
  const content = approvalBody(proposalId, fingerprint, verb)
  return {
    pubkey: approver,
    created_at: createdAt,
    kind: 27235,
    tags: [
      ['u', approvalUrl(instance, proposalId)],
      ['method', 'POST'],
      ['payload', createHash('sha256').update(content).digest('hex')],
    ],
    content: '',
  }
}

export function verifyOutboundApproval(event, { instance, proposalId, fingerprint, approvers, nowMs = Date.now(), maxAgeMs = 5 * 60 * 1000 } = {}) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) fail('event is missing')
  const keys = Object.keys(event).sort()
  const expectedKeys = ['content', 'created_at', 'id', 'kind', 'pubkey', 'sig', 'tags']
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) fail('event schema is not closed')
  if (!HEX64.test(String(event.pubkey || '')) || !Array.isArray(approvers) || !approvers.includes(event.pubkey)) fail('signer is not an authorized approver')
  if (event.kind !== 27235 || event.content !== '' || !Number.isInteger(event.created_at)) fail('event shape is invalid')
  const ageMs = nowMs - event.created_at * 1000
  if (ageMs < -30_000 || ageMs > maxAgeMs) fail('event is stale or future-dated')
  if (!Array.isArray(event.tags) || event.tags.length !== 3 || event.tags.some(tag => !Array.isArray(tag) || tag.length !== 2 || typeof tag[0] !== 'string' || typeof tag[1] !== 'string')) fail('tag schema is not closed')
  const tags = new Map()
  for (const tag of event.tags) {
    if (tags.has(tag[0]) || !['u', 'method', 'payload'].includes(tag[0])) fail('tag schema is not closed')
    tags.set(tag[0], tag[1])
  }
  const body = approvalBody(proposalId, fingerprint, 'approve')
  if (tags.get('u') !== approvalUrl(instance, proposalId) || tags.get('method') !== 'POST' ||
      tags.get('payload') !== createHash('sha256').update(body).digest('hex')) fail('event does not bind the exact approval body')
  if (event.id !== getEventHash(event) || !verifyEvent(JSON.parse(JSON.stringify(event)))) fail('signature is invalid')
  return Object.freeze({ approver: event.pubkey, proposalId, fingerprint, approvedAt: event.created_at, eventId: event.id })
}
