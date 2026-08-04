// DOM-free authority primitive.  Both Nvoy's authority screen and a future
// Nact operation approval use this exact event shape.
import { verifyEvent } from 'nostr-tools'

export const TASK_CAPS = new Set(['task', 'task+act', 'task-relay'])
const DOMAIN = 'waggle/da-scope/v1\0'
const hex = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/i.test(s)
const hexBytes = (s) => Uint8Array.from(String(s).match(/../g) || [], h => parseInt(h, 16))
const hexOf = (bytes) => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('')

export async function taskScopeHash(agentPub, saltHex) {
  if (!hex(agentPub) || !/^[0-9a-f]{32}$/i.test(saltHex || '')) throw new Error('invalid task scope input')
  const body = new Uint8Array([...new TextEncoder().encode(DOMAIN), ...new TextEncoder().encode(agentPub.toLowerCase()), ...hexBytes(saltHex)])
  const digest = await crypto.subtle.digest('SHA-256', body)
  return hexOf(new Uint8Array(digest))
}

export async function buildTaskAuthority({ senderPub, agentPub, cap = 'task', createdAt = Math.floor(Date.now() / 1000), salt } = {}) {
  if (!hex(senderPub) || !hex(agentPub)) throw new Error('sender and agent must be 64-character public keys')
  if (!TASK_CAPS.has(cap)) throw new Error('choose Task, Task + act, or Task relay')
  const saltHex = salt || hexOf(crypto.getRandomValues(new Uint8Array(16)))
  return { kind: 440, created_at: Math.floor(createdAt), tags: [['p', senderPub.toLowerCase()], ['da-scope', await taskScopeHash(agentPub, saltHex), saltHex], ['da-cap', cap]], content: '' }
}

export async function signPublishTaskAuthority({ signer, relay, draft, verify = verifyEvent }) {
  const expectedPub = await signer.getPublicKey()
  const signed = JSON.parse(JSON.stringify(await signer.signEvent(draft)))
  if (!verify(signed)) throw new Error('your signer returned an invalid signature')
  if (signed.pubkey !== expectedPub || signed.kind !== draft.kind || signed.content !== draft.content || JSON.stringify(signed.tags) !== JSON.stringify(draft.tags)) throw new Error('your signer changed the authority you reviewed')
  const receipt = await relay.publish(signed)
  const observed = (await relay.query({ ids: [signed.id], limit: 1 })).find(ev => ev?.id === signed.id)
  if (!observed || !verify(observed) || observed.pubkey !== expectedPub || observed.kind !== 440) throw new Error('relay accepted the authority but it was not readable back; nothing is claimed as active')
  return { signed, receipt }
}
