// onboard_request.mjs — read an owner-signed setup request for nvoy-onboard (#289).
//
// A request names an operation from a closed list and carries public fields only. Nothing in it is
// an instruction: an unknown tag, a second value where one is allowed, or anything that looks like
// key material refuses the whole request. The signer must be a grantor of the template agent the
// request copies, so an owner the fleet already trusts is the only one who can ask.

import { verifyEvent } from 'nostr-tools/pure'
import { readPublicKey } from './instance_apply.mjs'

export const SETUP_KIND = 30078
export const SETUP_PREFIX = 'nvoy-onboard/'
export const OPS = Object.freeze(['add_agent', 'bind_runtime'])
export const HARNESSES = Object.freeze(['claude-code', 'codex', 'pi', 'openclaw', 'grokbot'])
export const MAX_AGE_S = 7 * 24 * 60 * 60

const NAME = /^[a-z0-9][a-z0-9._-]{1,63}$/i
const HEX = /^[0-9a-f]{64}$/
const ROOM = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const SECRETISH = /nsec1|bunker:|nostrconnect:|PRIVATE KEY|secret=/i
const ONE = ['d', 'op', 'p', 'harness', 'like', 'channel_key', 'invite', 'policy', 'age']
const JOIN_TAGS = ['invite', 'policy', 'age']
const POLICY = /^[A-Za-z0-9._:-]{1,64}$/
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/

// A NIP-44 v2 payload: version byte 2, a 32-byte nonce, at least 34 padded bytes, a 32-byte MAC.
// Its shape is all the fleet can check here; whether it opens is the agent's connection's answer.
export function sealedShape(value) {
  if (!BASE64.test(value) || value.length < 132 || value.length > 87472) return false
  const bytes = Buffer.from(value, 'base64')
  return bytes.length >= 99 && bytes[0] === 2
}
const MANY = ['giver', 'room']

export class OnboardRefusal extends Error {
  constructor(code, message) { super(message); this.code = code }
}
const refuse = (code, message) => { throw new OnboardRefusal(code, message) }

// Each op has its own d tag, so a later bind_runtime does not replace the add_agent it follows.
export const requestD = (name, op) => `${SETUP_PREFIX}${name}/${op}`

// The newest request for a name and op, by created_at then id, as a replaceable event is resolved.
export function newestRequest(events, name, op) {
  const d = requestD(name, op)
  return (Array.isArray(events) ? events : [])
    .filter(event => event?.kind === SETUP_KIND && event.tags?.some(tag => tag[0] === 'd' && tag[1] === d))
    .sort((a, b) => b.created_at - a.created_at || String(b.id).localeCompare(String(a.id)))[0] || null
}

// manifests: Map(id -> manifest) of installed identities. seen: request ids already finished.
// inProgress: request ids with receipts, so an add_agent whose own install has landed still reads.
export function parseSetupRequest(event, { name, manifests, seen = new Set(), inProgress = new Set(), now = Date.now() }) {
  if (!NAME.test(String(name || ''))) refuse('ONBOARD_BAD_NAME', 'name must be a short stable identifier')
  if (!event) refuse('ONBOARD_NO_REQUEST', `no setup request for ${name}`)
  if (event.kind !== SETUP_KIND) refuse('ONBOARD_BAD_REQUEST', 'not a setup request')
  let valid = false
  try { valid = verifyEvent(JSON.parse(JSON.stringify(event))) } catch {}
  if (!valid) refuse('ONBOARD_BAD_SIGNATURE', 'the request signature does not verify')
  if (seen.has(event.id)) refuse('ONBOARD_REPLAY', 'this request was already acted on')
  const age = Math.floor(now / 1000) - event.created_at
  if (age > MAX_AGE_S) refuse('ONBOARD_STALE', 'the request is more than 7 days old; sign it again')
  if (age < -600) refuse('ONBOARD_STALE', 'the request is dated in the future')
  if (event.content !== '') refuse('ONBOARD_BAD_REQUEST', 'a setup request has no content')

  const one = {}, many = { giver: [], room: [] }
  for (const tag of event.tags || []) {
    if (!Array.isArray(tag) || tag.length !== 2 || typeof tag[1] !== 'string') refuse('ONBOARD_BAD_TAG', 'every tag is a name and one value')
    const [key, value] = tag
    if (key !== 'invite' && SECRETISH.test(value)) refuse('ONBOARD_SECRET', `the ${key} tag holds something that looks like a secret`)
    if (ONE.includes(key)) {
      if (key in one) refuse('ONBOARD_BAD_TAG', `${key} appears twice`)
      one[key] = value
    } else if (MANY.includes(key)) many[key].push(value)
    else refuse('ONBOARD_UNKNOWN_TAG', `unknown tag ${key}`)
  }

  if (!OPS.includes(one.op)) refuse('ONBOARD_BAD_OP', `op must be one of ${OPS.join(', ')}`)
  if (one.d !== requestD(name, one.op)) refuse('ONBOARD_BAD_REQUEST', `the request is not ${one.op} for ${name}`)
  const pubkey = String(one.p || '')
  if (!HEX.test(pubkey)) refuse('ONBOARD_BAD_PUBKEY', 'p must be 64 lowercase hex')
  const template = manifests.get(String(one.like || ''))
  if (!template) refuse('ONBOARD_BAD_TEMPLATE', 'like must name an installed agent')
  if (!template.grantors.includes(event.pubkey)) refuse('ONBOARD_NOT_OWNER', `the signer is not a grantor of ${template.id}`)

  const installed = [...manifests.values()].find(manifest => manifest.pubkey === pubkey)
  if (one.op === 'add_agent') {
    const resumed = inProgress.has(event.id) && (!installed || installed.id === name) &&
      (!manifests.has(name) || manifests.get(name).pubkey === pubkey)
    if (manifests.has(name) && !resumed) refuse('ONBOARD_EXISTS', `${name} is already installed`)
    if (installed && !resumed) refuse('ONBOARD_EXISTS', `that key is already ${installed.id}`)
    if ('channel_key' in one) refuse('ONBOARD_BAD_TAG', 'channel_key belongs to bind_runtime')
    if ('invite' in one && !sealedShape(one.invite)) refuse('ONBOARD_BAD_INVITE', 'the invite must be sealed to the agent (NIP-44), never plain')
    if ('invite' in one && !('policy' in one)) refuse('ONBOARD_BAD_TAG', 'an invite needs the policy the owner agreed to, or none')
    if ('policy' in one && !POLICY.test(one.policy)) refuse('ONBOARD_BAD_TAG', 'policy is a terms version, or none')
    if ('age' in one && one.age !== 'confirmed') refuse('ONBOARD_BAD_TAG', 'age is confirmed, or absent')
  } else {
    if (installed && installed.id !== name) refuse('ONBOARD_EXISTS', `that key is already ${installed.id}`)
    if (!('channel_key' in one)) refuse('ONBOARD_BAD_TAG', 'bind_runtime needs channel_key')
    if (JOIN_TAGS.some(key => key in one)) refuse('ONBOARD_BAD_TAG', 'the invite belongs to add_agent')
  }
  if (!HARNESSES.includes(one.harness)) refuse('ONBOARD_BAD_HARNESS', `harness must be one of ${HARNESSES.join(', ')}`)

  const seatKeys = new Map([...manifests.values()].map(manifest => [manifest.pubkey, manifest.id]))
  const givers = [...new Set(many.giver)].map(giver => {
    if (!HEX.test(giver)) refuse('ONBOARD_BAD_GIVER', 'a giver is 64 lowercase hex')
    if (giver === pubkey) refuse('ONBOARD_BAD_GIVER', 'an agent does not give itself work')
    if (seatKeys.has(giver)) return { pubkey: giver, seat: seatKeys.get(giver) }
    if (event.pubkey === giver) return { pubkey: giver, owner: true }
    // A Buzz agent, or anyone else outside the fleet: reported, and nothing runs for it here.
    return { pubkey: giver, outside: true }
  })
  const rooms = [...new Set(many.room)]
  if (rooms.some(room => !ROOM.test(room))) refuse('ONBOARD_BAD_ROOM', 'a room is a Buzz room id')

  let channelKey = null
  if ('channel_key' in one) {
    try { channelKey = readPublicKey(one.channel_key) } catch (error) { refuse('ONBOARD_BAD_CHANNEL_KEY', error.message) }
  }

  return Object.freeze({ id: event.id, owner: event.pubkey, created_at: event.created_at, name, op: one.op,
    pubkey, harness: one.harness, like: template.id, givers, rooms, channelKey,
    invite: one.invite || '', policy: one.policy || '', ageConfirmed: one.age === 'confirmed' })
}
