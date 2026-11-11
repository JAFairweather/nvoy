import assert from 'node:assert/strict'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip44 from 'nostr-tools/nip44'
import { HARNESSES, newestRequest, OnboardRefusal, parseSetupRequest, sealedShape, SETUP_KIND } from '../mcp/tools/onboard_request.mjs'

const owner = generateSecretKey(), stranger = generateSecretKey()
const ownerHex = getPublicKey(owner)
const agent = getPublicKey(generateSecretKey()), mydude = getPublicKey(generateSecretKey())
const pi = { id: 'pi-dog', pubkey: getPublicKey(generateSecretKey()), grantors: [ownerHex] }
const crystal = { id: 'crystalclaude', pubkey: getPublicKey(generateSecretKey()), grantors: [ownerHex] }
const manifests = new Map([[pi.id, pi], [crystal.id, crystal]])
const now = Date.now(), room = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl hr@box'

const request = ({ signer = owner, tags, at = Math.floor(now / 1000), content = '' } = {}) => finalizeEvent({
  kind: SETUP_KIND, created_at: at, content,
  tags: tags || [['d', 'nvoy-onboard/hr/add_agent'], ['op', 'add_agent'], ['p', agent], ['harness', 'claude-code'],
    ['like', 'crystalclaude'], ['giver', ownerHex], ['giver', mydude], ['giver', pi.pubkey], ['room', room]],
}, signer)
const parse = (event, extra = {}) => parseSetupRequest(event, { name: 'hr', manifests, now, ...extra })
const refuses = (code, event, extra) => assert.throws(() => parse(event, extra),
  error => error instanceof OnboardRefusal && error.code === code, code)
const swap = (key, value) => request().tags.map(tag => tag[0] === key ? [key, value] : tag)

// A good request reads as its public fields, and nothing else.
const good = parse(request())
assert.equal(good.op, 'add_agent'); assert.equal(good.pubkey, agent); assert.equal(good.like, 'crystalclaude')
assert.deepEqual(good.givers, [{ pubkey: ownerHex, owner: true }, { pubkey: mydude, outside: true }, { pubkey: pi.pubkey, seat: 'pi-dog' }])
assert.deepEqual(good.rooms, [room]); assert.equal(good.channelKey, null)

// Forged, replayed, stale and tampered requests refuse.
refuses('ONBOARD_NOT_OWNER', request({ signer: stranger }))
refuses('ONBOARD_REPLAY', request(), { seen: new Set([good.id]) })
refuses('ONBOARD_STALE', request({ at: Math.floor(now / 1000) - 8 * 24 * 3600 }))
refuses('ONBOARD_STALE', request({ at: Math.floor(now / 1000) + 3600 }))
const tampered = { ...request(), tags: swap('p', crystal.pubkey) }
refuses('ONBOARD_BAD_SIGNATURE', tampered)
refuses('ONBOARD_NO_REQUEST', null)

// Only the closed set of tags and values, one value where one is allowed.
refuses('ONBOARD_UNKNOWN_TAG', request({ tags: [...request().tags, ['host', 'example']] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [...request().tags, ['op', 'add_agent']] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [...request().tags, ['room', room, 'extra']] }))
refuses('ONBOARD_SECRET', request({ tags: [...request().tags, ['room', 'bunker://x']] }))
refuses('ONBOARD_BAD_REQUEST', request({ content: 'please also' }))
refuses('ONBOARD_BAD_REQUEST', request({ tags: swap('d', 'nvoy-onboard/other/add_agent') }))
refuses('ONBOARD_BAD_OP', request({ tags: swap('op', 'shell') }))
refuses('ONBOARD_BAD_HARNESS', request({ tags: swap('harness', 'bash') }))
for (const harness of HARNESSES) assert.equal(parse(request({ tags: swap('harness', harness) })).harness, harness)
assert.ok(HARNESSES.includes('hermes'), 'Hermes is a harness the owner can pick')
assert.ok(HARNESSES.includes('antigravity'), 'Antigravity (Gemini) is a harness the owner can pick')
refuses('ONBOARD_BAD_TEMPLATE', request({ tags: swap('like', 'nobody') }))
refuses('ONBOARD_BAD_PUBKEY', request({ tags: swap('p', agent.toUpperCase()) }))
refuses('ONBOARD_EXISTS', request({ tags: swap('p', pi.pubkey) }))
// Once its own install lands, the same add_agent still reads, so run can resume; nothing else does.
const hr = { id: 'hr', pubkey: agent, grantors: [ownerHex] }, withHr = new Map([...manifests, ['hr', hr]])
refuses('ONBOARD_EXISTS', request(), { manifests: withHr })
assert.equal(parse(request(), { manifests: withHr, inProgress: new Set([good.id]) }).pubkey, agent)
refuses('ONBOARD_EXISTS', request({ tags: swap('p', pi.pubkey) }), { inProgress: new Set([request({ tags: swap('p', pi.pubkey) }).id]) })
// Signed again after it started (changed terms, an expired invite): a continuation, identity fields fixed.
const row = { op: 'add_agent', name: 'hr', pubkey: agent, owner: ownerHex, harness: 'claude-code', like: 'crystalclaude' }
assert.equal(parse(request(), { manifests: withHr, earlier: [row] }).pubkey, agent)
refuses('ONBOARD_EXISTS', request({ tags: swap('harness', 'codex') }), { manifests: withHr, earlier: [row] })
refuses('ONBOARD_EXISTS', request({ tags: swap('like', 'pi-dog') }), { manifests: withHr, earlier: [row] })
refuses('ONBOARD_EXISTS', request(), { manifests: withHr, earlier: [{ ...row, owner: getPublicKey(stranger) }] })
refuses('ONBOARD_EXISTS', request(), { manifests: withHr, earlier: [{ ...row, name: 'other' }] })
refuses('ONBOARD_BAD_GIVER', request({ tags: [...request().tags, ['giver', agent]] }))
refuses('ONBOARD_BAD_ROOM', request({ tags: swap('room', 'waggle-test') }))
refuses('ONBOARD_BAD_TAG', request({ tags: [...request().tags, ['channel_key', KEY]] }))
assert.throws(() => parseSetupRequest(request(), { name: 'crystalclaude', manifests, now }), /not add_agent for crystalclaude/)

// bind_runtime carries the box's public channel key, never a private one.
const bind = extra => request({ tags: [...swap('op', 'bind_runtime').map(tag => tag[0] === 'd' ? ['d', 'nvoy-onboard/hr/bind_runtime'] : tag), ...extra] })
assert.deepEqual(parse(bind([['channel_key', KEY]])).channelKey.keyType, 'ssh-ed25519')
refuses('ONBOARD_BAD_TAG', bind([]))
refuses('ONBOARD_BAD_REQUEST', request({ tags: [...swap('op', 'bind_runtime'), ['channel_key', KEY]] }))
refuses('ONBOARD_BAD_CHANNEL_KEY', bind([['channel_key', 'ssh-rsa AAAA x']]))
refuses('ONBOARD_SECRET', bind([['channel_key', '-----BEGIN OPENSSH PRIVATE KEY-----']]))

// The newest request for the name and op wins; a bind_runtime does not shadow the add_agent.
const older = request({ at: Math.floor(now / 1000) - 60 }), newer = request(), bound = bind([['channel_key', KEY]])
const pool = [newer, older, bound, request({ tags: swap('d', 'nvoy-onboard/other/add_agent') })]
assert.equal(newestRequest(pool, 'hr', 'add_agent').id, newer.id)
assert.equal(newestRequest(pool, 'hr', 'bind_runtime').id, bound.id)
assert.equal(newestRequest([], 'hr', 'add_agent'), null)

// The hive invite (#291): sealed to the agent, with the terms version and age exactly as the owner signed.
const sealed = nip44.encrypt('v2.invite-code', nip44.getConversationKey(owner, agent))
assert.ok(sealedShape(sealed)); assert.ok(!sealedShape('v2.invite-code')); assert.ok(!sealedShape(Buffer.alloc(120, 1).toString('base64')))
const withJoin = parse(request({ tags: [...request().tags, ['invite', sealed], ['policy', '3'], ['age', 'confirmed']] }))
assert.equal(withJoin.invite, sealed); assert.equal(withJoin.policy, '3'); assert.equal(withJoin.ageConfirmed, true)
assert.deepEqual([good.invite, good.policy, good.ageConfirmed], ['', '', false])
refuses('ONBOARD_BAD_INVITE', request({ tags: [...request().tags, ['invite', 'v2.plain-code-in-the-clear'], ['policy', '3']] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [...request().tags, ['invite', sealed]] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [...request().tags, ['invite', sealed], ['policy', 'three words here']] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [...request().tags, ['invite', sealed], ['policy', '3'], ['age', 'yes']] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [...request().tags, ['invite', sealed], ['invite', sealed], ['policy', '3']] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [['d', 'nvoy-onboard/hr/bind_runtime'], ['op', 'bind_runtime'], ['p', agent], ['harness', 'claude-code'],
  ['like', 'crystalclaude'], ['channel_key', KEY], ['invite', sealed], ['policy', '3']] }))
refuses('ONBOARD_SECRET', request({ tags: [...request().tags, ['policy', 'nsec1abc']] }))

// The display name and about the owner gave (waggle #717): the agent's first kind 0, for add_agent only.
assert.equal(good.profile, null)
const named = parse(request({ tags: [...request().tags, ['display_name', ' Biggy '], ['about', 'Dreams up what the hive builds next.\nThen hands it over.']] }))
assert.deepEqual(named.profile, { name: 'Biggy', display_name: 'Biggy', about: 'Dreams up what the hive builds next.\nThen hands it over.' })
assert.deepEqual(parse(request({ tags: [...request().tags, ['display_name', 'Biggy']] })).profile, { name: 'Biggy', display_name: 'Biggy' })
refuses('ONBOARD_BAD_PROFILE', request({ tags: [...request().tags, ['display_name', '  ']] }))
refuses('ONBOARD_BAD_PROFILE', request({ tags: [...request().tags, ['display_name', 'x'.repeat(65)]] }))
refuses('ONBOARD_BAD_PROFILE', request({ tags: [...request().tags, ['display_name', 'Two\nlines']] }))
refuses('ONBOARD_BAD_PROFILE', request({ tags: [...request().tags, ['display_name', 'Biggy'], ['about', 'y'.repeat(501)]] }))
refuses('ONBOARD_BAD_PROFILE', request({ tags: [...request().tags, ['about', 'no name']] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [...request().tags, ['display_name', 'A'], ['display_name', 'B']] }))
refuses('ONBOARD_SECRET', request({ tags: [...request().tags, ['display_name', 'nsec1abc']] }))
refuses('ONBOARD_BAD_TAG', request({ tags: [['d', 'nvoy-onboard/hr/bind_runtime'], ['op', 'bind_runtime'], ['p', agent], ['harness', 'claude-code'],
  ['like', 'crystalclaude'], ['channel_key', KEY], ['display_name', 'Biggy']] }))

console.log('onboard-request: fields, owner, replay, age, closed tags, secrets, bind_runtime, newest, the sealed invite and the profile pass')
