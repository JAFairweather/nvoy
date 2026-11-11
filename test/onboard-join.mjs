// #291 — the hive and rooms steps: a sealed invite opened by the agent's own connection, the owner's
// terms passed exactly as signed, the claim NIP-98-signed by the agent, rooms proven by member list.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import * as nip44 from 'nostr-tools/nip44'
import { joinHive, joinRooms, readTerms, JOIN_KIND, MEMBERS_KIND } from '../mcp/tools/onboard_join.mjs'

const ownerSk = generateSecretKey(), owner = getPublicKey(ownerSk), agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const otherSk = generateSecretKey()
const CODE = 'v2.single-use-invite-code-0123456789'
const seal = (text, to = agent) => nip44.encrypt(text, nip44.getConversationKey(ownerSk, to))
const relay = 'wss://buzz.example', http = 'https://buzz.example'
const room1 = '00000000-0000-4000-8000-000000000001', room2 = '00000000-0000-4000-8000-000000000002'

function world({ member = false, terms = { version: '3', age_attestation_required: true }, termsFail = false, claimError = '', stall = '' } = {}) {
  const w = { member, posts: [], decrypts: 0, logins: 0 }
  w.signer = {
    async nip44Decrypt(peer, ct) { w.decrypts++; return nip44.decrypt(ct, nip44.getConversationKey(agentSk, peer)) },
    async signEvent(t) { return finalizeEvent({ ...t }, agentSk) },
  }
  w.open = async () => { w.logins++; if (!w.member) throw new Error('AUTH refused: restricted: not a member'); return { close() {} } }
  w.fetchImpl = async (url, { method, headers, body }) => {
    if (stall && url.endsWith(stall)) return new Promise(() => {})
    const reply = (status, json) => ({ status, json: async () => json })
    if (method === 'GET' && url === `${http}/api/join-policy`) {
      if (termsFail) throw new Error('connection reset')
      return reply(200, { policy: terms })
    }
    const payload = JSON.parse(body)
    w.posts.push({ url, headers, payload })
    if (url === `${http}/api/invites/accept-policy`) return reply(200, { receipt: 'receipt-1' })
    if (url === `${http}/api/invites/claim`) {
      if (claimError) return reply(403, { error: claimError })
      w.member = true
      return reply(200, { status: 'member', role: 'member' })
    }
    return reply(404, {})
  }
  return w
}
const request = (extra = {}) => ({ owner, pubkey: agent, invite: seal(CODE), policy: '3', ageConfirmed: true, rooms: [room1], ...extra })
const go = (w, add, ms) => joinHive({ add, relay, signer: w.signer, open: w.open, fetchImpl: w.fetchImpl, ...(ms ? { ms } : {}) })
const noCode = r => assert.ok(!JSON.stringify({ state: r.state, detail: r.detail }).includes(CODE), 'the code never reaches a receipt')

// Already a member: done, and the invite is never opened.
let w = world({ member: true }), r = await go(w, request())
assert.equal(r.state, 'done'); assert.equal(w.decrypts, 0); assert.ok(r.session)

// Not a member and no invite: waits for the owner.
w = world(); r = await go(w, request({ invite: '' }))
assert.equal(r.state, 'pending'); assert.match(r.detail, /carries no invite/); assert.equal(w.posts.length, 0)

// Sealed to another key: refused, nothing sent.
w = world(); r = await go(w, request({ invite: seal(CODE, getPublicKey(otherSk)) }))
assert.equal(r.state, 'refused'); assert.match(r.detail, /not sealed to this agent/); assert.equal(w.posts.length, 0)

// The relay did not answer (not a refused login): pending, the invite stays closed.
w = world(); w.open = async () => { throw new Error('AUTH challenge timed out') }
r = await go(w, request()); assert.equal(r.state, 'pending'); assert.equal(w.decrypts, 0)

// Terms unreadable is "can't tell", never "none": nothing claimed.
w = world({ termsFail: true }); r = await go(w, request())
assert.equal(r.state, 'pending'); assert.match(r.detail, /can't read the hive's terms/); assert.equal(w.posts.length, 0)
const termsOf = (json, status = 200) => readTerms(relay, { fetchImpl: async () => ({ status, json: async () => { if (json instanceof Error) throw json; return json } }) })
// The relay's no-terms answer is 200 {}: no terms, as the owner's page reads it. Policy null reads the same.
assert.deepEqual(await termsOf({}), { ok: true, version: 'none', age: false })
assert.deepEqual(await termsOf({ policy: null }), { ok: true, version: 'none', age: false })
// Anything else that is not versioned terms stays unread.
assert.deepEqual(await termsOf({}, 404), { ok: false, reason: 'HTTP 404' })
// Only the exact no-terms shapes mean none: an error object, or a null policy beside other fields, is unread.
assert.deepEqual(await termsOf({ error: 'policy unavailable' }), { ok: false, reason: 'no policy field' })
assert.deepEqual(await termsOf({ policy: null, error: 'policy unavailable' }), { ok: false, reason: 'a null policy beside other fields' })
w = world({ terms: undefined }); w.fetchImpl = (f => async (url, init) => url.endsWith('/api/join-policy') ? { status: 200, json: async () => ({ error: 'policy unavailable' }) } : f(url, init))(w.fetchImpl)
r = await go(w, request({ policy: 'none', ageConfirmed: false }))
assert.equal(r.state, 'pending'); assert.match(r.detail, /can't read the hive's terms \(no policy field\)/); assert.equal(w.posts.length, 0, 'an error answer never lets a claim through as no terms')
assert.deepEqual(await termsOf(new SyntaxError('Unexpected token <')), { ok: false, reason: 'not JSON' })
for (const body of [null, [], 'terms']) assert.equal((await termsOf(body)).ok, false, `${JSON.stringify(body)} is unread`)
for (const policy of ['v1', [], {}]) assert.equal((await termsOf({ policy })).ok, false, `policy ${JSON.stringify(policy)} is unread`)
assert.deepEqual(await termsOf({ policy: { version: 'v9', age_attestation_required: true } }), { ok: true, version: 'v9', age: true })

// The terms changed since the owner signed: the owner signs again, nothing claimed.
w = world({ terms: { version: '4', age_attestation_required: true } }); r = await go(w, request())
assert.equal(r.state, 'pending'); assert.match(r.detail, /serves 4, the request agreed 3/); assert.equal(w.posts.length, 0)

// The terms ask for the age confirmation and the owner did not give it: never filled in here.
w = world(); r = await go(w, request({ ageConfirmed: false }))
assert.equal(r.state, 'pending'); assert.match(r.detail, /age confirmation/); assert.equal(w.posts.length, 0)

// The whole claim: terms accepted as signed, then the claim, NIP-98 by the agent, bound to URL and body.
w = world(); r = await go(w, request())
assert.equal(r.state, 'done'); assert.ok(r.session); noCode(r)
assert.deepEqual(w.posts.map(p => p.url), [`${http}/api/invites/accept-policy`, `${http}/api/invites/claim`])
assert.deepEqual(w.posts[0].payload, { code: CODE, policy_version: '3', age_confirmed: true })
assert.deepEqual(w.posts[1].payload, { code: CODE, policy_receipt: 'receipt-1' })
const auth = JSON.parse(Buffer.from(w.posts[1].headers.authorization.replace(/^Nostr /, ''), 'base64').toString())
assert.ok(verifyEvent(auth)); assert.equal(auth.kind, 27235); assert.equal(auth.pubkey, agent)
const tag = name => auth.tags.find(t => t[0] === name)?.[1]
assert.equal(tag('u'), `${http}/api/invites/claim`); assert.equal(tag('method'), 'POST')
assert.equal(tag('payload'), createHash('sha256').update(JSON.stringify(w.posts[1].payload)).digest('hex'))
assert.equal(w.logins, 2, 'the proof is a second login, after the claim')

// No terms: claim straight away, no acceptance sent.
w = world({ terms: null }); r = await go(w, request({ policy: 'none', ageConfirmed: false }))
assert.equal(r.state, 'done'); assert.deepEqual(w.posts.map(p => p.url), [`${http}/api/invites/claim`])

// Plaintext invite via explicit add.inviteCode (hive-memory join path): never calls nip44Decrypt, claims and logs in.
w = world(); delete w.signer.nip44Decrypt
r = await go(w, { inviteCode: CODE, policy: '3', ageConfirmed: true })
assert.equal(r.state, 'done'); assert.equal(w.decrypts, 0); noCode(r)
assert.deepEqual(w.posts.map(p => p.url), [`${http}/api/invites/accept-policy`, `${http}/api/invites/claim`])

// An add with invite (not inviteCode) and no owner still requires nip44Decrypt and fails closed.
w = world(); delete w.signer.nip44Decrypt
r = await go(w, { invite: CODE, policy: '3', ageConfirmed: true })
assert.equal(r.state, 'refused'); assert.match(r.detail, /not sealed to this agent/)

// A refused claim that echoes the code: refused, and the code is scrubbed from the receipt.
w = world({ claimError: `invite ${CODE} already used` }); r = await go(w, request())
assert.equal(r.state, 'refused'); assert.match(r.detail, /already used/); noCode(r)

// A code straddling the 200-character cut: redacted first, so not even its prefix survives.
const lead = 'x'.repeat(190)   // the relay's words are cut at 200: the code starts 10 before the cut
w = world({ claimError: `${lead}${CODE} was already used` }); r = await go(w, request())
assert.equal(r.state, 'refused'); noCode(r); assert.ok(!r.detail.includes(CODE.slice(0, 8)), 'no prefix of the code survives the cut')

// A hive that stops answering: each of the three exchanges becomes a waiting step, never a hang.
w = world({ stall: '/api/join-policy' }); r = await go(w, request(), 20)
assert.equal(r.state, 'pending'); assert.match(r.detail, /can't read the hive's terms \(no answer in 0\.02s\)/); assert.equal(w.posts.length, 0)
w = world({ stall: '/api/invites/accept-policy' }); r = await go(w, request(), 20)
assert.equal(r.state, 'pending'); assert.match(r.detail, /did not answer the terms acceptance/); assert.equal(w.posts.length, 0)
w = world({ stall: '/api/invites/claim' }); r = await go(w, request(), 20)
assert.equal(r.state, 'pending'); assert.match(r.detail, /did not answer the claim .*checks whether it took/); noCode(r)

// ── Rooms ──────────────────────────────────────────────────────────────────────────────────────
function rooms({ members = {}, refuse = [] } = {}) {
  const s = { published: [], lists: members }
  s.fetch = async filter => {
    assert.deepEqual(filter.kinds, [MEMBERS_KIND]); assert.deepEqual(filter['#d'], filter['#h'])
    const room = filter['#h'][0]
    return [{ kind: MEMBERS_KIND, created_at: 1, tags: (s.lists[room] || []).map(pk => ['p', pk]) }]
  }
  s.publish = async template => {
    s.published.push(template)
    const room = template.tags[0][1]
    if (refuse.includes(room)) return { accepted: false, message: 'restricted: closed group' }
    s.lists[room] = [...(s.lists[room] || []), agent]
    return { accepted: true, message: '' }
  }
  return s
}
assert.deepEqual(await joinRooms({ add: request({ rooms: [] }), session: rooms() }), { state: 'done', detail: 'no rooms asked for' })

let s = rooms({ members: { [room1]: [agent] } }); r = await joinRooms({ add: request(), session: s })
assert.equal(r.state, 'done'); assert.equal(s.published.length, 0, 'already in: nothing published')

s = rooms(); r = await joinRooms({ add: request({ rooms: [room1, room2] }), session: s, now: () => 5000 })
assert.deepEqual(r, { state: 'done', detail: '2 of 2 rooms joined' })
assert.deepEqual(s.published[0], { kind: JOIN_KIND, created_at: 5, tags: [['h', room1]], content: '' })

// A partial earlier run (claimed, one room joined): the next run is a member, opens nothing, and joins only the missing room.
w = world({ member: true }); r = await go(w, request()); assert.equal(r.state, 'done'); assert.equal(w.decrypts, 0); assert.equal(w.posts.length, 0)
s = rooms({ members: { [room1]: [agent] } }); r = await joinRooms({ add: request({ rooms: [room1, room2] }), session: s })
assert.deepEqual(r, { state: 'done', detail: '2 of 2 rooms joined' }); assert.deepEqual(s.published.map(t => t.tags[0][1]), [room2])

s = rooms({ refuse: [room2] }); r = await joinRooms({ add: request({ rooms: [room1, room2] }), session: s })
assert.equal(r.state, 'pending'); assert.match(r.detail, /1 of 2 rooms joined; 00000000 refused the join \(restricted: closed group\); if it is private, the owner adds it/)

console.log('onboard-join: member already, no invite, wrong seal, relay down, terms unread/changed/age, no-terms {} contract, full claim, no terms, scrubbed refusal (straddling the cut), stalled hive, partial resume, rooms joined/private pass')
