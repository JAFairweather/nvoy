// owner_view on the agent card (waggle docs/DESIGN_MENTION_RIGHTS.md, step 2): the merged mention
// list, its refusals and the post channels, sealed to each grantor with a one-use key, re-signed
// only when the plaintext changes, and never signed anew from a run that cannot read the policy.
import { strict as assert } from 'node:assert'
import { spawn, spawnSync } from 'node:child_process'
import { createServer } from 'node:http'
import { createServer as createTlsServer } from 'node:https'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { WebSocketServer } from 'ws'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { scopeHash } from '../mcp/tools/grant_fold.mjs'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { readMentionGrants } from '../mcp/tools/agent_post.mjs'
import { agentCard, cardDigest, cardDue, ownerView, sealOwnerView } from '../mcp/tools/agent_card.mjs'

const key = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk) } }
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const alice = key(), bob = key(), outsider = key()
const peer = key().pk, kerouac = key().pk, mallory = key().pk
const channel = '00000000-0000-4000-8000-000000000000', second = '11111111-1111-4111-8111-111111111111'
const salt = 'ab'.repeat(16), at = Math.floor(Date.now() / 1000)
const root = mkdtempSync(join(tmpdir(), 'nvoy-owner-view-'))
const mention = (by, to, name, created) => finalizeEvent({ kind: 440, created_at: created, content: '',
  tags: [['p', to], ['da-scope', scopeHash(agent, salt), salt], ['da-cap', 'mention'], ['name', name]] }, by.sk)
const revoke = (by, id) => finalizeEvent({ kind: 441, created_at: at - 10, content: '', tags: [['e', id]] }, by.sk)
const asGrant = (e, grantor) => ({ pubkey: e.tags[0][1], name: e.tags[3][1], grant_id: e.id, grantor, created_at: e.created_at })
const open = (entry, sk) => nip44.decrypt(entry.sealed, nip44.utils.getConversationKey(sk, entry.by))

function fixture(id, extra = {}) {
  const directory = join(root, id)
  for (const name of ['instances', 'state', 'run', 'spool']) mkdirSync(join(directory, name), { recursive: true })
  const raw = { id, pubkey: agent, grantors: [alice.pk, bob.pk], relays: ['wss://127.0.0.1:1'], buzz: { relay: 'wss://buzz.example', channels: [channel, second] },
    broker_mode: 'local', key_ref: '/etc/nvoy/credentials/seat.nsec', delivery_mode: 'notify_only', worker_enabled: false,
    state_dir: join(directory, 'state'), runtime_dir: join(directory, 'run'), spool_dir: join(directory, 'spool'),
    broker_adapter_gid: 1001, worker_handoff_gid: 1002, watcher_uid: 1001, broker_uid: 1002, adapter_uid: 1003, worker_uid: 1004,
    may_post: { channels: [channel], per_hour: 5, mention: [{ name: 'peer', pubkey: peer }] }, agent_card: true, ...extra }
  const write = patch => writeFileSync(join(directory, 'instances', `${id}.json`), JSON.stringify(Object.assign(raw, patch)))
  write({})
  return { root: join(directory, 'instances'), directory, write, load: () => readManifest(join(directory, 'instances'), id) }
}

// --- the view, its sealing and its digest, directly ---
const g1 = mention(alice, kerouac, 'kerouac', at - 300), g2 = mention(bob, peer, 'peer', at - 200), g3 = mention(alice, mallory, 'peer', at - 100)
const grants = [asGrant(g3, alice.pk), asGrant(g1, alice.pk), asGrant(g2, bob.pk)]
const manifest = fixture('unit').load(), quiet = () => {}
const view = ownerView(manifest, grants, quiet)
const expected = {
  mention: [{ name: 'peer', pubkey: peer, source: 'manifest', grants: [g2.id] }, { name: 'kerouac', pubkey: kerouac, source: 'grant', grants: [g1.id] }],
  refused: [{ grant: g3.id, reason: `the name peer is held by ${peer.slice(0, 8)}` }],
  channels: [{ id: channel, name: null }],
}
assert.deepEqual(view, expected, 'a manifest entry stays `manifest` though a grant attached to it; a grant entry is `grant`; the clash is refused')
assert.equal(ownerView(fixture('quiet', { may_post: undefined }).load(), grants, quiet), null, 'no may_post, no owner view')

const sealed = sealOwnerView(view, manifest.grantors)
assert.deepEqual(sealed.map(e => e.to), [alice.pk, bob.pk])
for (const [entry, who] of [[sealed[0], alice], [sealed[1], bob]]) assert.equal(open(entry, who.sk), JSON.stringify(view), 'each grantor opens its own copy')
assert.throws(() => open(sealed[0], outsider.sk), 'a non-grantor cannot open it')
assert.throws(() => open(sealed[0], bob.sk), 'nor can one grantor open another\'s copy')
const resealed = sealOwnerView(view, manifest.grantors)
assert.notEqual(resealed[0].by, sealed[0].by, 'a fresh key each publication')
assert.notEqual(resealed[0].sealed, sealed[0].sealed)
assert(sealed.every(e => e.by === sealed[0].by) && /^[0-9a-f]{64}$/.test(sealed[0].by), 'one key per publication, shared by its copies')

const card = agentCard(manifest), now = Date.now(), last = { event: { id: 'x' }, at: now, digest: cardDigest(card, view) }
assert.equal(cardDue(card, last, now, ownerView(manifest, [...grants].reverse(), quiet)), false, 'fresh ciphertext and grant order never make a card due')
const due = list => cardDue(card, last, now, ownerView(manifest, list, quiet))
const g4 = mention(bob, kerouac, 'jack', at - 50)
assert.equal(due([...grants, asGrant(g4, bob.pk)]), true, 'a grant id added')
assert.equal(due(grants.filter(g => g.grant_id !== g1.id)), true, 'a grant id removed')
assert.equal(due(grants.filter(g => g.grant_id !== g3.id)), true, 'a refusal gone')
assert.equal(cardDue(card, last, now, ownerView({ ...manifest, mayPost: { ...manifest.mayPost, channels: [channel, second] } }, grants, quiet)), true, 'a channel added')
assert.equal(cardDue(card, { ...last, digest: cardDigest(card) }, now, view), true, 'a record from before the view counts as changed once')
assert.equal(cardDigest(card, null), cardDigest(card), 'a card without a view keeps its old digest')

// --- end to end: the publisher reads the live policy from a TLS grant relay ---
const certDir = join(root, 'tls'); mkdirSync(certDir)
const tls = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
  '-keyout', join(certDir, 'key.pem'), '-out', join(certDir, 'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8' })
if (tls.status !== 0) throw new Error('openssl could not make the test certificate')
const grantServer = createTlsServer({ key: readFileSync(join(certDir, 'key.pem')), cert: readFileSync(join(certDir, 'cert.pem')) }, (q, r) => { r.writeHead(404); r.end() })
await new Promise(done => grantServer.listen(0, '127.0.0.1', done))
const grantRelay = { url: `wss://127.0.0.1:${grantServer.address().port}`, events: [g1, g2, g3], down: false }
new WebSocketServer({ server: grantServer }).on('connection', socket => socket.on('message', raw => {
  const frame = JSON.parse(raw.toString())
  if (frame[0] !== 'REQ') return
  if (grantRelay.down) return socket.send(JSON.stringify(['CLOSED', frame[1], 'error: down']))
  for (const e of grantRelay.events) if (frame[2].kinds.includes(e.kind) && frame[2].authors.includes(e.pubkey)) socket.send(JSON.stringify(['EVENT', frame[1], e]))
  socket.send(JSON.stringify(['EOSE', frame[1]]))
}))
const cardServer = createServer((q, r) => { r.writeHead(404); r.end() })
await new Promise(done => cardServer.listen(0, '127.0.0.1', done))
const cards = [], cardRelay = `ws://127.0.0.1:${cardServer.address().port}`
new WebSocketServer({ server: cardServer }).on('connection', socket => socket.on('message', raw => {
  const frame = JSON.parse(raw.toString())
  if (frame[0] === 'EVENT') { cards.push(frame[1]); socket.send(JSON.stringify(['OK', frame[1].id, true, ''])) }
  if (frame[0] === 'REQ') { socket.send(JSON.stringify(['EVENT', frame[1], cards.at(-1)])); socket.send(JSON.stringify(['EOSE', frame[1]])) }
}))

// attention.mjs runs with an env the publisher builds; this preload lets it trust the test certificate.
const preload = join(root, 'trust.mjs')
writeFileSync(preload, `import { createRequire, syncBuiltinESMExports } from 'node:module'
const cp = createRequire(import.meta.url)('node:child_process'), spawnSync = cp.spawnSync
cp.spawnSync = (file, args, options = {}) => spawnSync(file, args, { ...options, env: { ...options.env, NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS } })
syncBuiltinESMExports()
`)
const credential = join(root, 'credential')
writeFileSync(credential, Buffer.from(agentSk).toString('hex'))
const run = seat => new Promise(done => {
  const child = spawn(process.execPath, ['--import', preload, 'mcp/tools/instance-broker-card.mjs', '--instance', seat.load().id],
    { cwd: new URL('..', import.meta.url).pathname, env: { ...process.env, NVOY_INSTANCE_ROOT: seat.root, NVOY_BROKER_CREDENTIAL: credential,
      NVOY_CARD_RELAYS: cardRelay, NODE_EXTRA_CA_CERTS: join(certDir, 'cert.pem') } })
  let out = '', err = ''
  child.stdout.on('data', c => { out += c }); child.stderr.on('data', c => { err += c })
  child.on('exit', code => done({ code, report: out.trim() ? JSON.parse(out.trim()) : null, err: err.trim() }))
})
const content = event => JSON.parse(event.content)

const live = fixture('live', { relays: [grantRelay.url] })
writeFileSync(join(live.directory, 'run', 'mention-grants.json'), '')
let result = await run(live)
assert.equal(result.code, 0, result.err)
const first = cards.at(-1), body = content(first)
assert(verifyEvent(first) && first.pubkey === agent, 'owner_view is inside the agent-signed content')
const { owner_view: firstView, ...publicFields } = body
assert.deepEqual(publicFields, agentCard(live.load()), 'the public projection is unchanged')
assert.deepEqual(Object.keys(body), [...Object.keys(agentCard(live.load())), 'owner_view'])
for (const hidden of [peer, kerouac, mallory, channel, g1.id, g2.id, g3.id, '"peer"', 'kerouac'])
  assert(!JSON.stringify(publicFields).includes(hidden) && !first.content.includes(hidden), `the published card leaks ${hidden}`)
assert.deepEqual(firstView.map(e => e.to), [alice.pk, bob.pk])
assert.deepEqual(JSON.parse(open(firstView[0], alice.sk)), expected, 'the live policy reaches the owner, merged')
assert.equal(open(firstView[1], bob.sk), open(firstView[0], alice.sk))
assert.deepEqual(readMentionGrants(live.load()).map(g => g.grant_id).sort(), [g1.id, g2.id, g3.id].sort(), 'the run refreshes the keyless snapshot')

result = await run(live)
assert.deepEqual(result.report, { card: 'current', event_id: first.id }, 'the same policy signs nothing')
assert.equal(cards.length, 1)

grantRelay.events.push(g4)
result = await run(live)
assert.equal(result.code, 0, result.err)
const added = cards.at(-1)
assert.notEqual(added.id, first.id, 'a new grant id re-signs')
assert.notEqual(content(added).owner_view[0].by, firstView[0].by, 'with a fresh sealing key')
assert.deepEqual(JSON.parse(open(content(added).owner_view[1], bob.sk)).mention[1].grants, [g1.id, g4.id])

grantRelay.events.push(revoke(bob, g4.id))
result = await run(live)
const revoked = cards.at(-1)
assert.notEqual(revoked.id, added.id, 'a 441 re-signs')
assert.deepEqual(JSON.parse(open(content(revoked).owner_view[0], alice.sk)), expected)

// Unable to read the policy: the last card stands, even though the public card changed.
grantRelay.down = true
live.write({ may_post: { channels: [channel], per_hour: 6, mention: [{ name: 'peer', pubkey: peer }] } })
result = await run(live)
assert.equal(result.code, 0, result.err)
assert.deepEqual(result.report, { card: 'current', event_id: revoked.id })
assert.equal(result.err, 'instance-broker-card: live mention grants are unavailable; keeping the last card')
assert.equal(cards.at(-1).id, revoked.id)

// With no last card it publishes one without owner_view, and the first readable policy re-signs it.
const fresh = fixture('fresh', { relays: [grantRelay.url] })
result = await run(fresh)
assert.equal(result.code, 0, result.err)
assert.equal(result.err, 'instance-broker-card: live mention grants are unavailable; publishing without owner_view')
assert(!('owner_view' in content(cards.at(-1))), 'no view is "can\'t tell", never an empty one')
const blind = cards.at(-1)
grantRelay.down = false
result = await run(fresh)
assert.notEqual(cards.at(-1).id, blind.id)
assert.deepEqual(JSON.parse(open(content(cards.at(-1)).owner_view[0], alice.sk)), expected)

// A reply-only agent's card carries no owner_view, and the policy is not read for it.
const plain = fixture('plain', { relays: [grantRelay.url], may_post: undefined })
result = await run(plain)
assert.equal(result.code, 0, result.err)
assert(!('owner_view' in content(cards.at(-1))) && result.err === '')

grantServer.close(); cardServer.close()
console.log('ok agent card owner_view: merged list sealed to each grantor, digest of the plaintext, last card kept when the policy is unreadable')
process.exit(0)
