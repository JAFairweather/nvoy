// Mention lists from room membership (#321, docs/MENTION_FROM_ROOMS.md): the relay-signed roster and
// its trust rules, the discovery file, the merged per-room view, the manifest opt-in, and the broker's
// fresh roster read before it signs a mention only a room allows.
import { WebSocketServer } from 'ws'
import { spawn, spawnSync } from 'node:child_process'
import { createServer } from 'node:http'
import { createServer as createTlsServer } from 'node:https'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { policyFromTemplate } from '../mcp/tools/identity_allocation.mjs'
import { capabilitySummary, effectiveMentions, mentionView, mentionable, queuePost, resolvePost, resolveReplyMention,
  validatePostRequest, validateReplyMention } from '../mcp/tools/agent_post.mjs'
import { ownerView } from '../mcp/tools/agent_card.mjs'
import { MEMBERS_KIND, confirmMembers, mentionName, namesFrom, readMentionRooms, readRooms, recordMentionRooms, rosterFrom } from '../mcp/tools/room_roster.mjs'

let fails = 0, passes = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }
const throws = fn => { try { fn(); return '' } catch (e) { return e.message } }
const key = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk) } }

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607', CH2 = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const relayKey = key(), impostor = key(), grantor = key().pk
const neil = key().pk, kerouac = key(), dennis = key(), leaver = key(), twinA = key(), twinB = key()
const list = (room, members, at, { signer = relayKey.sk, tags } = {}) => finalizeEvent({ kind: MEMBERS_KIND, created_at: at,
  tags: tags || [['d', room], ['h', room], ...members.map(p => ['p', p])], content: '' }, signer)
const profile = (who, body, at = 100) => finalizeEvent({ kind: 0, created_at: at, tags: [], content: JSON.stringify(body) }, who.sk)

// --- 1. the roster: only the newest list the pinned relay key signed for exactly this room ---
const opts = { room: CH, relaySigner: relayKey.pk }
ok('the newest passing list wins', rosterFrom([list(CH, [neil], 10), list(CH, [neil, kerouac.pk], 20), list(CH, [dennis.pk], 15)], opts).join() === [neil, kerouac.pk].join())
const tampered = list(CH, [neil], 30); tampered.tags.push(['p', dennis.pk])
ok('a list whose signature no longer verifies is ignored, even one nostr-tools already verified', verifyEvent(tampered) &&
  rosterFrom([list(CH, [neil], 10), tampered], opts).join() === neil)
ok('a list another key signed is ignored', rosterFrom([list(CH, [neil], 10), list(CH, [dennis.pk], 50, { signer: impostor.sk })], opts).join() === neil)
ok('a list for another room is ignored', rosterFrom([list(CH, [neil], 10), list(CH2, [dennis.pk], 50)], opts).join() === neil)
ok('a list with two d tags is ignored', rosterFrom([list(CH, [neil], 10), list(CH, [], 50, { tags: [['d', CH], ['d', CH2], ['h', CH], ['p', dennis.pk]] })], opts).join() === neil)
ok('a list whose h is another room is ignored', rosterFrom([list(CH, [neil], 10), list(CH, [], 50, { tags: [['d', CH], ['h', CH2], ['p', dennis.pk]] })], opts).join() === neil)
ok('with nothing passing there is no roster: null, never an empty list', rosterFrom([list(CH, [neil], 50, { signer: impostor.sk })], opts) === null && rosterFrom([], opts) === null)
ok('an invalid room or pinned key reads nothing', rosterFrom([list(CH, [neil], 10)], { room: 'general', relaySigner: relayKey.pk }) === null &&
  rosterFrom([list(CH, [neil], 10)], { room: CH, relaySigner: 'relay' }) === null)
ok('an empty passing list is an empty roster, and malformed p tags are dropped', rosterFrom([list(CH, [], 10, { tags: [['d', CH], ['p', 'zz'], ['p', neil], ['p', neil]] })], opts).join() === neil)

const session = events => ({ fetch: async f => events.filter(e => f.kinds.includes(e.kind) &&
  (!f['#d'] || e.tags.some(t => t[0] === 'd' && f['#d'].includes(t[1]))) && (!f.authors || f.authors.includes(e.pubkey))) })
ok('confirmMembers resolves undefined when every key is in the fresh roster', await confirmMembers({ session: session([list(CH, [neil, kerouac.pk], 10)]), room: CH, keys: [kerouac.pk], relaySigner: relayKey.pk }) === undefined)
ok('and names the first key that is not', await confirmMembers({ session: session([list(CH, [neil], 10)]), room: CH, keys: [neil, kerouac.pk], relaySigner: relayKey.pk }) === kerouac.pk)
const rejects = async p => { try { await p; return '' } catch (e) { return e.message } }
ok('it throws, so the caller holds, when no list passes', /no member list for room/.test(await rejects(confirmMembers({ session: session([list(CH, [kerouac.pk], 10, { signer: impostor.sk })]), room: CH, keys: [kerouac.pk], relaySigner: relayKey.pk }))))
ok('and when the read itself fails', /socket closed/.test(await rejects(confirmMembers({ session: { fetch: async () => { throw new Error('socket closed') } }, room: CH, keys: [kerouac.pk], relaySigner: relayKey.pk }))))

// --- 2. names, and readRooms ---
ok('a name is name, else display_name, lowercased with dashes, cut to the manifest pattern',
  mentionName(JSON.stringify({ name: 'Jack Kerouac!' })) === 'jack-kerouac' && mentionName(JSON.stringify({ name: ' ', display_name: 'Neil' })) === 'neil' &&
  mentionName(JSON.stringify({ name: '!!!' })) === null && mentionName('not json') === null)
ok('the newest verified profile per wanted key gives the name', namesFrom([profile(kerouac, { name: 'old' }, 10), profile(kerouac, { name: 'kerouac' }, 20),
  { ...profile(dennis, { name: 'dennis' }), content: '{"name":"forged"}' }, profile(impostor, { name: 'x' })], [kerouac.pk, dennis.pk]).get(kerouac.pk) === 'kerouac')
const roomsRead = await readRooms({ session: session([list(CH, [agent, kerouac.pk, twinA.pk, twinB.pk, dennis.pk], 10), list(CH2, [kerouac.pk], 10),
  profile(kerouac, { name: 'kerouac' }), profile(twinA, { name: 'Twin' }), profile(twinB, { display_name: 'twin' })]), rooms: [CH, CH2, 'not-a-room'], relaySigner: relayKey.pk, me: agent })
const inCH = Object.fromEntries((roomsRead.rooms[CH] || []).map(e => [e.pubkey, e.name]))
ok('readRooms drops the broker itself and names each member it can', !(agent in inCH) && inCH[kerouac.pk] === 'kerouac' && inCH[dennis.pk] === null)
ok('a name two keys reduce to is kept by neither', inCH[twinA.pk] === null && inCH[twinB.pk] === null)
ok('an unreadable room comes back empty, never borrowed from another', roomsRead.rooms['not-a-room'].length === 0 && roomsRead.rooms[CH2].length === 1)
const brokenRead = await readRooms({ session: { fetch: async f => { if (f.kinds[0] === 0) throw new Error('profiles down'); throw new Error('room down') } }, rooms: [CH], relaySigner: relayKey.pk, me: agent })
ok('a room or the profiles that fail to read are listed as failed', brokenRead.failed.some(f => f.room === CH) && !(CH in brokenRead.rooms))

// --- 3. the manifest opt-in ---
const root = mkdtempSync(join(tmpdir(), 'nvoy-mention-rooms-'))
const gid = process.getgid(), uid = process.getuid()
const fixture = (id, extra = {}) => {
  const dir = join(root, id)
  for (const d of ['instances', 'state', 'run', 'spool']) mkdirSync(join(dir, d), { recursive: true })
  const m = { version: 1, id, pubkey: agent, broker_mode: 'local', key_ref: '/etc/nvoy/credentials/agent.nsec', worker_enabled: false, delivery_mode: 'notify_only',
    state_dir: join(dir, 'state'), runtime_dir: join(dir, 'run'), spool_dir: join(dir, 'spool'),
    broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid,
    grantors: [grantor], relays: ['wss://127.0.0.1:1'], buzz: { relay: 'wss://buzz.example', channels: [CH, CH2], relay_signer: relayKey.pk }, ...extra }
  writeFileSync(join(dir, 'instances', `${id}.json`), JSON.stringify(m))
  return { root: join(dir, 'instances'), run: join(dir, 'run'), state: join(dir, 'state'), load: () => readManifest(join(dir, 'instances'), id) }
}
const mayPost = { channels: [CH, CH2], per_hour: 20, mention: [{ name: 'neil', pubkey: neil }], mention_rooms: true }
const unsigned = { relay: 'wss://buzz.example', channels: [CH, CH2] }
ok('mention_rooms without buzz.relay_signer is refused', /mention_rooms requires buzz\.relay_signer/.test(throws(() => fixture('nosigner', { may_post: mayPost, buzz: unsigned }).load())))
ok('an invalid relay_signer is refused', /relay_signer must be a pubkey/.test(throws(() => fixture('badsigner', { may_post: mayPost, buzz: { ...unsigned, relay_signer: 'relay' } }).load())))
ok('mention_rooms must be a boolean', /must be true or false/.test(throws(() => fixture('notbool', { may_post: { ...mayPost, mention_rooms: 'yes' } }).load())))
ok('mention_rooms is off by default', fixture('off', { may_post: { ...mayPost, mention_rooms: undefined } }).load().mayPost.mentionRooms === false)
const rf = fixture('rooms', { may_post: mayPost }), rm = rf.load()
ok('with both, the manifest carries the flag and the pinned key', rm.mayPost.mentionRooms === true && rm.buzz.relaySigner === relayKey.pk)
ok('onboarding copies both from a template', (p => p.may_post.mention_rooms === true && p.buzz.relay_signer === relayKey.pk)(policyFromTemplate(JSON.parse(readFileSync(join(rf.root, 'rooms.json'), 'utf8')), { pubkey: kerouac.pk })))

// --- 4. the discovery file ---
const roomsFile = join(rf.run, 'mention-rooms.json')
ok('an unprovisioned file is never created', recordMentionRooms(rm, { rooms: { [CH]: [] } }) === false && !existsSync(roomsFile))
writeFileSync(roomsFile, '', { mode: 0o640 })
const entry = (who, name = null) => ({ pubkey: who.pk || who, name })
ok('a read is recorded and read back', recordMentionRooms(rm, { rooms: { [CH]: [entry(kerouac, 'kerouac'), entry(dennis, 'dennis')], [CH2]: [entry(dennis, 'dennis')] } }, 1_700_000_000_000) &&
  readMentionRooms(rm)[CH].length === 2 && JSON.parse(readFileSync(roomsFile, 'utf8')).read_at === 1_700_000_000)
ok('a room not read this time keeps its last good list', recordMentionRooms(rm, { rooms: { [CH]: [entry(kerouac, 'kerouac')] }, failed: [{ room: CH2, reason: 'down' }] }) &&
  readMentionRooms(rm)[CH2].map(e => e.pubkey).join() === dennis.pk && readMentionRooms(rm)[CH].length === 1)
ok('with the profiles unread, a member keeps the name it last had', recordMentionRooms(rm, { rooms: { [CH]: [entry(kerouac)] }, failed: [{ room: null, reason: 'profiles: down' }] }) &&
  readMentionRooms(rm)[CH][0].name === 'kerouac')
writeFileSync(roomsFile, JSON.stringify({ version: 1, instance: 'someone-else', rooms: { [CH]: [entry(dennis)] } }))
ok('a file for another instance reads as nothing', readMentionRooms(rm) === null)
writeFileSync(roomsFile, JSON.stringify({ version: 1, instance: 'rooms', rooms: { [CH]: [entry(kerouac, 'kerouac'), { pubkey: 'zz', name: 'x' }, entry(dennis, '-bad')], [grantor]: [entry(dennis)] } }))
ok('only this identity\'s rooms and well-formed entries are read', JSON.stringify(readMentionRooms(rm)) === JSON.stringify({ [CH]: [entry(kerouac, 'kerouac')] }))
ok('an identity without the flag records nothing', recordMentionRooms(fixture('flagless', { may_post: { ...mayPost, mention_rooms: false } }).load(), { rooms: { [CH]: [] } }) === false)

// --- 5. one merged view, per room ---
const rooms = { [CH]: [entry(kerouac, 'kerouac'), entry(twinA, 'neil'), entry(neil, 'neil-again')], [CH2]: [entry(dennis, 'dennis')] }
const grant = { pubkey: leaver.pk, name: 'leaver', grant_id: 'a'.repeat(64), grantor, created_at: 1000 }
const eff = effectiveMentions(rm, { grants: [grant], rooms }, CH)
ok('the sources come in order: manifest, grants, then the room\'s members', eff.map(e => e.source).join() === 'manifest,grant,room,room' &&
  eff.map(e => e.pubkey).join() === [neil, leaver.pk, kerouac.pk, twinA.pk].join())
ok('a key already listed is not added again from the room', eff.filter(e => e.pubkey === neil).length === 1)
ok('a manifest name beats a roster name: the roster entry stays key only', eff.find(e => e.pubkey === twinA.pk).name === null)
ok('a room entry carries its room', eff.filter(e => e.source === 'room').every(e => e.room === CH))
ok('a member of one room is not mentionable in another', !effectiveMentions(rm, { rooms }, CH2).some(e => e.pubkey === kerouac.pk) &&
  effectiveMentions(rm, { rooms }, CH2).some(e => e.pubkey === dennis.pk))
ok('with no channel, every may_post room is listed', effectiveMentions(rm, { rooms }).filter(e => e.source === 'room').length === 3)
ok('the flag off means no room entries', effectiveMentions(fixture('flagoff', { may_post: { ...mayPost, mention_rooms: false } }).load(), { rooms }, CH).every(e => e.source !== 'room'))
ok('the owner view lists room members with source room and their room', (v => v.filter(e => e.source === 'room').map(e => `${e.pubkey}:${e.room}`).join() ===
  [`${kerouac.pk}:${CH}`, `${twinA.pk}:${CH}`, `${dennis.pk}:${CH2}`].join() && v.find(e => e.pubkey === twinA.pk && e.source === 'room').name === null)(ownerView(rm, [], () => {}, rooms).mention))

// --- 6. the keyless side: resolve against the target room, re-read on every call ---
writeFileSync(roomsFile, '')
recordMentionRooms(rm, { rooms: { [CH]: [entry(kerouac, 'kerouac')], [CH2]: [] } })
const view = mentionView(rm)
ok('a room member resolves by name in its room', resolvePost(view(), { text: 'hi @kerouac', channel: CH }).mention?.join() === kerouac.pk)
const elsewhere = resolvePost(view(), { text: 'hi', channel: CH2, mention: ['kerouac'] })
ok('and is refused in another, saying both sources', elsewhere.code === 'NVOY_POST_MENTION_REFUSED' && elsewhere.message === `kerouac is not on may_post.mention or in room ${CH2}`)
ok('a reply resolves against the envelope\'s room', resolveReplyMention(view(), ['kerouac'], '', CH).mention?.join() === kerouac.pk &&
  resolveReplyMention(view(), ['kerouac'], '', CH2).code === 'NVOY_REPLY_MENTION_REFUSED')
ok('the agent is told the room members per room', capabilitySummary(view()).includes(`In room ${CH}, also its members: kerouac.`) &&
  capabilitySummary(view()).includes(`In room ${CH2}, also its members: none read yet.`))
recordMentionRooms(rm, { rooms: { [CH]: [entry(kerouac, 'kerouac'), entry(dennis, 'dennis')] } })
ok('a member recorded while running is mentionable on the next call, with no restart', resolvePost(view(), { text: '@dennis', channel: CH }).mention?.join() === dennis.pk)
writeFileSync(roomsFile, 'torn')
ok('a torn file keeps the last good view', mentionable(view().mayPost, CH).some(e => e.pubkey === dennis.pk))

// --- 7. the broker's shape check leaves room keys to the fresh roster ---
const row = { version: 1, type: 'post-request', id: 'a'.repeat(32), instance: 'rooms', channel: CH, mention: [kerouac.pk], content: 'hi', requested_at: Date.now() }
ok('with the flag, an off-list key passes the shape check for the roster to decide', validatePostRequest(row, rm) === row)
ok('without it, the same key is refused', /is not on may_post\.mention/.test(throws(() => validatePostRequest({ ...row, instance: 'flagoff2' }, fixture('flagoff2', { may_post: { ...mayPost, mention_rooms: false } }).load()))))
ok('a mention that is not a key is refused as overbroad', /invalid or overbroad/.test(throws(() => validatePostRequest({ ...row, mention: ['kerouac'] }, rm))))
ok('the reply shape check defers the same way', throws(() => validateReplyMention([kerouac.pk], rm, CH)) === '')

// --- 8. the broker end to end: a TLS grants relay and a Buzz relay that serves relay-signed lists ---
const certDir = join(root, 'tls'); mkdirSync(certDir)
const tls = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
  '-keyout', join(certDir, 'key.pem'), '-out', join(certDir, 'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8' })
if (tls.status !== 0) throw new Error('openssl could not make the test certificate')
const grantServer = createTlsServer({ key: readFileSync(join(certDir, 'key.pem')), cert: readFileSync(join(certDir, 'cert.pem')) }, (q, r) => { r.writeHead(404); r.end() })
await new Promise(done => grantServer.listen(0, '127.0.0.1', done))
new WebSocketServer({ server: grantServer }).on('connection', ws => ws.on('message', raw => {
  const m = JSON.parse(raw.toString()); if (m[0] === 'REQ') ws.send(JSON.stringify(['EOSE', m[1]]))
}))
const GRANTS = `wss://127.0.0.1:${grantServer.address().port}`

const buzz = { lists: { [CH]: [], [CH2]: [] }, profiles: [], stored: [], rosterReads: 0, refuseEvents: false, down: false }
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
new WebSocketServer({ server: http }).on('connection', ws => {
  const challenge = Buffer.from(generateSecretKey()).toString('hex')
  let authed = null
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      const ev = m[1], tag = n => ev.tags.find(t => t[0] === n)?.[1]
      if (!(verifyEvent(ev) && tag('challenge') === challenge && tag('relay') === RELAY && ev.pubkey === agent)) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      authed = ev.pubkey
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'REQ') {
      if (!authed) return ws.send(JSON.stringify(['CLOSED', m[1], 'auth-required: members only']))
      for (const f of m.slice(2)) {
        if (f.kinds?.includes(MEMBERS_KIND)) {
          buzz.rosterReads++
          if (buzz.down) return ws.send(JSON.stringify(['CLOSED', m[1], 'error: roster store down']))
          for (const e of buzz.lists[f['#d']?.[0]] || []) ws.send(JSON.stringify(['EVENT', m[1], e]))
        }
        if (f.kinds?.includes(0)) for (const e of buzz.profiles) if (f.authors.includes(e.pubkey)) ws.send(JSON.stringify(['EVENT', m[1], e]))
      }
      return ws.send(JSON.stringify(['EOSE', m[1]]))
    }
    if (m[0] === 'EVENT') {
      const ev = m[1]
      if (!authed || ev.pubkey !== authed || buzz.refuseEvents || !verifyEvent(ev)) return ws.send(JSON.stringify(['OK', ev.id, false, 'blocked: not now']))
      if (!buzz.stored.some(s => s.id === ev.id)) buzz.stored.push(ev)
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
  })
})

// attention.mjs runs with an env the broker builds; this preload lets it trust the test certificate.
const preload = join(root, 'trust.mjs')
writeFileSync(preload, `import { createRequire, syncBuiltinESMExports } from 'node:module'
const cp = createRequire(import.meta.url)('node:child_process'), spawnSync = cp.spawnSync
cp.spawnSync = (file, args, options = {}) => spawnSync(file, args, { ...options, env: { ...options.env, NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS } })
syncBuiltinESMExports()
`)
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })
const run = (args, env) => new Promise(done => {
  const child = spawn(process.execPath, ['--import', preload, ...args], { env: { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: join(certDir, 'cert.pem'), ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.on('data', c => { stdout += c }); child.stderr.on('data', c => { stderr += c })
  child.on('exit', status => done({ status, stdout, stderr }))
})
const bf = fixture('broker', { relays: [GRANTS], buzz: { relay: RELAY, channels: [CH, CH2], relay_signer: relayKey.pk }, may_post: mayPost }), bm = bf.load()
for (const f of ['post-requests.jsonl', 'mention-rooms.json', 'mention-grants.json']) writeFileSync(join(bf.run, f), '', { mode: 0o640 })
const post = request => run(['mcp/tools/instance-broker-post.mjs', '--instance', 'broker', '--request', request], { NVOY_INSTANCE_ROOT: bf.root, NVOY_BROKER_CREDENTIAL: credential })
const refresh = () => run(['mcp/tools/instance-broker-rooms.mjs', '--instance', 'broker'], { NVOY_INSTANCE_ROOT: bf.root, NVOY_BROKER_CREDENTIAL: credential })
const bview = mentionView(bm)
const queue = (text, mention, channel = CH) => queuePost(bview(), { text, mention, channel })
const sent = text => buzz.stored.filter(ev => ev.content === text)
let at = 100
const setRoom = (room, members) => { buzz.lists[room] = [list(room, [agent, ...members], ++at)] }

setRoom(CH, [kerouac.pk, leaver.pk]); setRoom(CH2, [dennis.pk])
buzz.profiles = [profile(kerouac, { name: 'kerouac' }), profile(leaver, { name: 'leaver' }), profile(dennis, { name: 'dennis' })]
let r = await refresh()
ok('the refresh records each room\'s members and their names, and logs only counts', r.status === 0 &&
  JSON.stringify(readMentionRooms(bm)[CH]) === JSON.stringify([entry(kerouac, 'kerouac'), entry(leaver, 'leaver')]) &&
  /3f1c2a4b 2, 9a8b7c6d 1/.test(r.stdout) && !r.stdout.includes(kerouac.pk))

let reads = buzz.rosterReads
const q1 = queue('room hello', ['kerouac'])
ok('the keyless side queues a room member by name', q1.ok?.mention?.join() === kerouac.pk)
r = await post(q1.ok.request)
ok('a room-derived key is read fresh, then signed and published with its p tag', r.status === 0 && sent('room hello').length === 1 &&
  JSON.stringify(sent('room hello')[0].tags.filter(t => t[0] === 'p')) === JSON.stringify([['p', kerouac.pk]]) && buzz.rosterReads > reads, r.stderr)

reads = buzz.rosterReads
const q2 = queue('listed only', ['neil'])
r = await post(q2.ok.request)
ok('a mention the manifest lists reads no roster', r.status === 0 && sent('listed only').length === 1 && buzz.rosterReads === reads)

const forge = (id, extra) => writeFileSync(join(bf.run, 'post-requests.jsonl'), readFileSync(join(bf.run, 'post-requests.jsonl'), 'utf8') +
  JSON.stringify({ version: 1, type: 'post-request', id, instance: 'broker', channel: CH, mention: [], content: 'forged', requested_at: Date.now(), ...extra }) + '\n')
forge('b'.repeat(32), { mention: [twinA.pk], content: 'not a member' })
r = await post('b'.repeat(32))
ok('a key in no source is refused, whatever the keyless side wrote', r.status === 1 && /post refused: [0-9a-f]{8} is not on may_post\.mention or in room/.test(r.stderr) && !sent('not a member').length)
forge('c'.repeat(32), { channel: CH2, mention: [kerouac.pk], content: 'wrong room' })
r = await post('c'.repeat(32))
ok('a member of one room is refused in another at the broker too', r.status === 1 && /post refused/.test(r.stderr) && !sent('wrong room').length)

const q3 = queue('after she left', ['leaver'])
ok('a member queued while in the room', q3.ok?.mention?.join() === leaver.pk)
setRoom(CH, [kerouac.pk])
ok('is still in the discovery file at drain', readMentionRooms(bm)[CH].some(e => e.pubkey === leaver.pk))
r = await post(q3.ok.request)
ok('leave between queue and send: the fresh roster refuses the post', r.status === 1 && /post refused/.test(r.stderr) && !sent('after she left').length)
ok('and the same read brings the discovery file up to date', !readMentionRooms(bm)[CH].some(e => e.pubkey === leaver.pk))

buzz.down = true
const q4 = queue('roster down', ['kerouac'])
r = await post(q4.ok.request)
ok('an unreadable roster holds the post, though the file lists the member', r.status === 1 && /room member list unavailable: .*held for retry/.test(r.stderr) &&
  !/post refused/.test(r.stderr) && !sent('roster down').length && readMentionRooms(bm)[CH].some(e => e.pubkey === kerouac.pk))
buzz.down = false
buzz.lists[CH] = [list(CH, [agent, kerouac.pk], ++at, { signer: impostor.sk })]
r = await post(q4.ok.request)
ok('so does a roster no pinned-key list vouches for', r.status === 1 && /no member list for room .*held for retry/.test(r.stderr) && !sent('roster down').length)
setRoom(CH, [kerouac.pk])
r = await post(q4.ok.request)
ok('the held post goes once the roster reads', r.status === 0 && sent('roster down').length === 1)

const q5 = queue('signed then refused', ['kerouac'])
buzz.refuseEvents = true
r = await post(q5.ok.request)
const record = join(bf.state, 'posts', `${q5.ok.request}.json`)
ok('a post the relay refuses stays signed and retryable', r.status === 1 && /remains retryable/.test(r.stderr) && existsSync(record) && !!JSON.parse(readFileSync(record, 'utf8')).event)
buzz.refuseEvents = false
setRoom(CH, [])
reads = buzz.rosterReads
r = await post(q5.ok.request)
ok('its retry reads the roster again and refuses the member who has gone', r.status === 1 && /post refused/.test(r.stderr) && buzz.rosterReads > reads && !sent('signed then refused').length)
setRoom(CH, [kerouac.pk])
r = await post(q5.ok.request)
ok('and publishes the signed event once they are back', r.status === 0 && sent('signed then refused').length === 1 && sent('signed then refused')[0].id === JSON.parse(readFileSync(record, 'utf8')).event.id)
reads = buzz.rosterReads
r = await post(q5.ok.request)
ok('a replay of a published post reads nothing and posts nothing new', r.status === 0 && /"replay":true/.test(r.stdout) && buzz.rosterReads === reads && sent('signed then refused').length === 1)

// The reply actuator needs a live admission receipt, so its roster check is held to the source here;
// confirmMembers and validateReplyMention are proven above.
const replySource = readFileSync('mcp/tools/instance-broker-reply.mjs', 'utf8')
ok('the reply path confirms room-derived keys before its claim and again in the publishing session',
  replySource.indexOf('try { await confirmRoom(check) }') > 0 && replySource.indexOf('try { await confirmRoom(check) }') < replySource.indexOf('const current = Array.isArray(policy.admissions)') &&
  replySource.indexOf('if (roomDerived.length) await confirmRoom(session)') < replySource.indexOf('const ok = await session.publishSigned(record.event)') &&
  /roomDerived = manifest\.mayPost\.mentionRooms \? offList\(allowed, request\.mention\) : \[\]/.test(replySource))
ok('a refused or unreadable roster dies before the reply is claimed or published',
  /catch \(e\) \{ die\(`room member list unavailable: \$\{e\.message\}; held for retry`\) \}/.test(replySource) && /die\(`reply refused: \$\{absent\.slice\(0, 8\)\}/.test(replySource))
ok('init provisions the snapshot broker-owned and worker-group readable, only with the flag',
  /if \(m\.mayPost\?\.mentionRooms\) provisionFile\(`\$\{m\.runtimeDir\}\/mention-rooms\.json`, m\.brokerUid, m\.workerHandoffGid, 0o640/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')))

// --- 9. the channel MCPs see a member recorded while they run ---
const cf = fixture('channel', { may_post: mayPost }), cm = cf.load()
for (const f of ['admitted-tasks.jsonl', 'reply-requests.jsonl', 'post-requests.jsonl', 'mention-grants.json', 'mention-rooms.json']) writeFileSync(join(cf.run, f), '', { mode: 0o640 })
recordMentionRooms(cm, { rooms: { [CH]: [entry(kerouac, 'kerouac')], [CH2]: [] } })
mkdirSync(join(cf.run, 'claude-channel-state'))
const child = spawn(process.execPath, [resolve('mcp/tools/claude-channel.mjs'), '--instance', 'channel', '--poll-ms', '250', '--renotify-ms', '60000'],
  { env: { ...process.env, NVOY_INSTANCE_ROOT: cf.root }, stdio: ['pipe', 'pipe', 'pipe'] })
const notices = [], results = new Map()
let buf = ''
child.stdout.on('data', d => {
  buf += d
  const lines = buf.split('\n'); buf = lines.pop()
  for (const line of lines) {
    let m; try { m = JSON.parse(line) } catch { continue }
    if (m.method === 'notifications/claude/channel' && m.params?.meta?.capabilities) notices.push(m.params)
    if (m.id != null) results.set(m.id, m.result)
  }
})
const say = frame => child.stdin.write(JSON.stringify(frame) + '\n')
const call = async (id, name, args) => { say({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }); for (let i = 0; i < 40 && !results.has(id); i++) await sleep(50); return JSON.parse(results.get(id)?.content?.[0]?.text || '{}') }
try {
  say({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'rooms-test', version: '0' } } })
  await sleep(300)
  say({ jsonrpc: '2.0', method: 'notifications/initialized' })
  await sleep(800)
  ok('Claude: a new session is told the room members', notices.length === 1 && notices[0].content.includes(`In room ${CH}, also its members: kerouac.`))
  ok('Claude: a key not yet in the room is refused', (await call(2, 'nvoy_channel_post', { text: 'hi', mention: ['dennis'] })).code === 'NVOY_POST_MENTION_REFUSED')
  recordMentionRooms(cm, { rooms: { [CH]: [entry(kerouac, 'kerouac'), entry(dennis, 'dennis')] } })
  await sleep(800)
  ok('Claude: a member who joins is told once, under a new hash', notices.length === 2 && notices[1].content.includes('kerouac, dennis') &&
    notices[1].meta.capabilities !== notices[0].meta.capabilities)
  const queued = await call(3, 'nvoy_channel_post', { text: 'hi @dennis' })
  ok('Claude: and is mentionable on the next call, with no restart', queued.queued === true && queued.mention?.join() === dennis.pk)
} finally { child.kill('SIGKILL') }

const xf = fixture('codex', { may_post: mayPost }), xm = xf.load()
for (const f of ['admitted-tasks.jsonl', 'reply-requests.jsonl', 'post-requests.jsonl', 'mention-grants.json', 'mention-rooms.json']) writeFileSync(join(xf.run, f), '', { mode: 0o640 })
recordMentionRooms(xm, { rooms: { [CH]: [entry(kerouac, 'kerouac')] } })
mkdirSync(join(xf.run, 'codex-mcp-state'))
const client = new Client({ name: 'rooms-test', version: '0.1.0' })
await client.connect(new StdioClientTransport({ command: process.execPath, args: [resolve('mcp/tools/codex-channel-mcp.mjs'), '--instance', 'codex'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: xf.root }, stderr: 'pipe' }))
try {
  const before = await client.callTool({ name: 'nvoy_channel_post', arguments: { text: 'hi', mention: ['dennis'] } })
  recordMentionRooms(xm, { rooms: { [CH]: [entry(kerouac, 'kerouac'), entry(dennis, 'dennis')] } })
  const after = await client.callTool({ name: 'nvoy_channel_post', arguments: { text: 'hi', mention: ['dennis'] } })
  const unknown = await client.callTool({ name: 'nvoy_channel_post', arguments: { text: 'hi @nobody' } })
  ok('Codex: refused before the join, queued after it, no restart', before.isError === true && JSON.parse(before.content[0].text).code === 'NVOY_POST_MENTION_REFUSED' &&
    !after.isError && JSON.parse(after.content[0].text).mention?.join() === dennis.pk)
  ok('Codex: an @name that reaches no one lists the room members as mentionable', JSON.parse(unknown.content[0].text).mentionable?.includes('dennis'))
} finally { await client.close() }

grantServer.close(); http.close()
console.log(fails ? `\n${fails} FAILED` : `\nmention-rooms: all ${passes} passed`)
process.exit(fails ? 1 : 0)
