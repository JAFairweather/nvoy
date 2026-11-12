// #382: an inbox must not pass by silence. "No messages" and "I could not tell" print the same
// and are acted on the same, so every assertion here is paired: the alarm fires for the case it
// names, AND a healthy read still comes back clean. A guard that only ever refuses cannot be told
// apart from one that refuses everything.

import { spawn } from 'node:child_process'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import * as nip44 from 'nostr-tools/nip44'
import { advertisedRelays, inboxVerdict, isSignerFault, normalizeRelay } from '../mcp/tools/inbox_reach.mjs'
import { WebSocketServer } from 'ws'
import { startWsRelay } from './wsrelay.mjs'

let pass = 0, fail = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? pass++ : fail++ }

// ---- the discrimination the whole exit code rests on -------------------------------------------
//
// This cannot be reached through a live run: makeBunkerSigner requires a wss:// relay and the test
// relay is ws://, so a real signer refusal is unstageable here. Asserted directly instead — which
// is the only reason the classifier was pulled out of inbox.mjs at all.
ok('a remote Bunker refusal counts as a signer fault', isSignerFault('bunker: user rejected'))
ok('a NIP-46 timeout counts as a signer fault', isSignerFault('nip46 nip44_decrypt timed out'))
ok('a closed signer counts as a signer fault', isSignerFault('nip46 signer closed'))
// The other direction, and the expensive one. Every wrap addressed to somebody else lands in the
// same catch; if those counted, a normal run would report itself inconclusive every time and the
// exit code would mean nothing.
ok('a wrap meant for another key is NOT a signer fault', !isSignerFault('invalid MAC'))
ok('a malformed payload is NOT a signer fault', !isSignerFault('Unexpected end of JSON input'))
ok('the word bunker mid-message is NOT a signer fault', !isSignerFault('decrypt failed for bunker: peer'))
ok('a missing reason is NOT a signer fault', !isSignerFault(undefined))

// ---- the verdict, both directions --------------------------------------------------------------
const healthy = { reachedWraps: ['wss://a'], relayCount: 1, answered10050: ['wss://a'], dmRelayLists: 1, dmRelays: ['wss://a'], total: 0 }
const clean = inboxVerdict(healthy)
ok('a reachable identity with an empty inbox is a RESULT, not a doubt', clean.code === 0 && !clean.inconclusive.length)

// ---- the fourth signer shape, which the classifier cannot see (review of #183) ------------------
//
// nip46-signer.mjs rejects verbatim whatever `pool.publish` threw, and its finalizeEvent /
// nip44.encrypt calls sit outside that try. "WebSocket is not open" matches none of the three
// shapes, so a signer failing that way looked exactly like an empty inbox. This is caught without
// reading the error at all — the envelopes were `#p`-filtered to this key, so none of them opening
// is a fact about this run.
const unopenable = inboxVerdict({ ...healthy, envelopesSeen: 5, opened: 0 })
ok('envelopes addressed to this key that NONE opened is inconclusive, with no fault recognised',
  unopenable.code === 3)
ok('  …and the reason counts them and refuses the "empty inbox" reading',
  /5 envelope\(s\) addressed to this key/.test(unopenable.inconclusive[0]) &&
  /this is not an empty inbox/.test(unopenable.inconclusive[0]))
// Both directions, and these are the ones that stop it becoming "always inconclusive".
ok('opening even one of them is a RESULT', inboxVerdict({ ...healthy, envelopesSeen: 5, opened: 1 }).code === 0)
ok('seeing no envelopes at all is a genuinely empty inbox, not a doubt',
  inboxVerdict({ ...healthy, envelopesSeen: 0, opened: 0 }).code === 0)
// A wrap can open cleanly and still be filtered out by --since-min, so `opened` must be counted
// before that filter and must NOT be inferred from the printed total. If it were, a healthy read
// of nothing but older mail would report as a failure to open anything.
ok('a wrap that opened but fell outside the window is not reported as unopenable',
  inboxVerdict({ ...healthy, envelopesSeen: 3, opened: 3, total: 0 }).code === 0)

const noRelay = inboxVerdict({ ...healthy, reachedWraps: [], unreachable: ['wss://a — timed out after 8s'] })
ok('no relay answering is inconclusive', noRelay.code === 3)
ok('  …and the reason says nothing was read, naming the relay',
  /no relay answered/.test(noRelay.inconclusive[0]) && /wss:\/\/a — timed out after 8s/.test(noRelay.inconclusive[0]))

const noList = inboxVerdict({ ...healthy, dmRelayLists: 0 })
ok('an empty inbox with no kind:10050 is inconclusive', noList.code === 3)
ok('  …and the reason distinguishes unreachable from empty',
  /nowhere to deliver to/.test(noList.inconclusive[0]) && /not an empty inbox/.test(noList.inconclusive[0]))
// A list that exists but points elsewhere (My Dude, PR 361): NIP-17 senders publish only to the
// advertised relays, so an empty read of a different relay says nothing about that mail.
const elsewhere = inboxVerdict({ ...healthy, dmRelays: ['wss://other'] })
ok('an empty inbox whose kind:10050 advertises only an unqueried relay is inconclusive',
  elsewhere.code === 3 && /wss:\/\/other/.test(elsewhere.inconclusive[0]) && /did not query/.test(elsewhere.inconclusive[0]))
const noTags = inboxVerdict({ ...healthy, dmRelays: [] })
ok('an empty inbox whose kind:10050 names no relay is inconclusive',
  noTags.code === 3 && /names no relay/.test(noTags.inconclusive[0]))
ok('one advertised relay unqueried among several is still inconclusive',
  inboxVerdict({ ...healthy, dmRelays: ['wss://a', 'wss://other'] }).code === 3)
ok('an advertised relay that was queried but never answered is inconclusive',
  inboxVerdict({ ...healthy, reachedWraps: ['wss://b'], relayCount: 2, dmRelays: ['wss://a'] }).code === 3)
ok('every advertised relay answered: clean, case and a trailing slash notwithstanding',
  inboxVerdict({ ...healthy, reachedWraps: ['wss://A.example/'], relayCount: 1, dmRelays: ['wss://a.example'] }).code === 0)
ok('messages that arrived are not second-guessed by where the list points',
  inboxVerdict({ ...healthy, dmRelays: ['wss://other'], total: 1 }).code === 0)
ok('normalizeRelay folds scheme and host case and the root slash, and nothing else',
  normalizeRelay(' WSS://Relay.X/ ') === 'wss://relay.x' && normalizeRelay('wss://relay.x') === 'wss://relay.x')
ok('  …but keeps path and query case, and a non-root trailing slash',
  normalizeRelay('wss://relay.x/Inbox') === 'wss://relay.x/Inbox' && normalizeRelay('wss://relay.x/inbox/') === 'wss://relay.x/inbox/' &&
  normalizeRelay('wss://relay.x/?Room=A') === 'wss://relay.x?Room=A')
ok('a list advertising /inbox does not match a wrap answer from /Inbox (My Dude, PR 361)',
  inboxVerdict({ ...healthy, reachedWraps: ['wss://relay.example/Inbox'], dmRelays: ['wss://relay.example/inbox'] }).code === 3)
ok('  …nor a different query', inboxVerdict({ ...healthy, reachedWraps: ['wss://relay.example/?a=1'], dmRelays: ['wss://relay.example/?a=2'] }).code === 3)
ok('  …while host case, the root slash and a default port are the same relay',
  inboxVerdict({ ...healthy, reachedWraps: ['wss://Relay.Example/'], dmRelays: ['wss://relay.example:443'] }).code === 0)
ok('a non-URL advertised entry cannot match a real relay',
  inboxVerdict({ ...healthy, dmRelays: ['not a url'] }).code === 3)
ok('the NEWEST kind:10050 wins, and only relay tags count',
  advertisedRelays([{ created_at: 1, tags: [['relay', 'wss://old']] },
    { created_at: 2, tags: [['relay', 'wss://new'], ['p', 'x'], ['relay']] }]).join() === 'wss://new')
ok('no kind:10050 yields no relays', advertisedRelays([]).length === 0)

// A walk that hit its page cap while still progressing is a partial read (My Dude, PR 362).
const capped = inboxVerdict({ ...healthy, walkCapped: ['wss://a'] })
ok('a relay whose page walk was cut by the cap makes an empty inbox inconclusive',
  capped.code === 3 && /page cap/.test(capped.inconclusive[0]) && /wss:\/\/a/.test(capped.inconclusive[0]))
ok('  …and it holds even when messages arrived', inboxVerdict({ ...healthy, walkCapped: ['wss://a'], total: 3 }).code === 3)
ok('  …and no cap hit stays clean', inboxVerdict({ ...healthy, walkCapped: [] }).code === 0)

// Asserting the REASON, not just the code: these two failures need different actions from the
// operator — publish a relay list, versus go and find out why the relays are down.
ok('  …and it is not the same reason as an unreachable relay', noList.inconclusive[0] !== noRelay.inconclusive[0])

const refused = inboxVerdict({ ...healthy, signerRefusals: ['bunker: user rejected'], envelopesSeen: 4 })
ok('a signer refusal is inconclusive even when relays answered', refused.code === 3)
ok('  …and the reason counts the envelopes and quotes the first refusal',
  /on 1 of 4 envelope\(s\)/.test(refused.inconclusive[0]) && /bunker: user rejected/.test(refused.inconclusive[0]))

// The 10050 rule must fire only on an EMPTY read. Messages arriving proves delivery works whatever
// the relay list says, so the same condition has to drop from alarm to note.
const arrivedAnyway = inboxVerdict({ ...healthy, dmRelayLists: 0, total: 2 })
ok('messages that arrived without a kind:10050 are a NOTE, not an alarm',
  arrivedAnyway.code === 0 && arrivedAnyway.notes.some(n => /some other route/.test(n)))

// `answered10050` gates both 10050 branches, so nobody answering that query skipped the whole
// reachability question silently — pass-by-silence inside the PR about pass-by-silence.
const noAnswer = inboxVerdict({ ...healthy, answered10050: [], dmRelayLists: 0, dmRelays: [] })
ok('an EMPTY read with no kind:10050 answer from anyone is inconclusive (Dennis, PR 361)',
  noAnswer.code === 3 && /relays senders deliver to are unknown/.test(noAnswer.inconclusive[0]))
const noAnswerButMail = inboxVerdict({ ...healthy, answered10050: [], dmRelayLists: 0, dmRelays: [], total: 2 })
ok('  …but with messages in hand it stays a NOTE — the doubt is about the check, not the inbox',
  noAnswerButMail.code === 0 && noAnswerButMail.notes.some(n => /DM reachability was not checked/.test(n)))
// A list that arrived from a relay which never sent EOSE is still a list: judge it, do not skip it.
ok('a list obtained without an EOSE is still checked against the relays that answered',
  inboxVerdict({ ...healthy, answered10050: [], dmRelays: ['wss://other'] }).code === 3 &&
  inboxVerdict({ ...healthy, answered10050: [], dmRelays: ['wss://a'] }).code === 0)
ok('  …and it stays quiet when the query WAS answered', !clean.notes.some(n => /was not checked/.test(n)))

const partial = inboxVerdict({ ...healthy, relayCount: 3, unreachable: ['wss://b — connection error'] })
ok('partial reach stays conclusive but is said out loud',
  partial.code === 0 && partial.notes.some(n => /partial reach: 1\/3/.test(n)))

// ---- live: the tool itself, end to end ---------------------------------------------------------
//
// Spawned ASYNCHRONOUSLY. wsrelay runs on this process's event loop, so spawnSync deadlocks —
// inbox waits for an EOSE the relay cannot send until the test resumes, and the test cannot resume
// until inbox exits. It surfaces as an 8s timeout and "no relay answered", which reads exactly
// like a relay that was genuinely down.
const runInbox = env => new Promise(res => {
  const p = spawn(process.execPath, ['mcp/tools/inbox.mjs'], {
    env: { ...process.env, NVOY_TRUSTED_SENDERS_FILE: '/nonexistent/trusted-senders.json', ...env },
  })
  let stdout = '', stderr = ''
  p.stdout.on('data', d => stdout += d)
  p.stderr.on('data', d => stderr += d)
  p.on('close', status => res({ status, stdout, stderr }))
})

const sk = generateSecretKey(), pk = getPublicKey(sk), nsec = nip19.nsecEncode(sk)
const relay = await startWsRelay(0)
const base = { NVOY_NSEC: nsec, NVOY_RELAYS: relay.url }

const empty = await runInbox(base)
ok('a live empty inbox with no kind:10050 exits 3, not 0', empty.status === 3)
ok('  …and refuses to be read as "no messages"', /must NOT be read as "no messages"/.test(empty.stderr))

// Now publish the DM relay list the previous case was missing, and nothing else. Same relay, same
// key, same empty inbox — only the reachability evidence changed.
relay.store.publish(finalizeEvent({ kind: 10050, created_at: Math.floor(Date.now() / 1000),
  tags: [['relay', relay.url]], content: '' }, sk))
const reachable = await runInbox(base)
ok('publishing a kind:10050 turns the same empty inbox into a clean exit 0', reachable.status === 0)
ok('  …and says nothing about being inconclusive', !/INCONCLUSIVE/.test(reachable.stderr))

// The same empty inbox, but the newest list now advertises a relay this run does not query.
relay.store.publish(finalizeEvent({ kind: 10050, created_at: Math.floor(Date.now() / 1000) + 5,
  tags: [['relay', 'ws://127.0.0.1:2']], content: '' }, sk))
const elsewhereLive = await runInbox(base)
ok('a live empty inbox whose list points at another relay exits 3', elsewhereLive.status === 3)
ok('  …and names the unqueried relay', /127\.0\.0\.1:2/.test(elsewhereLive.stderr) && /did not query/.test(elsewhereLive.stderr))
relay.store.publish(finalizeEvent({ kind: 10050, created_at: Math.floor(Date.now() / 1000) + 10,
  tags: [], content: '' }, sk))
const noTagsLive = await runInbox(base)
ok('a live empty inbox whose newest list names no relay exits 3', noTagsLive.status === 3 && /names no relay/.test(noTagsLive.stderr))
relay.store.publish(finalizeEvent({ kind: 10050, created_at: Math.floor(Date.now() / 1000) + 15,
  tags: [['relay', relay.url]], content: '' }, sk))
const backLive = await runInbox(base)
ok('republishing a list that names the queried relay clears it', backLive.status === 0)

// Dennis, PR 361: a relay that answers the wrap query and never answers the kind:10050 query. The
// inbox is empty and the delivery relays are unknown, so the read must not exit 0. (Takes the 8s
// idle timeout, because the dm subscription is simply never closed out.)
const mute = await new Promise(res => {
  const server = new WebSocketServer({ port: 0, host: '127.0.0.1' })
  server.on('connection', ws => ws.on('message', raw => {
    const [type, sub, filter] = JSON.parse(raw.toString())
    if (type === 'REQ' && (filter.kinds || [])[0] === 1059) ws.send(JSON.stringify(['EOSE', sub]))
  }))
  server.on('listening', () => res(server))
})
const unanswered = await runInbox({ NVOY_NSEC: nsec, NVOY_RELAYS: `ws://127.0.0.1:${mute.address().port}` })
ok('a live empty inbox whose kind:10050 query is never answered exits 3', unanswered.status === 3)
ok('  …for that reason, and not by printing a bare "(none)" verdict',
  /INCONCLUSIVE/.test(unanswered.stderr) && /kind:10050 query/.test(unanswered.stderr))
mute.close()

// A relay that PAGES (the repo stub ignores until/limit), holding more in-window wraps than the
// walk is allowed to fetch. Foreign wraps cannot be opened, so every run here also says "none
// opened"; the assertions are on the page-cap reason itself, which only a cut walk may print.
const nowSec = Math.floor(Date.now() / 1000)
const pagedWraps = Array.from({ length: 5 }, (_, i) => ({
  id: String(i + 1).padStart(64, '0'), kind: 1059, created_at: nowSec - 10 * (i + 1), pubkey: 'e'.repeat(64),
  content: 'x', sig: 'f'.repeat(128), tags: [['p', pk]],
}))
const pager = await new Promise(res => {
  const server = new WebSocketServer({ port: 0, host: '127.0.0.1' })
  server.on('connection', ws => ws.on('message', raw => {
    const [type, sub, filter] = JSON.parse(raw.toString())
    if (type !== 'REQ') return
    const url = `ws://127.0.0.1:${server.address().port}`
    const events = (filter.kinds || [])[0] === 10050
      ? [finalizeEvent({ kind: 10050, created_at: nowSec, tags: [['relay', url]], content: '' }, sk)]
      : pagedWraps.filter(w => (!filter.until || w.created_at <= filter.until) && (!filter.since || w.created_at >= filter.since))
          .sort((a, b) => b.created_at - a.created_at).slice(0, filter.limit || 1000)
    for (const event of events) ws.send(JSON.stringify(['EVENT', sub, event]))
    ws.send(JSON.stringify(['EOSE', sub]))
  }))
  server.on('listening', () => res(server))
})
const pagerEnv = { NVOY_NSEC: nsec, NVOY_RELAYS: `ws://127.0.0.1:${pager.address().port}`, NVOY_INBOX_FETCH_PAGE: '2' }
const cutShort = await runInbox({ ...pagerEnv, NVOY_INBOX_MAX_PAGES: '2' })
ok('a live relay with more in-window wraps than the page cap allows exits 3 for the page cap',
  cutShort.status === 3 && /page cap/.test(cutShort.stderr))
const walkedOut = await runInbox({ ...pagerEnv, NVOY_INBOX_MAX_PAGES: '10' })
ok('  …and the same relay walked to its end does NOT report a page cap', !/page cap/.test(walkedOut.stderr))
pager.close()

// Equal timestamps across a page boundary (My Dude, PR 362): the relay returns ties in id order and
// honours an INCLUSIVE until, so a walk that asked below the oldest timestamp would never see the
// tie that did not fit. Three wraps share one timestamp, page size 2.
const tieAt = nowSec - 60
const tied = Array.from({ length: 3 }, (_, i) => ({
  id: String(i + 1).padStart(64, '0'), kind: 1059, created_at: tieAt, pubkey: 'e'.repeat(64),
  content: 'x', sig: 'f'.repeat(128), tags: [['p', pk]],
}))
const served = []
const tiePager = await new Promise(res => {
  const server = new WebSocketServer({ port: 0, host: '127.0.0.1' })
  server.on('connection', ws => ws.on('message', raw => {
    const [type, sub, filter] = JSON.parse(raw.toString())
    if (type !== 'REQ') return
    const url = `ws://127.0.0.1:${server.address().port}`
    const events = (filter.kinds || [])[0] === 10050
      ? [finalizeEvent({ kind: 10050, created_at: nowSec, tags: [['relay', url]], content: '' }, sk)]
      : tied.filter(w => (!filter.until || w.created_at <= filter.until) && (!filter.since || w.created_at >= filter.since))
          .slice(0, filter.limit || 1000)
    if ((filter.kinds || [])[0] !== 10050) served.push(events.map(e => e.id.slice(-1)).join(''))
    for (const event of events) ws.send(JSON.stringify(['EVENT', sub, event]))
    ws.send(JSON.stringify(['EOSE', sub]))
  }))
  server.on('listening', () => res(server))
})
const tieEnv = { NVOY_NSEC: nsec, NVOY_RELAYS: `ws://127.0.0.1:${tiePager.address().port}`, NVOY_INBOX_MAX_PAGES: '6' }
// 3 ties, page 4: all fit with room to spare, the repeat page is short -> a finished walk. (A page
// EXACTLY full of ties is ambiguous by construction and counts as stalled.)
const fits = await runInbox({ ...tieEnv, NVOY_INBOX_FETCH_PAGE: '4' })
ok('ties that fit in one page are a finished walk (no page-cap reason)', !/page cap/.test(fits.stderr))
// 3 ties, page 2: the third can never be reached, and the read must say so.
const overflow = await runInbox({ ...tieEnv, NVOY_INBOX_FETCH_PAGE: '2' })
ok('more ties than a page holds exits 3 and says the read is partial', overflow.status === 3 && /page cap/.test(overflow.stderr))
tiePager.close()

// A relay that is not there at all. Port 1 refuses the connection immediately.
const dead = await runInbox({ ...base, NVOY_RELAYS: 'ws://127.0.0.1:1' })
ok('an unreachable relay exits 3', dead.status === 3)
ok('  …for the relay reason, not the relay-list reason',
  /no relay answered/.test(dead.stderr) && !/nowhere to deliver to/.test(dead.stderr))

// A real sealed message, built the way relay-send builds one. The point is that a run which
// actually reads something exits 0 — the exit code tracks reach, not emptiness.
const senderSk = generateSecretKey(), senderPk = getPublicKey(senderSk)
const now = Math.floor(Date.now() / 1000)
const rumor = { kind: 14, pubkey: senderPk, created_at: now, tags: [], content: 'a message that really arrived' }
rumor.id = getEventHash(rumor)
const seal = finalizeEvent({ kind: 13, created_at: now, tags: [],
  content: nip44.encrypt(JSON.stringify(rumor), nip44.getConversationKey(senderSk, pk)) }, senderSk)
const wsk = generateSecretKey()
relay.store.publish(finalizeEvent({ kind: 1059, created_at: now, tags: [['p', pk]],
  content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(wsk, pk)) }, wsk))

const delivered = await runInbox(base)
ok('an inbox holding a real sealed message exits 0', delivered.status === 0)
ok('  …and prints the message body it opened', delivered.stdout.includes('a message that really arrived'))

// The fourth-shape hole, live and without a signer: a wrap p-tagged at this key whose content is
// not openable at all. envelopesSeen goes up, opened does not, and no error shape is recognised —
// which is exactly what an unrecognised signer fault looks like from here.
const junkRelay = await startWsRelay(0)
const junkKey = generateSecretKey()
junkRelay.store.publish(finalizeEvent({ kind: 1059, created_at: Math.floor(Date.now() / 1000),
  tags: [['p', pk]], content: 'not nip44 ciphertext at all' }, junkKey))
junkRelay.store.publish(finalizeEvent({ kind: 10050, created_at: Math.floor(Date.now() / 1000),
  tags: [['relay', junkRelay.url]], content: '' }, sk))
const unopened = await runInbox({ NVOY_NSEC: nsec, NVOY_RELAYS: junkRelay.url })
ok('a live wrap addressed here that cannot be opened exits 3, not 0', unopened.status === 3)
ok('  …and says so without blaming the signer, which reported nothing',
  /addressed to this key were read and none opened/.test(unopened.stderr) && !/signer refused/.test(unopened.stderr))
await junkRelay.close()

await relay.close()

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
