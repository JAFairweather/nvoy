// #382: an inbox must not pass by silence. "No messages" and "I could not tell" print the same
// and are acted on the same, so every assertion here is paired: the alarm fires for the case it
// names, AND a healthy read still comes back clean. A guard that only ever refuses cannot be told
// apart from one that refuses everything.

import { spawn } from 'node:child_process'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import * as nip44 from 'nostr-tools/nip44'
import { inboxVerdict, isSignerFault } from '../mcp/tools/inbox_reach.mjs'
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
const healthy = { reachedWraps: ['wss://a'], relayCount: 1, answered10050: ['wss://a'], dmRelayLists: 1, total: 0 }
const clean = inboxVerdict(healthy)
ok('a reachable identity with an empty inbox is a RESULT, not a doubt', clean.code === 0 && !clean.inconclusive.length)

const noRelay = inboxVerdict({ ...healthy, reachedWraps: [], unreachable: ['wss://a — timed out after 8s'] })
ok('no relay answering is inconclusive', noRelay.code === 3)
ok('  …and the reason says nothing was read, naming the relay',
  /no relay answered/.test(noRelay.inconclusive[0]) && /wss:\/\/a — timed out after 8s/.test(noRelay.inconclusive[0]))

const noList = inboxVerdict({ ...healthy, dmRelayLists: 0 })
ok('an empty inbox with no kind:10050 is inconclusive', noList.code === 3)
ok('  …and the reason distinguishes unreachable from empty',
  /nowhere to deliver to/.test(noList.inconclusive[0]) && /not an empty inbox/.test(noList.inconclusive[0]))
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

await relay.close()

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
