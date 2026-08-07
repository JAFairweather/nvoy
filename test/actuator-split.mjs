// AD-12 has two actuators, and until now the daemon held both identically. A public event is
// permanent and world-readable, so it is enacted only by a discrete signed approval. A private
// channel-carry reply is a sealed answer into a channel the identity is already admitted to:
// waggle carries it across the boundary, and the live admit/task/task-relay chain that admitted it
// IS the authorisation to post. This suite pins that split in both directions, because a guard
// that refuses everything and a guard that refuses nothing fail identically from the outside.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateSecretKey, getPublicKey, finalizeEvent, getEventHash } from 'nostr-tools/pure'
import { validateOutboundRecord } from '../mcp/tools/outbound_record.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }

const root = mkdtempSync(join(tmpdir(), 'nvoy-actuator-'))
const key = generateSecretKey(), pubkey = getPublicKey(key)
const wrapKey = generateSecretKey()

const seal = { kind: 13, pubkey, created_at: 1, tags: [], content: 'ciphertext' }
const fingerprint = getEventHash(seal)
const wrap = finalizeEvent({ kind: 1059, created_at: 2, tags: [['p', 'a'.repeat(64)]], content: 'x' }, wrapKey)
const base = { version: 2, request_digest: 'b'.repeat(64), request_id: 'c'.repeat(32), fingerprint, unsigned_seal: seal }
const check = record => { try { validateOutboundRecord(record); return null } catch (e) { return e.message } }

// --- the record schema: exactly one enactment path ------------------------------------------
ok('an unenacted proposal is valid with neither approval nor enactment',
  check({ ...base, wrap: null, published: false }) === null)

ok('an unenacted proposal claiming an enactment path is refused',
  /claims enactment/.test(check({ ...base, wrap: null, enactment: 'channel-carry-direct', published: false }) || ''))

ok('a public event enacted by a signed approval remains valid',
  check({ ...base, wrap, approval_id: 'd'.repeat(64), published: false }) === null)

ok('a private reply enacted directly is valid with no approval id',
  check({ ...base, wrap, enactment: 'channel-carry-direct', published: false }) === null)

// The hole this field exists to close: an enacted record justified by nothing at all.
ok('an enacted record with neither approval nor enactment is still refused',
  /lacks a valid approval or names two enactment paths/.test(check({ ...base, wrap, published: false }) || ''))

// ...and its mirror: a direct enactment must not also carry an approval id, or a private reply
// could launder an approval nobody verified.
ok('an enacted record naming BOTH paths is refused',
  /names two enactment paths/.test(check({ ...base, wrap, enactment: 'channel-carry-direct', approval_id: 'd'.repeat(64), published: false }) || ''))

ok('an unknown enactment path is refused rather than treated as direct',
  /unknown enactment path/.test(check({ ...base, wrap, enactment: 'whatever-i-like', published: false }) || ''))

ok('an enacted record with an invalid wrap is refused regardless of enactment',
  /lacks a valid wrap/.test(check({ ...base, wrap: { ...wrap, sig: 'e'.repeat(128) }, enactment: 'channel-carry-direct', published: false }) || ''))

// --- the actuator: --direct is confined to private channel-carry replies ---------------------
// Asserted against the source, because the branch that matters is the one that refuses to enact a
// public event without approval, and it must live in the signer rather than in its caller.
const replySource = readFileSync('mcp/tools/instance-broker-reply.mjs', 'utf8')
ok('the actuator refuses direct enactment for anything that is not a channel-carry reply',
  /if \(!channelCarry\) die\('direct enactment is permitted only for a private channel-carry reply/.test(replySource))

ok('the actuator refuses direct enactment of a proposal already bound to an approval',
  /if \(record\.approval_id\) die\('this proposal is already bound to an approval/.test(replySource))

ok('exactly one of --prepare, --direct and --approval is accepted',
  /\[prepareOnly, !!approvalPath, direct\]\.filter\(Boolean\)\.length !== 1/.test(replySource))

ok('the actuator reports which actuator applies rather than leaving the daemon to infer it',
  /approval_required: !channelCarry/.test(replySource) && /nostr-private-reply/.test(replySource) && /nostr-public-event/.test(replySource))

// --- the daemon: acts on the actuator's verdict, and only the permissive one is narrow ---------
const daemonSource = readFileSync('mcp/tools/instance-broker-daemon.mjs', 'utf8')
ok('the daemon enacts directly only when the actuator reports a private reply needing no approval',
  /verdict\?\.approval_required === false && verdict\?\.action === 'nostr-private-reply'/.test(daemonSource))

ok('the daemon still announces and waits for anything else',
  /awaiting discrete approval/.test(daemonSource))

ok('a failed direct enactment is classified terminal-or-retry rather than looping',
  /isTerminalReplyFailure\(stderr\)/.test(daemonSource) && /recordTerminalReply\(/.test(daemonSource))

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
