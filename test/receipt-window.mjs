// #150: the reply capability expired five minutes after ADMISSION, but admission and delivery
// are deliberately decoupled — a wake exists so a session can read an envelope later. The clock
// therefore ran almost entirely before the agent could act, and any wake not answered inside it
// became permanently unanswerable: still queued, grant chain still live, readable in full, and
// impossible to reply to. Three replies died that way in one evening.
//
// Authorisation never came from that deadline. It comes from the present-tense policy re-check
// further down, which re-derives the chain from live relays and requires every receipt field to
// match it. So the deadline stopped being a gate.
//
// That change is observable WITHOUT a signer or a relay: an expired receipt used to be refused
// at the receipt check, and must now travel past it and fail later, at the credential step. The
// mirror matters just as much — a receipt that is genuinely not bound to this broker/envelope
// must STILL be refused at the receipt check, or this would have removed the binding rather than
// the deadline.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'

let passed = 0, failed = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passed++ : failed++ }

const root = mkdtempSync(join(tmpdir(), 'nvoy-receipt-window-'))
const manifests = join(root, 'instances'), runtime = join(root, 'runtime'), state = join(root, 'state')
mkdirSync(manifests); mkdirSync(runtime); mkdirSync(state); mkdirSync(join(state, 'receipts'))
const uid = process.getuid(), gid = process.getgid()
const BROKER = '1'.repeat(64), SENDER = '4'.repeat(64), CARRIER = '8'.repeat(64)
const CHANNEL = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const envelope = '3'.repeat(64)
const manifest = {
  version: 1, id: 'receipt-window', pubkey: BROKER, broker_mode: 'local',
  state_dir: state, runtime_dir: runtime, spool_dir: join(root, 'spool'),
  bunker_uri_ref: '/etc/nvoy/test.bunker', bunker_client_ref: '/etc/nvoy/test.client',
  worker_enabled: false, delivery_mode: 'notify_only',
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1,
  watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid,
  grantors: ['2'.repeat(64)], relays: ['wss://nos.lol'],
  task_carriers: [{ pubkey: CARRIER, channels: [CHANNEL] }],
}
writeFileSync(join(manifests, `${manifest.id}.json`), JSON.stringify(manifest))

const LONG_EXPIRED = Date.now() - 60 * 60 * 1000   // an hour past the old five-minute window
const receipt = (over = {}) => ({
  version: 2, instance: manifest.id, broker: BROKER, envelope, sender: SENDER,
  grant_id: '5'.repeat(64), mode: 'channel-carry', carrier: CARRIER,
  carrier_grant_id: '6'.repeat(64), reply_channel: CHANNEL, source_event: '7'.repeat(64),
  admitted_at: LONG_EXPIRED - 300000, expires_at: LONG_EXPIRED, ...over,
})

const REQUEST_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
const run = (rec, requestId = REQUEST_ID) => {
  writeFileSync(join(state, 'receipts', `${envelope}.json`), JSON.stringify(rec), { mode: 0o600 })
  writeFileSync(join(runtime, 'reply-requests.jsonl'), JSON.stringify({
    version: 1, type: 'reply-request', id: requestId, instance: manifest.id,
    receipt: envelope, content: 'a bounded reply',
  }) + '\n', { mode: 0o640 })
  const r = spawnSync(process.execPath, [resolve('mcp/tools/instance-broker-reply.mjs'),
    '--instance', manifest.id, '--request', requestId, '--source', 'worker', '--prepare'],
    { encoding: 'utf8', timeout: 60000, env: { ...process.env,
      NVOY_INSTANCE_ROOT: manifests,
      // Deliberately absent, so the run stops at the credential step. Everything this suite
      // asserts happens before any key is needed — which is the point: no signer, no relay.
      NVOY_BROKER_CREDENTIAL: join(root, 'no-such-credential') } })
  return String(r.stderr || '') + String(r.stdout || '')
}

const RECEIPT_REFUSAL = 'admission receipt is not a live broker-bound sender capability'
const PAST_THE_GATE = 'broker credential file is unavailable'

// --- the fix ---------------------------------------------------------------------------------
const expired = run(receipt())
ok('an expired receipt is no longer refused as a dead capability', !expired.includes(RECEIPT_REFUSAL))
ok('it travels past the receipt gate and stops where a key is genuinely needed',
  expired.includes(PAST_THE_GATE))

// --- the mirror: binding must survive intact --------------------------------------------------
// If the change had removed the receipt check rather than the deadline, every one of these would
// sail past too. A guard that refuses nothing and one that refuses everything fail identically.
for (const [name, over] of [
  ['bound to a different broker', { broker: '9'.repeat(64) }],
  ['bound to a different envelope', { envelope: 'b'.repeat(64) }],
  ['bound to a different instance', { instance: 'someone-else' }],
  ['carrying no valid sender', { sender: 'not-a-key' }],
  ['carrying an unusable expiry field', { expires_at: 'whenever' }],
]) {
  ok(`a receipt ${name} is still refused`, run(receipt(over)).includes(RECEIPT_REFUSAL))
}

// The carrier binding is a separate refusal and must also survive. Use a LIVE expiry here on
// purpose: with an expired one these would be refused at the earlier gate on the old code, and
// the assertion would be passing for the wrong reason instead of testing carrier binding at all.
const live = { expires_at: Date.now() + 5 * 60 * 1000 }
ok('a channel-carry receipt naming an unlisted carrier is still refused',
  run(receipt({ ...live, carrier: 'c'.repeat(64) })).includes('not bound to an allowed carrier and channel'))
ok('a channel-carry receipt naming an unlisted channel is still refused',
  run(receipt({ ...live, reply_channel: '00000000-0000-0000-0000-000000000000' }))
    .includes('not bound to an allowed carrier and channel'))

// --- replay protection is independent of the deadline -----------------------------------------
// It is enforced by the one-use rename, not by expiry, so removing the deadline must not touch
// it. A consumed receipt stays consumed however old it is.
const replayId = 'f0e1d2c3b4a5968778695a4b3c2d1e0f'
writeFileSync(join(state, 'receipts', `${envelope}.${replayId}.used`), '{}', { mode: 0o600 })
const replayed = run(receipt(), replayId)
ok('a receipt already consumed is reported as a replay rather than re-enacted',
  /"replay":\s*true/.test(replayed) && !replayed.includes(PAST_THE_GATE))

console.log(failed ? `\n${failed} FAILED` : `\nall ${passed} passed`)
process.exit(failed ? 1 : 0)
