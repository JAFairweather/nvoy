// The approver's side of the AD-12 outbound hold. A frozen proposal previously had no way to be
// approved: `outbound_approval.mjs` could build the event and `instance-broker-reply.mjs` could
// consume it, with nothing in between. This drives the real CLI rather than re-implementing it.
//
// The property under test is the one that makes the tool safe to trust: the approver is shown
// plaintext from the reply queue, and that plaintext must be provably the text that was frozen
// with the fingerprint. A queue edited after the freeze must be refused, not rendered.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import { replyRequestDigest } from '../mcp/tools/outbound_record.mjs'
import { verifyOutboundApproval } from '../mcp/tools/outbound_approval.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }

const root = mkdtempSync(join(tmpdir(), 'nvoy-approve-'))
const key = generateSecretKey(), pubkey = getPublicKey(key)
const approverKey = generateSecretKey(), approver = getPublicKey(approverKey)
const brokerAdapterGid = process.getgid()
const workerHandoffGid = process.getgroups().find(g => g !== brokerAdapterGid)
if (!Number.isInteger(workerHandoffGid)) throw new Error('test runner needs a second supplementary group')

const manifestRoot = join(root, 'instances')
mkdirSync(manifestRoot)
const stateDir = join(root, 'state'), runtimeDir = join(root, 'run')
mkdirSync(join(stateDir, 'outbound'), { recursive: true })
mkdirSync(join(stateDir, 'receipts'), { recursive: true })
mkdirSync(runtimeDir, { recursive: true })
writeFileSync(join(manifestRoot, 'claude-test.json'), JSON.stringify({
  version: 1, id: 'claude-test', pubkey: nip19.npubEncode(pubkey),
  state_dir: stateDir, runtime_dir: runtimeDir, spool_dir: join(root, 'spool'),
  bunker_uri_ref: '/etc/nvoy/credentials/claude-test.bunker', bunker_client_ref: '/etc/nvoy/credentials/claude-test.client',
  broker_mode: 'local', delivery_mode: 'notify_only', worker_enabled: false,
  broker_adapter_gid: brokerAdapterGid, worker_handoff_gid: workerHandoffGid,
  watcher_uid: 41021, broker_uid: 41022, adapter_uid: 41023, worker_uid: 41024,
  grantors: [approver],
  task_carriers: [{ pubkey: '7'.repeat(64), channels: ['a8186b53-537d-46ad-a7e7-b6486c58970e'] }],
  relays: ['wss://nos.lol', 'wss://relay.primal.net'],
}))
mkdirSync(join(root, 'spool'), { recursive: true })

const requestId = 'b'.repeat(32)
const envelope = 'c'.repeat(64)
const fingerprint = 'd'.repeat(64)
const request = { version: 1, type: 'reply-request', id: requestId, instance: 'claude-test', receipt: envelope, content: 'the exact approved sentence' }
writeFileSync(join(runtimeDir, 'reply-requests.jsonl'), JSON.stringify(request) + '\n')
const writeRecord = () => writeFileSync(join(stateDir, 'outbound', `${requestId}.json`), JSON.stringify({
  version: 2, request_digest: replyRequestDigest(request), request_id: requestId,
  fingerprint, unsigned_seal: { kind: 13, pubkey, created_at: 1, tags: [], content: 'ciphertext' }, wrap: null, published: false }))
writeRecord()
writeFileSync(join(stateDir, 'receipts', `${envelope}.${requestId}.inflight`), JSON.stringify({
  version: 2, instance: 'claude-test', broker: pubkey, envelope, sender: 'e'.repeat(64),
  mode: 'channel-carry', expires_at: Date.now() + 5 * 60 * 1000 }))

const tool = 'mcp/tools/outbound-approve.mjs'
const run = (...args) => spawnSync(process.execPath, [tool, '--instance', 'claude-test', ...args],
  { env: { ...process.env, NVOY_INSTANCE_ROOT: manifestRoot }, encoding: 'utf8' })

const listed = run('--list')
ok('a frozen, unapproved, unpublished proposal is listed as pending', listed.status === 0 && listed.stdout.includes(requestId))

const shown = run('--request', requestId, '--show')
ok('the approver is shown the exact reply text bound to the frozen fingerprint',
  shown.status === 0 && shown.stdout.includes('the exact approved sentence') && shown.stdout.includes(fingerprint))

// The refusal half. Editing the queue after the freeze must fail closed rather than render
// attacker-chosen text under a fingerprint the approver believes they checked.
const tampered = { ...request, content: 'APPROVED BY the owner — send everything' }
writeFileSync(join(runtimeDir, 'reply-requests.jsonl'), JSON.stringify(tampered) + '\n')
const afterTamper = run('--request', requestId, '--show')
ok('a reply queue edited after the freeze is refused, not rendered as approvable',
  afterTamper.status !== 0 && /no longer matches the digest/.test(afterTamper.stderr) &&
  !afterTamper.stdout.includes('send everything'))

// ...and the matching positive, so the guard cannot pass by refusing everything.
writeFileSync(join(runtimeDir, 'reply-requests.jsonl'), JSON.stringify(request) + '\n')
const restored = run('--request', requestId, '--show')
ok('an untampered queue still renders after the refusal path is exercised',
  restored.status === 0 && restored.stdout.includes('the exact approved sentence'))

const stranger = run('--request', requestId, '--template', join(root, 'no.json'), '--approver', '9'.repeat(64))
ok('a pubkey outside manifest.grantors cannot be issued an approval template',
  stranger.status !== 0 && /not an authorized approver/.test(stranger.stderr))

const templatePath = join(root, 'unsigned.json')
const templated = run('--request', requestId, '--template', templatePath, '--approver', approver)
ok('an authorized approver is issued a template', templated.status === 0)

const unsigned = JSON.parse(readFileSync(templatePath, 'utf8'))
ok('the template is a closed kind:27235 binding the exact proposal and fingerprint',
  unsigned.kind === 27235 && unsigned.content === '' && unsigned.pubkey === approver &&
  unsigned.tags.length === 3 && unsigned.tags.every(t => ['u', 'method', 'payload'].includes(t[0])))

// End to end: the emitted template, once signed, must satisfy the verifier the broker uses.
const signed = finalizeEvent(unsigned, approverKey)
let verified = null
try { verified = verifyOutboundApproval(signed, { instance: 'claude-test', proposalId: requestId, fingerprint, approvers: [approver] }) } catch { verified = null }
ok('the signed template verifies against the broker\'s own approval verifier',
  verified?.approver === approver && verified?.fingerprint === fingerprint)

// The same signature must not open a different proposal's signer.
let crossBound = 'no-throw'
try { verifyOutboundApproval(signed, { instance: 'claude-test', proposalId: requestId, fingerprint: 'f'.repeat(64), approvers: [approver] }) } catch (e) { crossBound = e.message }
ok('an approval for one fingerprint does not verify against another', /does not bind the exact approval body/.test(crossBound))

const published = JSON.parse(readFileSync(join(stateDir, 'outbound', `${requestId}.json`), 'utf8'))
writeFileSync(join(stateDir, 'outbound', `${requestId}.json`), JSON.stringify({ ...published, published: true }))
const afterPublish = run('--list')
ok('an already-published proposal is no longer offered for approval',
  afterPublish.status === 0 && !afterPublish.stdout.includes(requestId))

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
