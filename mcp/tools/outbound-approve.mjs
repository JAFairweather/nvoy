#!/usr/bin/env node
// outbound-approve.mjs — the approver's side of the AD-12 outbound hold.
//
// The broker freezes a proposal and waits for a discrete, signed approval binding one exact
// fingerprint. `outbound_approval.mjs` could already BUILD that event and `instance-broker-reply.mjs`
// could already CONSUME it, but nothing sat between them, so a frozen proposal had no way to be
// approved and simply expired with its receipt. This is that missing step.
//
//   node tools/outbound-approve.mjs --instance <id> --list
//   node tools/outbound-approve.mjs --instance <id> --request <32-hex> --show
//   node tools/outbound-approve.mjs --instance <id> --request <32-hex> --template <out.json> \
//     --approver <64-hex>
//   node tools/outbound-approve.mjs --instance <id> --request <32-hex> --approval-out <out.json> \
//     --bunker-uri-file <path> --nip46-client-file <path>
//
// What the approver can and cannot see, stated exactly, because overstating it would make this
// tool worse than useless:
//
// The frozen bytes are a kind:13 seal whose content is NIP-44 ciphertext addressed to the
// recipient. The approver CANNOT decrypt it — only the participant key can, through its Bunker.
// So "what you sign" is not read directly off the frozen event. Instead this tool shows the
// plaintext from the reply-request queue and PROVES it is the text that was frozen, by recomputing
// `replyRequestDigest` and requiring it to equal the `request_digest` recorded alongside the
// fingerprint. A queue edited after the freeze fails that check and is refused.
//
// That is a binding between shown text and frozen record, not a decryption of the frozen record.
// It rests on the broker having sealed the request it recorded. It detects tampering with the
// queue after the fact; it does not by itself prove the ciphertext encrypts that plaintext.
//
// Signing is external by default: this prints an unsigned template for the approver's own signer.
// The optional Bunker path takes credential FILES and never accepts a key as an argument.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { approvalTemplate, approvalUrl } from './outbound_approval.mjs'
import { replyRequestDigest } from './outbound_record.mjs'
import { makeBunkerSigner } from './nip46-signer.mjs'
import { getEventHash } from 'nostr-tools/pure'

const die = m => { console.error(`outbound-approve: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const has = n => process.argv.includes(n)
const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/

const id = flag('--instance')
if (!id) die('usage: --instance <id> (--list | --request <32-hex> [--show|--template <path>|--approval-out <path>])')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }

const outboundDir = resolve(manifest.stateDir, 'outbound')

// A proposal is pending when it is frozen, unapproved and unpublished. Anything else is history.
function pending() {
  let names = []
  try { names = readdirSync(outboundDir) } catch (e) { if (e.code === 'ENOENT') return []; die(`cannot read outbound dir: ${e.message}`) }
  const out = []
  for (const name of names) {
    if (!name.endsWith('.json')) continue
    let record
    try { record = JSON.parse(readFileSync(resolve(outboundDir, name), 'utf8')) } catch { continue }
    if (record?.published || record?.approval_id || !HEX32.test(String(record?.request_id || ''))) continue
    out.push(record)
  }
  return out
}

// The plaintext, and the proof it is the text that was frozen.
function boundRequest(record) {
  for (const filename of ['reply-requests.jsonl', 'desktop-reply-requests.jsonl']) {
    let text
    try { text = readFileSync(resolve(manifest.runtimeDir, filename), 'utf8') } catch { continue }
    for (const line of text.split('\n')) {
      let request
      try { request = JSON.parse(line) } catch { continue }
      if (request?.id !== record.request_id) continue
      if (replyRequestDigest(request) !== record.request_digest) {
        die(`request ${record.request_id.slice(0, 12)}… no longer matches the digest frozen with its fingerprint — the queue changed after the proposal was frozen; refusing to render it as approvable`)
      }
      return request
    }
  }
  return null
}

// The receipt bounds the whole exchange: approval is verified against a live receipt, so an
// approval signed after it lapses is refused downstream. Surface that before the approver signs.
function receiptWindow(record) {
  let names = []
  try { names = readdirSync(resolve(manifest.stateDir, 'receipts')) } catch { return null }
  for (const name of names) {
    if (!name.includes(record.request_id)) continue
    try {
      const receipt = JSON.parse(readFileSync(resolve(manifest.stateDir, 'receipts', name), 'utf8'))
      if (Number.isFinite(receipt?.expires_at)) return receipt.expires_at
    } catch { /* a malformed receipt is not a window */ }
  }
  return null
}

const left = expiresAt => expiresAt === null ? 'unknown'
  : expiresAt > Date.now() ? `${((expiresAt - Date.now()) / 60000).toFixed(1)} min left` : 'EXPIRED'

if (has('--list')) {
  const rows = pending()
  if (!rows.length) { console.log('no pending proposals'); process.exit(0) }
  for (const record of rows) {
    console.log(`${record.request_id}  fingerprint ${record.fingerprint.slice(0, 16)}…  receipt ${left(receiptWindow(record))}`)
  }
  process.exit(0)
}

const requestId = flag('--request')
if (!HEX32.test(requestId)) die('--request must be a 32-hex proposal id')
const record = pending().find(r => r.request_id === requestId)
if (!record) die(`no pending proposal ${requestId.slice(0, 12)}… (already approved, published, or absent)`)
const request = boundRequest(record)
if (!request) die('the frozen proposal has no matching reply request in this instance queue')
const expiresAt = receiptWindow(record)

function render() {
  console.log(`instance    : ${manifest.id}`)
  console.log(`proposal    : ${record.request_id}`)
  console.log(`fingerprint : ${record.fingerprint}`)
  console.log(`receipt     : ${left(expiresAt)}`)
  console.log(`approval url: ${approvalUrl(manifest.id, record.request_id)}`)
  console.log('digest      : MATCHES the frozen record (text below is the text that was frozen)')
  console.log('\n--- exact reply text ---')
  console.log(request.content)
  console.log('--- end ---')
  if (expiresAt !== null && expiresAt <= Date.now()) {
    console.log('\nThis receipt has already lapsed. An approval signed now will be refused downstream.')
  }
}

if (has('--show')) { render(); process.exit(0) }

const templateOut = flag('--template')
const approvalOut = flag('--approval-out')
if (!templateOut && !approvalOut) { render(); process.exit(0) }

if (templateOut) {
  const approver = flag('--approver')
  if (!HEX64.test(approver)) die('--approver must be the 64-hex pubkey that will sign')
  if (!manifest.grantors.includes(approver)) die('--approver is not an authorized approver for this instance')
  render()
  const unsigned = approvalTemplate({ approver, instance: manifest.id, proposalId: record.request_id, fingerprint: record.fingerprint })
  writeFileSync(templateOut, JSON.stringify(unsigned, null, 2), { mode: 0o600 })
  console.log(`\nunsigned approval written to ${templateOut}`)
  console.log('Sign it with the approver key, then release the reply with:')
  console.log(`  node tools/instance-broker-reply.mjs --instance ${manifest.id} --request ${record.request_id} --approval <signed.json>`)
  process.exit(0)
}

// Optional one-step path: sign through the approver's OWN Bunker. Credential files only — a key
// never appears in argv. This signs as the approver, never as the participant.
const uriFile = flag('--bunker-uri-file')
const clientFile = flag('--nip46-client-file')
if (!uriFile || !clientFile) die('--approval-out requires --bunker-uri-file and --nip46-client-file (paths, never key values)')
const credential = (path, label) => {
  let value
  try { value = readFileSync(path, 'utf8').trim() } catch { die(`cannot read ${label} at ${path}`) }
  if (!value) die(`${label} at ${path} is empty`)
  return value
}
const signer = makeBunkerSigner(credential(uriFile, 'approver Bunker URI'), credential(clientFile, 'approver Bunker client credential'))
const approver = await signer.getPublicKey()
if (!manifest.grantors.includes(approver)) die('the Bunker identity is not an authorized approver for this instance')
if (approver === manifest.pubkey) die('the participant identity cannot approve its own outbound action')
render()
const signed = await signer.signEvent(approvalTemplate({ approver, instance: manifest.id, proposalId: record.request_id, fingerprint: record.fingerprint }))
if (signed.id !== getEventHash(signed)) die('signer returned an event whose id does not match its content')
writeFileSync(approvalOut, JSON.stringify(signed), { mode: 0o600 })
console.log(`\nsigned approval written to ${approvalOut}`)
console.log('Release the reply with:')
console.log(`  node tools/instance-broker-reply.mjs --instance ${manifest.id} --request ${record.request_id} --approval ${approvalOut}`)
process.exit(0)
