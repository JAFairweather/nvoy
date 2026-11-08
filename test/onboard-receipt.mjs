import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { nip19 } from 'nostr-tools'
import { installDetails, latestSteps, makeSealer, readInstallDetails, receiptBody, receiptD, RECEIPT_KIND, RECEIPT_TTL_S, RUNNER_PERMS, runnerConfig, WRITER_RELAY } from '../mcp/tools/onboard_receipt.mjs'
import { brokerPerms } from '../mcp/tools/instance-pair.mjs'

const runner = generateSecretKey(), owner = generateSecretKey(), ownerHex = getPublicKey(owner), runnerHex = getPublicKey(runner)
const signer = {
  nip44Encrypt: async (peer, text) => nip44.encrypt(text, nip44.utils.getConversationKey(runner, peer)),
  signEvent: async template => finalizeEvent(template, runner),
}
const open = event => JSON.parse(nip44.decrypt(event.content, nip44.utils.getConversationKey(owner, runnerHex)))
const request = 'ab'.repeat(32), sha = 'c0ffee'.repeat(6) + 'c0ff'
const hostKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIYeHBpTKcWZcMIRUe6qSiCIGJ4pIrXrSdB1zg9hqTd'
const link = 'nostrconnect://' + 'ef'.repeat(32) + '?relay=wss%3A%2F%2Frelay.example&secret=one-time'

// Newest row per step, in first-seen order.
const rows = [
  { step: 'staged', state: 'done', at: 1, detail: 'staged' },
  { step: 'paired', state: 'pending', at: 2, detail: 'waiting for the owner' },
  { step: 'staged', state: 'done', at: 3, detail: 'staged again' },
]
assert.deepEqual(latestSteps(rows).map(row => [row.step, row.detail]), [['staged', 'staged again'], ['paired', 'waiting for the owner']])

// Install details: each field by the installer's own rule; a bad value is refused, never repaired.
const install = installDetails({ instance: 'curator', sshTarget: 'root@fleet.example', hostKeyText: `${hostKey} root@fleet\n`, commit: `${sha}\n` })
assert.deepEqual(Object.keys(install), ['instance', 'ssh_target', 'host_key', 'commit'])
assert.equal(install.host_key, hostKey)
assert.equal(install.commit, sha)
for (const bad of [{ sshTarget: 'root@fleet example' }, { sshTarget: "root@x';rm" }, { commit: 'C0FFEE'.repeat(6) + 'c0ff' },
  { commit: sha.slice(1) }, { hostKeyText: 'ssh-rsa AAAAB3NzaC1yc2E' }, { hostKeyText: '' }])
  assert.throws(() => installDetails({ instance: 'curator', sshTarget: 'root@fleet.example', hostKeyText: hostKey, commit: sha, ...bad }))
const dir = mkdtempSync(join(tmpdir(), 'nvoy-receipt-'))
writeFileSync(join(dir, 'key.pub'), `${hostKey} root@fleet\n`); writeFileSync(join(dir, 'sha'), sha + '\n')
assert.deepEqual(readInstallDetails({ instance: 'curator', sshTarget: 'root@fleet.example', hostKeyPath: join(dir, 'key.pub'), commitPath: join(dir, 'sha') }), install)

// The link rides only while pairing waits.
const pairing = { uri: link, made_at: 100, expires_at: 400 }
const waiting = receiptBody({ name: 'curator', request, instance: 'curator', rows, pairing, install })
assert.equal(waiting.pairing.uri, link)
const paired = receiptBody({ name: 'curator', request, instance: 'curator', rows: [...rows, { step: 'paired', state: 'done', at: 4, detail: 'paired' }], pairing, install })
assert.equal(paired.pairing, undefined)
assert.deepEqual(paired.install, install)

// Sealed to the owner, signed by the runner, only d/p/e/expiration in the clear.
let clock = 1000
const seal = makeSealer(signer, { now: () => clock })
const first = await seal({ owner: ownerHex, request, body: waiting })
assert.ok(verifyEvent(first))
assert.equal(first.kind, RECEIPT_KIND)
assert.equal(first.pubkey, runnerHex)
assert.deepEqual(first.tags, [['d', receiptD(request)], ['p', ownerHex], ['e', request], ['expiration', String(1000 + RECEIPT_TTL_S)]])
assert.deepEqual(open(first), waiting)
const clear = JSON.stringify({ ...first, content: '' })
for (const secret of ['nostrconnect', 'one-time', 'fleet.example', hostKey.split(' ')[1], sha, 'curator']) {
  assert.ok(!clear.includes(secret), `${secret} is outside the seal`)
  assert.ok(!first.content.includes(secret), `${secret} is in the ciphertext as text`)
}
const stranger = generateSecretKey()
assert.throws(() => nip44.decrypt(first.content, nip44.utils.getConversationKey(stranger, runnerHex)))

// created_at never goes back, so a relay keeps the newest of two receipts made in one second.
const second = await seal({ owner: ownerHex, request, body: paired })
assert.ok(second.created_at > first.created_at)
clock = 900
assert.ok((await seal({ owner: ownerHex, request, body: paired })).created_at > second.created_at)

await assert.rejects(seal({ owner: 'npub1nope', request, body: paired }))
await assert.rejects(seal({ owner: ownerHex, request: 'x', body: paired }))

// The runner config: every field checked, and the connection asks for less than any agent's.
const good = { pubkey: nip19.npubEncode(runnerHex), relays: ['wss://relay.nave.pub', 'wss://relay.nave.pub'], bunker_client_ref: '/etc/nvoy/onboard/nvoy-onboard.nip46-client',
  bunker_uri_ref: '/etc/nvoy/onboard/nvoy-onboard.bunker-uri', authorized_keys: '/root/.ssh/authorized_keys', ssh_target: 'root@fleet.example' }
const config = runnerConfig(good)
assert.equal(config.pubkey, runnerHex, 'an npub is read as its hex key')
assert.deepEqual(config.relays, ['wss://relay.nave.pub'])
assert.equal(config.writerRelay, WRITER_RELAY)
assert.deepEqual(config.perms, ['get_public_key', 'nip44_encrypt', 'sign_event:27235', 'sign_event:30078'])
assert.ok(!RUNNER_PERMS.includes('nip44_decrypt') && RUNNER_PERMS.every(perm => brokerPerms().includes(perm)), 'no decrypt, and nothing an agent lacks')
for (const bad of [{ pubkey: 'nsec1nope' }, { pubkey: 'ab' }, { relays: [] }, { relays: ['ws://plain.example'] }, { relays: 'wss://x.example' },
  { bunker_client_ref: 'relative/path' }, { bunker_uri_ref: undefined }, { authorized_keys: '' }, { ssh_target: 'fleet.example' }, { writer_relay: 'https://x.example' }])
  assert.throws(() => runnerConfig({ ...good, ...bad }), /runner config/)
assert.throws(() => runnerConfig([]), /runner config/)

console.log('onboard-receipt: runner config checked field by field with no decrypt, newest step rows, install details by the installer rules, link only while pairing waits, sealed to the owner with only d/p/e/expiration clear, monotonic created_at pass')
