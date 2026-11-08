// onboard_receipt.mjs — phase B: what the fleet tells the owner about one setup request, sealed to
// them and signed by the runner key (docs/ONBOARD_PHASE_B.md).
//
// One addressable kind 30078 per request, d = nvoy-onboard:<request id>, replaced on each change. Its
// NIP-44 content holds the newest state of every step, the pairing link while pairing waits, and the
// four install details waggle's step 4 builds the box's install line from. Nothing in it is ever in
// the clear: an event this module makes has only the d, p, e and expiration tags outside the seal.

import { readFileSync } from 'node:fs'
import { isAbsolute } from 'node:path'
import { nip19 } from 'nostr-tools'
import { parseHostKey } from './box-install.mjs'
import { SSH_TARGET } from './channel_client.mjs'

export const RECEIPT_KIND = 30078
export const RECEIPT_VERSION = 1
export const RECEIPT_TTL_S = 30 * 24 * 60 * 60
export const receiptD = request => `nvoy-onboard:${request}`
const HEX64 = /^[0-9a-f]{64}$/, HEX40 = /^[0-9a-f]{40}$/

// What the runner's connection may do, and nothing more: no decrypt, no post, no reaction, no join.
// 27235 is the pairing probe, never published; 30078 is the receipt.
export const RUNNER_PERMS = Object.freeze(['get_public_key', 'nip44_encrypt', 'sign_event:27235', 'sign_event:30078'])
export const RUNNER_CONFIG = '/etc/nvoy/onboard/runner.json'
export const WRITER_RELAY = 'wss://relay.nave.pub'

// /etc/nvoy/onboard/runner.json. Every field is checked here, so a bad config stops the tick before
// anything is staged, paired or published.
export function runnerConfig(raw) {
  const fail = message => { throw new Error(`runner config: ${message}`) }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('not a JSON object')
  let pubkey = String(raw.pubkey || '').trim().toLowerCase()
  if (pubkey.startsWith('npub1')) { try { pubkey = nip19.decode(pubkey).data } catch { fail('pubkey is not a valid npub') } }
  if (!HEX64.test(pubkey)) fail('pubkey must be 64 hex or an npub')
  const wss = url => typeof url === 'string' && /^wss:\/\/[a-z0-9.-]+(:\d+)?(\/[^\s]*)?$/i.test(url)
  if (!Array.isArray(raw.relays) || !raw.relays.length || !raw.relays.every(wss)) fail('relays must be a non-empty list of wss:// URLs')
  for (const field of ['bunker_client_ref', 'bunker_uri_ref', 'authorized_keys'])
    if (typeof raw[field] !== 'string' || !isAbsolute(raw[field])) fail(`${field} must be an absolute path`)
  if (!SSH_TARGET.test(raw.ssh_target || '')) fail('ssh_target must be user@host')
  const writerRelay = raw.writer_relay ?? WRITER_RELAY
  if (!wss(writerRelay)) fail('writer_relay must be a wss:// URL')
  return Object.freeze({ id: 'nvoy-onboard', pubkey, relays: [...new Set(raw.relays)], bunkerClientRef: raw.bunker_client_ref,
    bunkerUriRef: raw.bunker_uri_ref, authorizedKeys: raw.authorized_keys, sshTarget: raw.ssh_target, writerRelay, perms: RUNNER_PERMS })
}
export const readRunnerConfig = (path = RUNNER_CONFIG) => runnerConfig(JSON.parse(readFileSync(path, 'utf8')))

// The newest row for each step, in the order the steps first ran.
export function latestSteps(rows) {
  const steps = new Map()
  for (const { step, state, at, detail } of rows) steps.set(step, { step, state, at, detail })
  return [...steps.values()]
}

// The four fields of the install line, each checked by the rule the box's installer applies, so a
// bad config is refused here and never reaches the owner's page.
export function installDetails({ instance, sshTarget, hostKeyText, commit }) {
  if (!SSH_TARGET.test(sshTarget || '')) throw new Error('the runner config ssh_target must be user@host')
  const fields = String(hostKeyText || '').trim().split(/\s+/)
  const hostKey = parseHostKey(fields.slice(0, 2).join(' '))
  const sha = String(commit || '').trim()
  if (!HEX40.test(sha)) throw new Error('the deployed commit is not 40 lowercase hex')
  return { instance, ssh_target: sshTarget, host_key: hostKey, commit: sha }
}

export function readInstallDetails({ instance, sshTarget, hostKeyPath = '/etc/ssh/ssh_host_ed25519_key.pub',
  commitPath = '/var/lib/nvoy-deploy/DEPLOYED_SHA' }) {
  return installDetails({ instance, sshTarget, hostKeyText: readFileSync(hostKeyPath, 'utf8'), commit: readFileSync(commitPath, 'utf8') })
}

export function receiptBody({ name, request, instance, rows, pairing = null, install = null }) {
  const steps = latestSteps(rows)
  const body = { v: RECEIPT_VERSION, name, request, instance, steps }
  // The link is useful only while pairing waits; its one-time secret is spent by the handshake.
  if (pairing && steps.find(row => row.step === 'paired')?.state !== 'done') body.pairing = pairing
  if (install) body.install = install
  return body
}

// Seals the body to the owner and signs it as the runner. created_at only ever moves forward, so a
// relay never keeps an older receipt over a newer one made in the same second.
export function makeSealer(signer, { now = () => Math.floor(Date.now() / 1000) } = {}) {
  let last = 0
  return async ({ owner, request, body }) => {
    if (!HEX64.test(owner || '') || !HEX64.test(request || '')) throw new Error('a receipt needs the owner and request ids')
    const content = await signer.nip44Encrypt(owner, JSON.stringify(body))
    const created_at = last = Math.max(now(), last + 1)
    return signer.signEvent({ kind: RECEIPT_KIND, created_at, content,
      tags: [['d', receiptD(request)], ['p', owner], ['e', request], ['expiration', String(created_at + RECEIPT_TTL_S)]] })
  }
}
