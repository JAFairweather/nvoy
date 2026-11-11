#!/usr/bin/env node
// instance-pair.mjs — pair a staged identity with the owner's Bunker, and seat its two credential
// files, without a bunker:// secret ever being copied (#166).
//
//   instance-pair.mjs --id <name> [--out <staging dir>] [--relay wss://…]… [--timeout-s <n>]
//
// The pairing is client-initiated (NIP-46 `nostrconnect://`). This tool makes the instance's NIP-46
// client key on the box it will live on, prints a one-time link, and waits. The owner opens the link
// in their Bunker and approves it with the key the manifest names. Then this tool:
//
//   1. refuses unless the Bunker answers as the manifest's pubkey — a pairing to any other key seats
//      nothing;
//   2. asks the Bunker to sign a probe event (kind 27235, never published) and verifies it, so
//      "paired" means "signs as this agent", not "a connect ack arrived" (#171);
//   3. writes `<id>.nip46-client` and `<id>.bunker-uri` where the manifest's refs point, root 0600,
//      each created exclusively and renamed into place, so `instance-identity.mjs check` passes.
//
// The bunker:// pointer it writes carries NO `secret=`. The nostrconnect secret is spent by the
// handshake; a stored copy is the "Unknown client" trap of #171. The broker's connect sends an empty
// secret, which a Bunker that already knows the client accepts.
//
// It prints the link (a client PUBLIC key, relays, requested permissions and a one-time nonce that
// is useless once the handshake completes) and the resulting npub. It never prints the client key or
// the pointer it writes. It refuses to overwrite either file: re-pairing is the operator removing
// both first, on purpose.
//
// Exit: 0 paired and seated · 1 refused, nothing written · 2 usage.

import { lstatSync, openSync, writeSync, fsyncSync, closeSync, renameSync, unlinkSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { verifyEvent, nip19 } from 'nostr-tools'
import { readManifest } from './runtime_manifest.mjs'

// What the runtime signs as the agent: its profile (0, still gated by may_set_profile), notes and
// replies (1), deletions (5), reactions (7), channel posts (9), sealed DMs (13), relay AUTH (22242),
// HTTP auth to Buzz (27235, also the probe) and its card and state (30078); plus the NIP-44 it uses to
// open and seal DMs. And joining a room (9021), so onboarding can put a new agent in the rooms its
// owner picked: the relay accepts a self-join only for an open room. Adding or removing someone else
// (9000/9001) stays the owner's.
export const BROKER_SIGN_KINDS = Object.freeze([0, 1, 5, 7, 9, 13, 9021, 22242, 27235, 30078])
export const brokerPerms = () => ['get_public_key', 'nip44_encrypt', 'nip44_decrypt', ...BROKER_SIGN_KINDS.map(k => `sign_event:${k}`)]

const HEX64 = /^[0-9a-f]{64}$/

// The pointer the broker reads: the signer and its relays, and no spent secret.
export function bunkerPointer(signerPubkey, relays) {
  if (!HEX64.test(signerPubkey || '')) throw new Error('the signer pubkey is not 64 hex')
  if (!relays.length || !relays.every(r => /^wss:\/\//.test(r))) throw new Error('the pointer needs wss relays')
  return `bunker://${signerPubkey}?${relays.map(r => `relay=${encodeURIComponent(r)}`).join('&')}`
}

// Write one credential file: never over an existing one, never through a symlink, 0600 from the
// first byte, durable before it takes its name.
function seat(path, value) {
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.tmp`)
  const fd = openSync(tmp, 'wx', 0o600)
  try { writeSync(fd, `${value}\n`); fsyncSync(fd) } finally { closeSync(fd) }
  try { lstatSync(path); unlinkSync(tmp); throw new Error(`${path} appeared while pairing; nothing replaced`) } catch (e) { if (e.code !== 'ENOENT') throw e }
  renameSync(tmp, path)
}
const exists = path => { try { lstatSync(path); return true } catch (e) { if (e.code === 'ENOENT') return false; throw e } }

/**
 * Pair and seat. `pair` is nave-connect's nostrConnectSigner (injected for tests). Resolves to
 * { npub, written: [paths] }; throws with nothing written on any refusal.
 */
export async function pairInstance(manifest, { pair, relays = manifest.relays, perms = manifest.perms || brokerPerms(), timeoutMs = 300000, onUri = () => {}, onLog = () => {}, now = () => Math.floor(Date.now() / 1000) }) {
  const refs = [manifest.bunkerClientRef, manifest.bunkerUriRef]
  if (!refs.every(r => typeof r === 'string' && r.startsWith('/'))) throw new Error('the manifest names no Bunker credential files; this identity does not pair through a Bunker')
  for (const r of refs) if (exists(r)) throw new Error(`${r} already exists; nothing was paired. To re-pair, remove both credential files first`)
  for (const d of new Set(refs.map(r => dirname(r)))) if (!exists(d)) throw new Error(`${d} does not exist`)

  const signer = await pair({ relays, perms, appName: `nvoy ${manifest.id}`, onUri, onLog, timeoutMs })
  try {
    const pk = String(await signer.getPublicKey()).toLowerCase()
    if (pk !== manifest.pubkey) {
      throw new Error(`the Bunker approved with ${nip19.npubEncode(pk)}, but ${manifest.id} is ${nip19.npubEncode(manifest.pubkey)}. Nothing was seated; approve the link with the agent's key`)
    }
    const probe = { kind: 27235, created_at: now(), tags: [['u', `nvoy:pair-probe:${manifest.id}`], ['method', 'GET']], content: '' }
    let signed = null
    try { signed = await signer.signEvent(probe) } catch (e) { throw new Error(`the Bunker paired but would not sign (${e.message}). Nothing was seated; allow signing for this connection`) }
    let valid = false
    try { valid = verifyEvent(signed) } catch { /* invalid */ }
    if (!valid || signed.pubkey !== manifest.pubkey || signed.kind !== probe.kind || signed.created_at !== probe.created_at) {
      throw new Error('the Bunker returned a probe that does not verify as this agent. Nothing was seated')
    }
    if (!HEX64.test(signer.clientSecretHex || '')) throw new Error('the pairing returned no client key. Nothing was seated')
    // The remote signer's own key, from the handshake; it need not be the agent's key.
    const pointer = bunkerPointer(String(signer.bunkerUri || '').match(/^bunker:\/\/([0-9a-f]{64})\?/)?.[1] || '', relays)
    seat(manifest.bunkerClientRef, signer.clientSecretHex)
    try { seat(manifest.bunkerUriRef, pointer) } catch (e) { try { unlinkSync(manifest.bunkerClientRef) } catch { /* best effort */ } throw e }
    return { npub: nip19.npubEncode(pk), written: refs }
  } finally { try { await signer.close?.() } catch { /* best effort */ } }
}

async function main(argv) {
  const flag = n => { const i = argv.indexOf(n); return i < 0 ? '' : argv[i + 1] || '' }
  const all = n => argv.reduce((acc, a, i) => (a === n && argv[i + 1] ? [...acc, argv[i + 1]] : acc), [])
  const id = flag('--id')
  if (!id) { console.error('usage: instance-pair.mjs --id <name> [--out <staging dir>] [--relay wss://…]… [--timeout-s <n>]'); return 2 }
  if (typeof process.getuid === 'function' && process.getuid() !== 0) { console.error('instance-pair: run as root; the credential files must be root-owned for the init step to accept them'); return 1 }
  const outDir = resolve(flag('--out') || join(process.env.HOME || '/root', '.nvoy', 'staged'))
  let manifest
  try { manifest = readManifest(outDir, id) } catch (e) { console.error(`instance-pair: staged manifest ${join(outDir, `${id}.json`)}: ${e.message}`); return 1 }
  const relays = all('--relay').length ? all('--relay') : manifest.relays
  const timeoutMs = Math.max(30, Number(flag('--timeout-s')) || 300) * 1000
  const { nostrConnectSigner } = await import('../../lib/nave-connect.mjs')
  try {
    const r = await pairInstance(manifest, {
      pair: nostrConnectSigner, relays, timeoutMs,
      onUri: uri => {
        console.log(`\nOpen this link in your Bunker and approve it with ${manifest.id}'s key (${nip19.npubEncode(manifest.pubkey)}).`)
        console.log(`It works once, and this tool waits ${timeoutMs / 1000} s for it:\n\n${uri}\n`)
      },
      onLog: m => { if (process.env.NVOY_PAIR_DEBUG) console.error(`  ${m}`) },
    })
    console.log(`paired: ${manifest.id} signs as ${r.npub}; a probe it signed verified.`)
    for (const p of r.written) console.log(`seated: ${p} (root 0600)`)
    console.log(`next: instance-identity.mjs check --id ${manifest.id}`)
    return 0
  } catch (e) { console.error(`instance-pair: ${e.message}`); return 1 }
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) process.exit(await main(process.argv.slice(2)))
