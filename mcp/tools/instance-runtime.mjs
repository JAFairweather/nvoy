#!/usr/bin/env node
// instance-runtime.mjs — one isolated Nvoy participant runtime per identity.
//
// A manifest is intentionally boring JSON: its public half names one participant, its state
// directory, policy grantors, and relays. Its sole private reference is a mode-0600 nsec file.
// `watch` never reads that file; it starts the keyless envelope observer. `attention` reads it
// only to launch the existing grant-gated reader with an instance-specific HOME/state directory.
// No decrypted message is persisted or passed to a watcher.
//
//   node tools/instance-runtime.mjs describe --manifest codex.json
//   node tools/instance-runtime.mjs watch --manifest codex.json
//   node tools/instance-runtime.mjs attention --manifest codex.json

import { readFileSync, statSync } from 'node:fs'
import { resolve } from 'node:path'
import { spawn } from 'node:child_process'
import { decode } from 'nostr-tools/nip19'
import { getPublicKey } from 'nostr-tools/pure'

const die = m => { console.error(`instance-runtime: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const command = process.argv[2]
const manifestPath = flag('--manifest')
if (!['describe', 'watch', 'attention'].includes(command) || !manifestPath) die('usage: describe|watch|attention --manifest <path>')

let manifest
try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) } catch (e) { die(`cannot read manifest: ${e.message}`) }
const hex = v => String(v || '').toLowerCase()
const toHex = v => String(v || '').startsWith('npub1') ? decode(String(v)).data : hex(v)
const valid = v => /^[0-9a-f]{64}$/.test(v)
const id = String(manifest.id || '')
const stateDir = String(manifest.stateDir || '')
const keyFile = String(manifest.keyFile || '')
const recipient = toHex(manifest.recipient || '')
const grantors = (Array.isArray(manifest.grantors) ? manifest.grantors : []).map(toHex)
const relays = (Array.isArray(manifest.relays) ? manifest.relays : []).map(String).filter(v => /^wss:\/\//.test(v))
if (!/^[a-z0-9][a-z0-9._-]{1,63}$/i.test(id)) die('manifest.id must be a short stable identifier')
if (!stateDir || !keyFile || !valid(recipient) || !grantors.length || !grantors.every(valid) || !relays.length) die('manifest requires stateDir, keyFile, recipient, grantors, and wss relays')
let mode
try { mode = statSync(keyFile).mode & 0o777 } catch (e) { die(`keyFile unavailable: ${e.message}`) }
if (mode !== 0o600) die(`keyFile must be mode 0600 (found ${mode.toString(8)})`)
const baseEnv = { ...process.env, HOME: stateDir, NVOY_RELAYS: relays.join(','), GRANTORS: grantors.join(',') }
delete baseEnv.NVOY_NSEC
const tool = name => resolve(new URL('.', import.meta.url).pathname, name)
if (command === 'describe') {
  console.log(JSON.stringify({ id, recipient, grantors, relays, stateDir, keyFileMode: '0600', watcher: 'keyless' }, null, 2)); process.exit(0)
}
if (command === 'watch') {
  const child = spawn(process.execPath, [tool('keyless-wake-watcher.mjs'), '--recipient', recipient,
    '--seen-path', resolve(stateDir, 'keyless-wake-seen.log'), '--queue-path', resolve(stateDir, 'keyless-wake-queue.jsonl')], { env: baseEnv, stdio: 'inherit' })
  child.on('exit', code => process.exit(code ?? 1))
} else {
  // The only keyed step. Read the local 0600 file directly into the child environment; it is never
  // an argument, output, queue entry, or watcher input. attention.mjs performs the live 440/441 gate.
  const nsec = readFileSync(keyFile, 'utf8').trim()
  let actual
  try { actual = getPublicKey(nsec.startsWith('nsec1') ? decode(nsec).data : Uint8Array.from(Buffer.from(nsec, 'hex'))) } catch { die('keyFile is not an nsec or 64-hex secret') }
  if (actual !== recipient) die('keyFile does not match manifest.recipient')
  const child = spawn(process.execPath, [tool('attention.mjs'), '--new', '--json'], { env: { ...baseEnv, NVOY_NSEC: nsec }, stdio: 'inherit' })
  child.on('exit', code => process.exit(code ?? 1))
}
