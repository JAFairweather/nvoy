// runtime_manifest.mjs — the deliberately small trusted configuration reader for #44.
//
// The adapter must not be able to select somebody else's identity by passing a manifest
// pathname.  Production callers name an instance, and this module finds its manifest below a
// supervisor-owned directory.  Tests may supply a different root, but every caller still gets
// the same structural validation and duplicate-identity check.

import { lstatSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { resolve, dirname, relative, sep } from 'node:path'
import { decode } from 'nostr-tools/nip19'

const die = message => { throw new Error(message) }
const hex = value => String(value || '').toLowerCase()
const toHex = value => String(value || '').startsWith('npub1') ? decode(String(value)).data : hex(value)
const valid = value => /^[0-9a-f]{64}$/.test(value)
const contained = (root, child) => child === root || child.startsWith(root + sep)

export function instanceId(value) {
  const id = String(value || '')
  if (!/^[a-z0-9][a-z0-9._-]{1,63}$/i.test(id)) die('instance id must be a short stable identifier')
  return id
}

function regular(path, label) {
  let st
  try { st = lstatSync(path) } catch { die(`${label} is missing`) }
  if (!st.isFile() || st.isSymbolicLink()) die(`${label} must be a regular non-symlink file`)
  return st
}

function safeDirectory(path, label) {
  // It is fine for an installer to create this later. Once it exists, though, a symlink would
  // let one identity point at another identity's state/socket tree.
  try {
    const st = lstatSync(path)
    if (!st.isDirectory() || st.isSymbolicLink()) die(`${label} must be a directory, never a symlink`)
  } catch (e) { if (e?.code !== 'ENOENT') throw e }
}

export function readManifest(root, requestedId) {
  const id = instanceId(requestedId)
  const canonicalRoot = realpathSync(root)
  const path = resolve(canonicalRoot, `${id}.json`)
  if (dirname(path) !== canonicalRoot) die('manifest escapes instance root')
  regular(path, 'manifest')
  let raw
  try { raw = JSON.parse(readFileSync(path, 'utf8')) } catch (e) { die(`manifest is not valid JSON: ${e.message}`) }
  if (raw.id !== id) die('manifest id does not match requested instance')
  const pubkey = toHex(raw.pubkey || raw.recipient)
  const grantors = (Array.isArray(raw.grantors) ? raw.grantors : []).map(toHex)
  const relays = (Array.isArray(raw.relays) ? raw.relays : []).map(String).filter(v => /^wss:\/\//.test(v))
  if (!valid(pubkey) || !grantors.length || !grantors.every(valid) || !relays.length) die('manifest requires pubkey, grantors, and wss relays')
  const rawStateDir = String(raw.state_dir || raw.stateDir || '')
  const rawRuntimeDir = String(raw.runtime_dir || raw.runtimeDir || '')
  const rawSpoolDir = String(raw.spool_dir || raw.spoolDir || '')
  if (!rawStateDir || !rawRuntimeDir || !rawSpoolDir) die('manifest requires state_dir, runtime_dir, and spool_dir')
  const stateDir = resolve(rawStateDir)
  const runtimeDir = resolve(rawRuntimeDir)
  const spoolDir = resolve(rawSpoolDir)
  if (stateDir === '/' || runtimeDir === '/' || spoolDir === '/') die('manifest requires bounded state_dir, runtime_dir, and spool_dir')
  safeDirectory(stateDir, 'state_dir')
  safeDirectory(runtimeDir, 'runtime_dir')
  safeDirectory(spoolDir, 'spool_dir')
  const keyRef = String(raw.key_ref || raw.keyRef || '')
  if (keyRef && !keyRef.startsWith('/')) die('key_ref must be an absolute broker-only credential path')
  const bunkerUriRef = String(raw.bunker_uri_ref || raw.bunkerUriRef || '')
  const bunkerClientRef = String(raw.bunker_client_ref || raw.bunkerClientRef || '')
  if ((bunkerUriRef || bunkerClientRef) && (!bunkerUriRef.startsWith('/') || !bunkerClientRef.startsWith('/'))) die('Bunker signer references must both be absolute paths')
  if (!keyRef && !bunkerUriRef) die('manifest requires a broker credential reference')
  const sharedGid = Number(raw.shared_gid ?? raw.sharedGid)
  if (!Number.isInteger(sharedGid) || sharedGid < 0) die('manifest requires non-negative shared_gid for the broker/adapter group')
  const watcherUid = Number(raw.watcher_uid ?? raw.watcherUid)
  const brokerUid = Number(raw.broker_uid ?? raw.brokerUid)
  const adapterUid = Number(raw.adapter_uid ?? raw.adapterUid)
  if (![watcherUid, brokerUid, adapterUid].every(v => Number.isInteger(v) && v > 0)) die('manifest requires positive watcher_uid, broker_uid, and adapter_uid')
  if (new Set([watcherUid, brokerUid, adapterUid]).size !== 3) die('watcher_uid, broker_uid, and adapter_uid must be distinct')
  const workerImage = String(raw.worker_image || raw.workerImage || '')
  const workerRunner = String(raw.worker_runner || raw.workerRunner || '')
  const workerCredentialRef = String(raw.worker_credential_ref || raw.workerCredentialRef || '')
  if ((workerImage || workerRunner || workerCredentialRef) && (!/^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$/i.test(workerImage) || !['codex', 'claude'].includes(workerRunner) || !workerCredentialRef.startsWith('/'))) die('worker_image must be digest-pinned, worker_runner must be codex or claude, and worker_credential_ref must be absolute')
  return Object.freeze({ id, path, root: canonicalRoot, pubkey, grantors, relays, stateDir, runtimeDir, spoolDir,
    sharedGid, watcherUid, brokerUid, adapterUid, serviceUser: String(raw.service_user || raw.serviceUser || ''), keyRef, bunkerUriRef, bunkerClientRef, workerImage, workerRunner, workerCredentialRef })
}

// Supervisor preflight: a second identity must never accidentally share a state or runtime
// root. This is intentionally fail-closed rather than silently picking one manifest.
export function assertNoCollisions(root, candidate) {
  const canonicalRoot = realpathSync(root)
  const seen = new Map()
  for (const name of readdirSync(canonicalRoot)) {
    if (!name.endsWith('.json')) continue
    const id = name.slice(0, -5)
    let m
    try { m = readManifest(canonicalRoot, id) } catch (e) { die(`invalid manifest ${name}: ${e.message}`) }
    for (const [field, value] of [['pubkey', m.pubkey], ['stateDir', m.stateDir], ['runtimeDir', m.runtimeDir], ['spoolDir', m.spoolDir]]) {
      const key = `${field}:${value}`
      if (seen.has(key)) die(`${field} collision between ${seen.get(key)} and ${m.id}`)
      seen.set(key, m.id)
    }
  }
  if (!candidate || !contained(canonicalRoot, candidate.path)) return
}
