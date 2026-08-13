// runtime_manifest.mjs — the deliberately small trusted configuration reader for #44.
//
// The adapter must not be able to select somebody else's identity by passing a manifest
// pathname.  Production callers name an instance, and this module finds its manifest below a
// supervisor-owned directory.  Tests may supply a different root, but every caller still gets
// the same structural validation and duplicate-identity check.

import { lstatSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { resolve, dirname, relative, sep } from 'node:path'
import { decode } from 'nostr-tools/nip19'
import { codexThreadId as validCodexThreadId, localControlSocket } from './codex_app_server.mjs'

const die = message => { throw new Error(message) }
const hex = value => String(value || '').toLowerCase()
const toHex = value => String(value || '').startsWith('npub1') ? decode(String(value)).data : hex(value)
const valid = value => /^[0-9a-f]{64}$/.test(value)
const validChannel = value => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
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
  const carriers = (Array.isArray(raw.task_carriers || raw.taskCarriers) ? (raw.task_carriers || raw.taskCarriers) : []).map(entry => {
    const pubkey = toHex(entry?.pubkey)
    const channels = (Array.isArray(entry?.channels) ? entry.channels : []).map(value => String(value || '').toLowerCase())
    if (!valid(pubkey) || !channels.length || !channels.every(validChannel) || new Set(channels).size !== channels.length) die('each task_carrier requires one pubkey and distinct channel UUIDs')
    return Object.freeze({ pubkey, channels: Object.freeze(channels) })
  })
  const relays = (Array.isArray(raw.relays) ? raw.relays : []).map(String).filter(v => /^wss:\/\//.test(v))
  if (!valid(pubkey) || !grantors.length || !grantors.every(valid) || !relays.length) die('manifest requires pubkey, grantors, and wss relays')
  if (new Set(carriers.map(entry => entry.pubkey)).size !== carriers.length) die('task_carrier pubkeys must be distinct')
  const approvalEndpoint = String(raw.approval_endpoint || raw.approvalEndpoint || '')
  if (approvalEndpoint) {
    let parsed
    try { parsed = new URL(approvalEndpoint) } catch { die('approval_endpoint must be an HTTPS origin') }
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') die('approval_endpoint must be an HTTPS origin')
  }
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
  const brokerMode = String(raw.broker_mode || raw.brokerMode || 'local')
  if (!['local', 'remote'].includes(brokerMode)) die('broker_mode must be local or remote')
  if (brokerMode === 'local' && !keyRef && !bunkerUriRef) die('a local broker manifest requires a credential reference')
  if (brokerMode === 'remote' && (keyRef || bunkerUriRef || bunkerClientRef)) die('a remote-broker Desktop manifest must be keyless')
  // These are intentionally different groups. The broker alone may connect to the adapter's
  // private socket; the worker instead gets only the narrower file handoff group.
  const brokerAdapterGid = Number(raw.broker_adapter_gid ?? raw.brokerAdapterGid)
  const workerHandoffGid = Number(raw.worker_handoff_gid ?? raw.workerHandoffGid)
  if (![brokerAdapterGid, workerHandoffGid].every(v => Number.isInteger(v) && v >= 0) || brokerAdapterGid === workerHandoffGid) die('manifest requires distinct non-negative broker_adapter_gid and worker_handoff_gid')
  const watcherUid = Number(raw.watcher_uid ?? raw.watcherUid)
  const brokerUid = Number(raw.broker_uid ?? raw.brokerUid)
  const adapterUid = Number(raw.adapter_uid ?? raw.adapterUid)
  const workerUid = Number(raw.worker_uid ?? raw.workerUid)
  if (![watcherUid, brokerUid, adapterUid, workerUid].every(v => Number.isInteger(v) && v > 0)) die('manifest requires positive watcher_uid, broker_uid, adapter_uid, and worker_uid')
  if (new Set([watcherUid, brokerUid, adapterUid, workerUid]).size !== 4) die('watcher_uid, broker_uid, adapter_uid, and worker_uid must be distinct')
  // The channel forced command has to name the adapter container exactly. Left to Compose that
  // name is *derived* — project prefix, service, replica index — so renaming the project or
  // changing the stack layout silently retargets an installed principal at a container that no
  // longer exists, and the only symptom is a channel that goes quiet (#154).
  //
  // Declaring it here gives the Compose file and the principal one authority to read. The default
  // is byte-for-byte what Compose already generates, replica suffix included, so pinning it
  // renames nothing on a running stack — it only stops the name being able to move.
  const adapterContainer = String(raw.adapter_container || raw.adapterContainer || '') || `nvoy-${id}-adapter-1`
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(adapterContainer)) die('adapter_container must be a valid Docker container name')
  const workerImage = String(raw.worker_image || raw.workerImage || '')
  const workerRunner = String(raw.worker_runner || raw.workerRunner || '')
  const workerCredentialRef = String(raw.worker_credential_ref || raw.workerCredentialRef || '')
  if ((workerImage || workerRunner || workerCredentialRef) && (!/^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$/i.test(workerImage) || !['codex', 'claude'].includes(workerRunner) || !workerCredentialRef.startsWith('/'))) die('worker_image must be digest-pinned, worker_runner must be codex or claude, and worker_credential_ref must be absolute')
  // Delivery is deliberately independent of the Nostr admission pipeline.  `headless` is the
  // existing worker; a desktop adapter is a local process which resumes one explicit Codex
  // thread.  Never silently create or select a desktop conversation from an incoming message.
  const deliveryMode = String(raw.delivery_mode || raw.deliveryMode || 'headless')
  const workerEnabled = raw.worker_enabled == null && raw.workerEnabled == null
    ? deliveryMode === 'headless'
    : (raw.worker_enabled ?? raw.workerEnabled)
  if (typeof workerEnabled !== 'boolean') die('worker_enabled must be boolean')
  if (workerEnabled && deliveryMode !== 'headless') die('worker_enabled is valid only for headless delivery')
  if (workerEnabled && (!workerImage || !workerRunner || !workerCredentialRef)) die('a worker-enabled manifest requires worker_image, worker_runner, and worker_credential_ref')
  if (!workerEnabled && (workerImage || workerRunner || workerCredentialRef)) die('a worker-disabled manifest cannot carry a model-worker credential or runtime')
  const codexThreadId = String(raw.codex_thread_id || raw.codexThreadId || '')
  const codexTransport = String(raw.codex_transport || raw.codexTransport || 'spawn')
  const codexSocketPath = String(raw.codex_app_server_socket || raw.codexAppServerSocket || '')
  const codexAppBundleId = String(raw.codex_app_bundle_id || raw.codexAppBundleId || '')
  const codexProjectLabel = String(raw.codex_project_label || raw.codexProjectLabel || '')
  const codexChatLabel = String(raw.codex_chat_label || raw.codexChatLabel || '')
  const codexUiDriver = String(raw.codex_ui_driver || raw.codexUiDriver || '')
  const sshTarget = String(raw.ssh_target || raw.sshTarget || '')
  const sshIdentityFile = String(raw.ssh_identity_file || raw.sshIdentityFile || '')
  const sshKnownHostsFile = String(raw.ssh_known_hosts_file || raw.sshKnownHostsFile || '')
  const sshKnownHostsSha256 = hex(raw.ssh_known_hosts_sha256 || raw.sshKnownHostsSha256 || '')
  if (!['headless', 'codex_app_server', 'macos_desktop', 'notify_only'].includes(deliveryMode)) die('delivery_mode must be headless, codex_app_server, macos_desktop, or notify_only')
  if (!['spawn', 'local_control_socket'].includes(codexTransport)) die('codex_transport must be spawn or local_control_socket')
  if (deliveryMode === 'codex_app_server') {
    try { validCodexThreadId(codexThreadId) } catch { die('codex_app_server delivery requires an explicit codex_thread_id (persistent app-server UUID or thr_ id)') }
    if (codexTransport === 'local_control_socket') {
      try { localControlSocket(codexSocketPath) } catch (e) { die(e.message) }
    }
  }
  if (deliveryMode === 'macos_desktop') {
    try { validCodexThreadId(codexThreadId) } catch { die('macos_desktop delivery requires an explicit codex_thread_id') }
    if (codexTransport !== 'local_control_socket') die('macos_desktop requires the read-only local control socket observer')
    try { localControlSocket(codexSocketPath) } catch (e) { die(e.message) }
    if (codexAppBundleId !== 'com.openai.codex' || !codexProjectLabel.trim() || !codexChatLabel.trim() || !codexUiDriver.startsWith('/')) {
      die('macos_desktop requires the fixed Codex bundle, project/chat labels, and an absolute UI driver')
    }
  }
  if (brokerMode === 'remote') {
    if (!['codex_app_server', 'macos_desktop'].includes(deliveryMode) || codexTransport !== 'local_control_socket') die('a remote broker is valid only for an exact local Codex Desktop binding')
    if (!/^[a-z_][a-z0-9_-]{0,31}@[a-z0-9.-]+$/i.test(sshTarget) || !sshIdentityFile.startsWith('/') ||
        !sshKnownHostsFile.startsWith('/') || !/^[0-9a-f]{64}$/.test(sshKnownHostsSha256)) {
      die('a remote broker manifest requires fixed ssh_target, absolute SSH files, and ssh_known_hosts_sha256')
    }
  }
  return Object.freeze({ id, path, root: canonicalRoot, pubkey, grantors, carriers: Object.freeze(carriers), relays, stateDir, runtimeDir, spoolDir,
    brokerMode, brokerAdapterGid, workerHandoffGid, watcherUid, brokerUid, adapterUid, workerUid, adapterContainer, serviceUser: String(raw.service_user || raw.serviceUser || ''), keyRef, bunkerUriRef, bunkerClientRef, workerEnabled, workerImage, workerRunner, workerCredentialRef, deliveryMode, codexThreadId, codexTransport, codexSocketPath, codexAppBundleId, codexProjectLabel, codexChatLabel, codexUiDriver,
    sshTarget, sshIdentityFile, sshKnownHostsFile, sshKnownHostsSha256, approvalEndpoint: approvalEndpoint.replace(/\/$/, '') })
}

// Supervisor preflight: a second identity must never accidentally share a state or runtime
// root. This is intentionally fail-closed rather than silently picking one manifest.
//
// THE UIDS AND GIDS ARE CHECKED HERE TOO (#177), and they are the reason this is a security check
// rather than a tidiness one. `instance-runtime-init.mjs` provisions the Bunker URI and the NIP-46
// client key to `brokerUid:brokerAdapterGid` at mode 0400 — owner-read only, which is correct and
// which depends entirely on that owner being unique to the instance. There is no `useradd` anywhere
// in this path: a uid is a number that gets chowned, so a duplicate is not a name clash that fails
// loudly, it is a second instance whose broker runs as the same OS user and can read the first
// instance's credentials. Within one manifest the four uids are already required to be distinct
// (see above); between manifests nothing enforced it, and the live root's non-overlapping blocks
// were a convention held by hand.
export function assertNoCollisions(root, candidate) {
  const canonicalRoot = realpathSync(root)
  const seen = new Map()
  for (const name of readdirSync(canonicalRoot)) {
    if (!name.endsWith('.json')) continue
    const id = name.slice(0, -5)
    let m
    try { m = readManifest(canonicalRoot, id) } catch (e) { die(`invalid manifest ${name}: ${e.message}`) }
    // `namespace` is what is compared; `field` is only what the message calls it. Every uid shares
    // ONE namespace, and so does every gid, because the hazard is two instances resolving to the
    // same OS user or group — not two instances using the same number for the same role. Keying by
    // role would let this instance's watcher_uid equal that instance's broker_uid and call it clean,
    // which is the same user with a different label on it.
    for (const [namespace, field, value] of [
      ['pubkey', 'pubkey', m.pubkey], ['stateDir', 'stateDir', m.stateDir],
      ['runtimeDir', 'runtimeDir', m.runtimeDir], ['spoolDir', 'spoolDir', m.spoolDir],
      ['uid', 'watcher_uid', m.watcherUid], ['uid', 'broker_uid', m.brokerUid],
      ['uid', 'adapter_uid', m.adapterUid], ['uid', 'worker_uid', m.workerUid],
      ['gid', 'broker_adapter_gid', m.brokerAdapterGid], ['gid', 'worker_handoff_gid', m.workerHandoffGid]]) {
      const key = `${namespace}:${value}`
      const prior = seen.get(key)
      // The message names both roles when they differ, because "uid collision between a and b" sends
      // the operator looking at the wrong four numbers when it is a's worker and b's watcher.
      if (prior) {
        die(prior.field === field
          ? `${field} collision between ${prior.id} and ${m.id}`
          : `${namespace} ${value} collision between ${prior.id} (${prior.field}) and ${m.id} (${field})`)
      }
      seen.set(key, { id: m.id, field })
    }
  }
  if (!candidate || !contained(canonicalRoot, candidate.path)) return
}
