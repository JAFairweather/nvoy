#!/usr/bin/env node
// Render one forced-command SSH capability for a native Claude Code channel. The remote process
// runs as workerUid:workerHandoffGid: admitted tasks are read-only, while only the bounded channel
// cursor and reply queue are writable. No shell, forwarding, PTY, signer, or broker command exists.

import { lstatSync, readFileSync } from 'node:fs'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { principalLine } from './participant_unit.mjs'

const die = message => { console.error(`instance-claude-channel-authorized-key: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), keyFile = flag('--public-key-file'), container = flag('--container')
// BY VALUE, as an alternative to --public-key-file (#188). This tool runs inside the adapter
// container, so a caller on the host holds a path the container cannot see: the two share only
// /etc/nvoy/instances, the rootfs is read-only so `docker cp` is refused, and nobody keeps a public
// key under the instance directory. A host path therefore reaches this process as "file is
// missing" — measured on the live claude-jaf adapter.
//
// A public key is not a secret, so argv is the right channel for it and no path crosses the
// filesystem boundary. --public-key-file stays, for callers already on the same filesystem.
const keyType = flag('--public-key-type'), keyBody = flag('--public-key-body')
if (!id || (!keyFile && !(keyType && keyBody))) {
  die('usage: --instance <id> (--public-key-file <path> | --public-key-type <type> --public-key-body <base64>) [--container <expected-adapter-container>]')
}
if (keyFile && (keyType || keyBody)) die('give --public-key-file or the --public-key-type/--public-key-body pair, not both')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (error) { die(error.message) }
if (manifest.brokerMode !== 'local' || manifest.deliveryMode !== 'notify_only' || manifest.workerEnabled) {
  die('Claude channel forced command requires a local-broker, worker-disabled notify_only instance')
}
// Both paths converge on the same two fields and the same validation, so a key supplied by value
// is not trusted more than one read from a file.
let fields
if (keyFile) {
  let stat
  try { stat = lstatSync(keyFile) } catch { die('public key file is missing') }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024) die('public key must be a bounded regular non-symlink file')
  fields = readFileSync(keyFile, 'utf8').trim().split(/\s+/)
} else {
  fields = [keyType, keyBody]
}
if (!/^(ssh-ed25519|ecdsa-sha2-nistp256)$/.test(fields[0] || '') || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1] || '')) die('unsupported or malformed OpenSSH public key')
// The container is the manifest's to declare, not the caller's to supply — a hand-passed name is
// how the installed principal drifted from the stack in the first place (#154). `--container` is
// kept as an assertion for existing call sites: if you name one, it must be the manifest's.
if (container && container !== manifest.adapterContainer) {
  die(`--container ${container} does not match the manifest adapter_container ${manifest.adapterContainer}`)
}
console.log(principalLine(manifest, fields[0], fields[1]))
