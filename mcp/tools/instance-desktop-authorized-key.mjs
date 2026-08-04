#!/usr/bin/env node
// Render the exact OpenSSH authorized_keys capability for one Desktop sync instance. The output
// grants no shell, forwarding, PTY, agent, X11, or caller-selected command. Install it only on
// the manifest adapter UID account; that UID has no broker/Bunker or model-provider credential.

import { lstatSync, readFileSync } from 'node:fs'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'

const die = message => { console.error(`instance-desktop-authorized-key: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), keyFile = flag('--public-key-file'), container = flag('--container')
if (!id || !keyFile || (container && !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(container))) die('usage: --instance <id> --public-key-file <OpenSSH-public-key> [--container <fixed-adapter-container>]')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (error) { die(error.message) }
if (manifest.brokerMode !== 'local') die('forced sync command belongs on the single remote broker host')
let stat
try { stat = lstatSync(keyFile) } catch { die('public key file is missing') }
if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024) die('public key must be a bounded regular non-symlink file')
const fields = readFileSync(keyFile, 'utf8').trim().split(/\s+/)
if (!/^(ssh-ed25519|ecdsa-sha2-nistp256)$/.test(fields[0] || '') || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1] || '')) die('unsupported or malformed OpenSSH public key')
const key = `${fields[0]} ${fields[1]}`
const command = container
  ? `/usr/bin/docker exec -i --user ${manifest.adapterUid}:${manifest.brokerAdapterGid} ${container} /usr/local/bin/node /srv/nvoy/mcp/tools/instance-desktop-sync.mjs --instance ${manifest.id}`
  : `/usr/bin/env NVOY_INSTANCE_ROOT=/etc/nvoy/instances /usr/bin/node /opt/nvoy/mcp/tools/instance-desktop-sync.mjs --instance ${manifest.id}`
console.log(`restrict,command="${command}" ${key} nvoy-desktop-sync-${manifest.id}`)
