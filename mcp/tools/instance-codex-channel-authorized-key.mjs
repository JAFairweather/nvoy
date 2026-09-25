#!/usr/bin/env node
// Render the sole forced SSH command for one fixed-instance Codex channel MCP reader. With
// --mode feed, render instead the second key a portable Codex harness needs: its wake feed
// (codex-channel-feed.mjs), under the same hardening and a tag of its own. Each key reaches
// exactly one program, so the two lines are installed for two distinct public keys.

import { lstatSync, readFileSync } from 'node:fs'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'

const die = message => { console.error(`instance-codex-channel-authorized-key: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), keyFile = flag('--public-key-file'), container = flag('--container'), mode = flag('--mode') || 'channel'
if (!id || !keyFile || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(container)) die('usage: --instance <id> --public-key-file <OpenSSH-public-key> --container <fixed-adapter-container> [--mode channel|feed]')
if (mode !== 'channel' && mode !== 'feed') die('--mode must be channel or feed')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (error) { die(error.message) }
if (manifest.brokerMode !== 'local' || manifest.deliveryMode !== 'notify_only' || manifest.workerEnabled) die('Codex channel MCP forced command requires a local-broker, worker-disabled notify_only instance')
const stat = lstatSync(keyFile)
if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024) die('public key must be a bounded regular non-symlink file')
const fields = readFileSync(keyFile, 'utf8').trim().split(/\s+/)
if (!/^(ssh-ed25519|ecdsa-sha2-nistp256)$/.test(fields[0] || '') || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1] || '')) die('unsupported or malformed OpenSSH public key')
const [program, tag] = mode === 'feed' ? ['codex-channel-feed.mjs', 'nvoy-codex-feed'] : ['codex-channel-mcp.mjs', 'nvoy-codex-channel']
const command = `/usr/bin/docker exec -i --user ${manifest.workerUid}:${manifest.workerHandoffGid} ${container} /usr/local/bin/node /srv/nvoy/mcp/tools/${program} --instance ${manifest.id}`
console.log(`restrict,command="${command}" ${fields[0]} ${fields[1]} ${tag}-${manifest.id}`)
