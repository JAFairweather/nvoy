#!/usr/bin/env node
// render-instance-compose.mjs — render an identity-bound Compose file from one immutable manifest.
// Compose cannot derive `user:` from JSON. A hand-written env file would be a second mutable
// identity authority, so this renderer substitutes every identity-bearing value itself.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'

const die = m => { console.error(`render-instance-compose: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), image = flag('--image')
if (!id || !image) die('usage: --instance <id> --image <immutable-image-ref>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let m
try { m = readManifest(root, instanceId(id)); assertNoCollisions(root, m) } catch (e) { die(e.message) }
const templatePath = resolve(new URL('../../deploy/participant-runtime.compose.yml', import.meta.url).pathname)
let out = readFileSync(templatePath, 'utf8')
const replacements = {
  '${NVOY_IMAGE:?set NVOY_IMAGE}': JSON.stringify(image), '${WATCHER_UID:?}': String(m.watcherUid),
  '${BROKER_UID:?}': String(m.brokerUid), '${ADAPTER_UID:?}': String(m.adapterUid), '${SHARED_GID:?}': String(m.sharedGid),
  '${INSTANCE_ID:?}': JSON.stringify(m.id), '${INSTANCE_ID}': m.id, '${MANIFEST_DIR:?}': JSON.stringify(m.root),
  '${BROKER_CREDENTIAL_FILE:?set BROKER_CREDENTIAL_FILE}': JSON.stringify(m.keyRef),
}
for (const [from, to] of Object.entries(replacements)) out = out.split(from).join(to)
if (/\$\{(?:WATCHER_UID|BROKER_UID|ADAPTER_UID|SHARED_GID|INSTANCE_ID|MANIFEST_DIR|BROKER_CREDENTIAL_FILE)/.test(out)) die('template retained an identity deployment variable')
process.stdout.write(out)
