#!/usr/bin/env node
// render-instance-compose.mjs — render an identity-bound Compose file from one immutable manifest.
// Compose cannot derive `user:` from JSON. A hand-written env file would be a second mutable
// identity authority, so this renderer substitutes every identity-bearing value itself.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'

const die = m => { console.error(`render-instance-compose: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), image = flag('--image'), workerImageOverride = flag('--worker-image')
if (!id || !image) die('usage: --instance <id> --image <immutable-image-ref>')
if (!/^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$/i.test(image)) die('--image must be a canonical name@sha256:<64-hex> reference')
if (workerImageOverride && !/^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$/i.test(workerImageOverride)) die('--worker-image must be a canonical name@sha256:<64-hex> reference')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let m
try { m = readManifest(root, instanceId(id)); assertNoCollisions(root, m) } catch (e) { die(e.message) }
if (!m.bunkerUriRef || !m.bunkerClientRef) die('production runtime requires bunker_uri_ref and bunker_client_ref in its manifest')
if (m.workerEnabled && (!m.workerImage || !m.workerRunner || !m.workerCredentialRef)) die('a worker-enabled production runtime requires a digest-pinned worker_image, worker_runner, and worker_credential_ref')
if (!m.workerEnabled && workerImageOverride) die('--worker-image is invalid for a worker-disabled instance')
const workerImage = workerImageOverride || m.workerImage
const templatePath = resolve(new URL('../../deploy/participant-runtime.compose.yml', import.meta.url).pathname)
let out = readFileSync(templatePath, 'utf8')
if (!m.workerEnabled) out = out.replace(/^\s*# @worker-begin\n[\s\S]*?^\s*# @worker-end\n?/gm, '')
else out = out.replace(/^\s*# @worker-(?:begin|end)\n?/gm, '')
const replacements = {
  '${NVOY_IMAGE:?set NVOY_IMAGE}': JSON.stringify(image), '${WATCHER_UID:?}': String(m.watcherUid),
  '${BROKER_UID:?}': String(m.brokerUid), '${ADAPTER_UID:?}': String(m.adapterUid), '${WORKER_UID:?}': String(m.workerUid), '${BROKER_ADAPTER_GID:?}': String(m.brokerAdapterGid), '${WORKER_HANDOFF_GID:?}': String(m.workerHandoffGid),
  '${INSTANCE_ID:?}': m.id, '${INSTANCE_ID}': m.id, '${MANIFEST_DIR:?}': JSON.stringify(m.root),
  '${STATE_DIR:?}': JSON.stringify(m.stateDir), '${SPOOL_DIR:?}': JSON.stringify(m.spoolDir), '${RUNTIME_DIR:?}': JSON.stringify(m.runtimeDir),
  '${BUNKER_URI_FILE:?}': JSON.stringify(m.bunkerUriRef), '${BUNKER_CLIENT_FILE:?}': JSON.stringify(m.bunkerClientRef),
  '${WORKER_IMAGE:?}': JSON.stringify(workerImage), '${WORKER_RUNNER:?}': m.workerRunner, '${WORKER_CREDENTIAL_FILE:?}': JSON.stringify(m.workerCredentialRef),
  '${BROKER_CREDENTIAL_FILE:?set BROKER_CREDENTIAL_FILE}': JSON.stringify(m.keyRef),
}
for (const [from, to] of Object.entries(replacements)) out = out.split(from).join(to)
if (/\$\{(?:WATCHER_UID|BROKER_UID|ADAPTER_UID|WORKER_UID|BROKER_ADAPTER_GID|WORKER_HANDOFF_GID|INSTANCE_ID|MANIFEST_DIR|STATE_DIR|SPOOL_DIR|RUNTIME_DIR|BUNKER_URI_FILE|BUNKER_CLIENT_FILE|WORKER_IMAGE|WORKER_RUNNER|WORKER_CREDENTIAL_FILE|BROKER_CREDENTIAL_FILE)/.test(out)) die('template retained an identity deployment variable')
process.stdout.write(out)
