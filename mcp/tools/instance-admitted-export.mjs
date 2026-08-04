#!/usr/bin/env node
// Export only records already accepted by the identity-scoped adapter. This command is intended
// to sit behind a forced SSH command: it has no signer, relay, manifest-path, or arbitrary-file
// argument, and emits one validated JSON record per line.

import { lstatSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest, instanceId } from './runtime_manifest.mjs'
import { validateAdmittedTask } from './admitted_task.mjs'

const die = message => { console.error(`instance-admitted-export: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id || process.argv.length !== 4) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (process.getuid?.() !== manifest.adapterUid) die('must run as the manifest-bound adapter user')

const queue = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
let stat
try { stat = lstatSync(queue) } catch (error) { if (error.code === 'ENOENT') process.exit(0); die(error.message) }
if (!stat.isFile() || stat.isSymbolicLink()) die('admitted queue must be a regular non-symlink file')
if (stat.size > 64 * 1024 * 1024) die('admitted queue exceeds export bound')

for (const line of readFileSync(queue, 'utf8').split('\n').filter(Boolean)) {
  if (Buffer.byteLength(line) > 1024 * 1024) die('admitted record exceeds export bound')
  let record
  try { record = JSON.parse(line) } catch { die('admitted queue contains malformed JSON') }
  try { validateAdmittedTask(record, { instance: manifest.id, scopeSubject: manifest.pubkey, grantors: manifest.grantors }) } catch { die('admitted queue contains an invalid record') }
  process.stdout.write(JSON.stringify(record) + '\n')
}
