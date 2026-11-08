#!/usr/bin/env node
// presence-collect.mjs — the host half of channel presence (waggle #721 step 4). Run as root on the
// fleet host by nvoy-presence.timer. It reads what only the host can see (the process table, the
// adapter container's id, the installed authorized_keys line) and writes one atomic snapshot per
// instance. It signs nothing, holds no credential, and opens no socket; the broker reads the
// snapshot read-only and decides (presence.mjs).
//
//   presence-collect.mjs --out /var/lib/nvoy/presence --authorized-keys /root/.ssh/authorized_keys
//
// An instance whose adapter container cannot be found still gets a snapshot, marked so: that reads as
// unproven downstream, never as a disconnect.

import { closeSync, fsyncSync, openSync, readdirSync, readFileSync, renameSync, writeSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { readManifest, instanceId } from './runtime_manifest.mjs'
import { keyFingerprint, parsePrincipal, principalComment, verifyPrincipal } from './participant_unit.mjs'
import { buildSnapshot } from './presence.mjs'

// [{ pid, uid, cgroup, argv }] from a /proc tree. A process that vanishes mid-read is skipped.
export function readProcs(procRoot = '/proc') {
  const out = []
  for (const name of readdirSync(procRoot)) {
    if (!/^[1-9][0-9]*$/.test(name)) continue
    try {
      const dir = join(procRoot, name)
      const argv = readFileSync(join(dir, 'cmdline'), 'utf8').split('\0')
      if (argv[argv.length - 1] === '') argv.pop()
      const uid = Number(/^Uid:\s+(\d+)/m.exec(readFileSync(join(dir, 'status'), 'utf8'))?.[1])
      out.push({ pid: Number(name), uid, cgroup: readFileSync(join(dir, 'cgroup'), 'utf8'), argv })
    } catch {}
  }
  return out
}

// The fingerprint a TAGGED installed line binds, or '' (no line, an older line, or a line whose
// fingerprint is not its own key's).
export function installedFingerprint(keysText, manifest) {
  const comment = principalComment(manifest)
  const lines = String(keysText || '').split('\n').map(l => l.trim()).filter(l => { const p = parsePrincipal(l); return p && p.comment === comment })
  if (lines.length !== 1) return ''
  // The whole line must verify against the manifest: restrict intact, the exact docker exec as the
  // worker uid:gid into the adapter, this instance, and the line's own key fingerprint. A line whose
  // command was swapped but still ends in a fingerprint supports no claim.
  const verified = verifyPrincipal(manifest, lines[0])
  return verified?.ok && verified.fingerprint === 'bound' ? keyFingerprint(verified.parsed.keyBody) : ''
}

export function writeAtomic(path, text) {
  const tmp = `${path}.${process.pid}.tmp`
  const fd = openSync(tmp, 'w', 0o644)
  try { writeSync(fd, text); fsyncSync(fd) } finally { closeSync(fd) }
  renameSync(tmp, path)
}

const dockerId = name => {
  const r = spawnSync('docker', ['inspect', '--format', '{{.Id}}', name], { encoding: 'utf8', timeout: 15000 })
  return r.status === 0 ? r.stdout.trim() : ''
}

export function collect({ instances, out, keysPath, procRoot = '/proc', containerId = dockerId, now = Date.now() }) {
  mkdirSync(out, { recursive: true, mode: 0o755 })
  const procs = readProcs(procRoot)
  let keysText = ''
  try { keysText = readFileSync(keysPath, 'utf8') } catch {}
  const written = []
  for (const file of readdirSync(instances).filter(f => f.endsWith('.json') && !f.includes('.compose.'))) {
    let manifest
    try { manifest = readManifest(instances, instanceId(file.slice(0, -5))) } catch { continue }
    if (!manifest.adapterContainer) continue
    const snapshot = buildSnapshot({ manifest, procs, containerId: containerId(manifest.adapterContainer), keyFp: installedFingerprint(keysText, manifest), now })
    writeAtomic(join(out, `${manifest.id}.json`), JSON.stringify(snapshot))
    written.push(manifest.id)
  }
  return written
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
  const out = flag('--out'), keysPath = flag('--authorized-keys')
  if (!out || !keysPath) { console.error('usage: --out <dir> --authorized-keys <file> [--instances <dir>]'); process.exit(2) }
  const written = collect({ instances: flag('--instances') || '/etc/nvoy/instances', out, keysPath })
  console.log(JSON.stringify({ presence_snapshots: written }))
}
