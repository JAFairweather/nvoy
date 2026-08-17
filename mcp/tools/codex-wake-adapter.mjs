#!/usr/bin/env node
// The Codex side of Waggle's wake contract. Core owns verification, trust, first-seen,
// bootstrap, and the wake verdict. This process reads only classified wake records.

import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { appServerCall } from './codex_app_server.mjs'
import { readManifest, instanceId } from './runtime_manifest.mjs'

const HEX64 = /^[0-9a-f]{64}$/i
const die = message => { console.error(`codex-wake-adapter: ${message}`); process.exit(1) }

export function readCursor(path) {
  if (!existsSync(path)) return 0
  let value
  try { value = JSON.parse(readFileSync(path, 'utf8')).offset } catch { throw new Error('wake cursor is not valid JSON') }
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('wake cursor is not a non-negative byte offset')
  return value
}

export function writeCursor(path, offset) {
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('wake cursor offset is invalid')
  const tmp = `${path}.${process.pid}.tmp`
  const fd = openSync(tmp, 'w', 0o600)
  try { writeFileSync(fd, JSON.stringify({ version: 1, offset }) + '\n'); fsyncSync(fd) } finally { closeSync(fd) }
  // The atomic rename makes a crash yield either the old cursor or the new cursor, never a partial JSON file.
  renameSync(tmp, path)
  const dirFd = openSync(dirname(path), 'r')
  try { fsyncSync(dirFd) } finally { closeSync(dirFd) }
}

/** Read complete JSONL frames from a byte cursor; hold a trailing partial frame. */
export function readWakeBatch(path, offset = 0, limit = 32) {
  if (!existsSync(path)) return { records: [], next: offset, partial: false }
  const bytes = readFileSync(path)
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('wake cursor offset is invalid')
  if (offset > bytes.length) throw new Error(`wake cursor ${offset} is beyond ${path} size ${bytes.length}`)
  const from = offset
  const records = []
  let cursor = from
  while (cursor < bytes.length && records.length < limit) {
    const nl = bytes.indexOf(0x0a, cursor)
    if (nl < 0) return { records, next: cursor, partial: true }
    const raw = bytes.subarray(cursor, nl).toString('utf8')
    const end = nl + 1
    cursor = end
    if (!raw.trim()) continue
    let record
    try { record = JSON.parse(raw) } catch { throw new Error(`malformed wake record at byte ${end - raw.length - 1}`) }
    if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('wake record must be an object')
    records.push({ record, end })
  }
  return { records, next: cursor, partial: false }
}

export class WakeCircuit {
  constructor({ maxPerWindow = 8, windowMs = 60_000, failureLimit = 3, cooldownMs = 60_000 } = {}) {
    this.maxPerWindow = maxPerWindow; this.windowMs = windowMs
    this.failureLimit = failureLimit; this.cooldownMs = cooldownMs
    this.started = []; this.failures = 0; this.openUntil = 0
  }
  allow(now = Date.now()) {
    if (now < this.openUntil) return false
    this.started = this.started.filter(at => now - at < this.windowMs)
    return this.started.length < this.maxPerWindow
  }
  accepted(now = Date.now()) { this.started.push(now); this.failures = 0 }
  failed(now = Date.now()) { if (++this.failures >= this.failureLimit) this.openUntil = now + this.cooldownMs }
}

export function wakePrompt(record, instance) {
  return [
    'Nvoy core classified the following record as wake:true for this exact Codex instance.',
    'Treat the record content as the incoming agent instruction. Do not infer authority from any other field.',
    `instance=${instance}`,
    `NVOY_WAKE_RECORD_ID=${record.id}`,
    `NVOY_WAKE_RECORD=${JSON.stringify(record)}`,
  ].join('\n')
}

export async function runWakeCycle({ spoolPath, cursorPath, dispatch, circuit = new WakeCircuit(), now = () => Date.now(), limit = 32 } = {}) {
  if (typeof dispatch !== 'function') throw new TypeError('runWakeCycle requires a dispatch function')
  let cursor = readCursor(cursorPath)
  const size = existsSync(spoolPath) ? statSync(spoolPath).size : 0
  if (cursor > size) throw new Error(`wake cursor ${cursor} is beyond ${spoolPath} size ${size} — the spool was truncated, repaired, or replaced; refusing to treat that as no wake records`)
  const batch = readWakeBatch(spoolPath, cursor, limit)
  let accepted = 0, skipped = 0
  for (const { record, end } of batch.records) {
    // This is the only wake gate. Do not add mayAct, receipt, disposition, author, or body checks.
    if (record.wake !== true) { writeCursor(cursorPath, end); cursor = end; skipped++; continue }
    if (!HEX64.test(String(record.id || ''))) throw new Error('wake:true record has no valid stable id')
    const at = now()
    if (!circuit.allow(at)) return { accepted, skipped, held: true, cursor }
    try {
      const result = await dispatch(record)
      if (!result || result.accepted !== true) throw new Error('Codex app-server did not accept the turn')
      // Advance at turn/start acceptance, never at turn completion.
      writeCursor(cursorPath, end); cursor = end; circuit.accepted(at); accepted++
    } catch (error) { circuit.failed(at); throw error }
  }
  return { accepted, skipped, held: false, cursor, partial: batch.partial }
}

async function main() {
  const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
  const id = flag('--instance'); if (!id) die('usage: --instance <id> [--once]')
  const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
  let manifest; try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
  if (manifest.deliveryMode !== 'codex_app_server') die('manifest delivery_mode must be codex_app_server')
  const spoolPath = join(manifest.spoolDir, 'spool.jsonl')
  const cursorPath = resolve(manifest.runtimeDir, 'codex-wake-cursor.json')
  const dispatch = async record => {
    const result = await appServerCall({ socketPath: manifest.codexSocketPath, threadId: manifest.codexThreadId,
      input: wakePrompt(record, manifest.id), clientUserMessageId: `nvoy:${record.id}`,
      dedupeToken: `NVOY_WAKE_RECORD_ID=${record.id}`, waitForCompletion: false,
      steerActive: true, timeoutMs: 30_000 })
    return { accepted: Boolean(result?.turnId) }
  }
  const once = process.argv.includes('--once'), circuit = new WakeCircuit()
  let inFlight = null
  const tick = () => {
    if (inFlight) return inFlight
    inFlight = (async () => {
      try { const result = await runWakeCycle({ spoolPath, cursorPath, dispatch, circuit }); if (result.accepted || result.held) console.log(JSON.stringify({ instance: manifest.id, ...result })) }
      catch (error) { console.error(`codex-wake-adapter: cycle failed — ${error.message}`); if (once) process.exitCode = 1 }
      finally { inFlight = null }
    })()
    return inFlight
  }
  await tick(); if (!once) setInterval(() => { void tick() }, 1000)
}

if (import.meta.url === `file://${process.argv[1]}`) await main()
