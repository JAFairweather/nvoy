// Bounded followers for the append-only JSONL files a keyless wake source reads: the admitted queue
// and the Claude channel's read log. Each read returns only the complete lines appended since the
// last one. A file that shrank was rewritten, so the follower starts again from its head and says so;
// the caller decides how to re-place itself. A record over its bound is dropped whole.

import { closeSync, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { StringDecoder } from 'node:string_decoder'

export const HEX64 = /^[0-9a-f]{64}$/
const MAX_RECORD = 1024 * 1024, MAX_FILE = 64 * 1024 * 1024

export function lineFollower(path, label) {
  let offset = 0, partial = '', skipping = false, decoder = new StringDecoder('utf8')
  return function read() {
    let st
    try { st = lstatSync(path) } catch { return { lines: [], reset: false } }
    if (!st.isFile() || st.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`)
    if (st.size > MAX_FILE) throw new Error(`${label} exceeds its 64 MiB bound`)
    const reset = st.size < offset
    if (reset) { offset = 0; partial = ''; skipping = false; decoder = new StringDecoder('utf8') }
    if (st.size === offset) return { lines: [], reset }
    const fd = openSync(path, 'r'), lines = []
    try {
      const size = Math.min(fstatSync(fd).size, MAX_FILE), chunk = Buffer.alloc(Math.min(size - offset, MAX_RECORD))
      while (offset < size) {
        const n = readSync(fd, chunk, 0, Math.min(chunk.length, size - offset), offset)
        if (n <= 0) break
        offset += n
        const parts = (partial + decoder.write(chunk.subarray(0, n))).split('\n')
        partial = parts.pop()
        for (const line of parts) {
          if (skipping) { skipping = false; continue }
          if (line.trim() && Buffer.byteLength(line) <= MAX_RECORD) lines.push(line)
        }
        // A record over its bound is dropped whole, not split into lines that might parse.
        if (Buffer.byteLength(partial) > MAX_RECORD) { partial = ''; skipping = true }
      }
    } finally { closeSync(fd) }
    return { lines, reset }
  }
}

// Metadata only, built fresh: whatever else a queue line carries never leaves this function.
export function admittedMeta(line) {
  let row
  try { row = JSON.parse(line) } catch { return null }
  const envelope = String(row?.envelope || '')
  if (!HEX64.test(envelope)) return null
  const at = Number(row.received_at)
  return { envelope, type: row.type === 'verified-notification' ? 'verified-notification' : 'admitted-task', at: Number.isFinite(at) ? at : null }
}

export function admittedFollower(path) {
  const read = lineFollower(path, 'admitted queue')
  return () => { const { lines, reset } = read(); return { rows: lines.map(admittedMeta).filter(Boolean), reset } }
}
