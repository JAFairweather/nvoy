// Per-seat read log for hive-memory (nvoy #390): which records each reader seat was shown, so a later evaluation can
// count how many target claims overlap an author's or labeler's reads instead of taking their word for it.
//
// One JSON line per read on a reader socket: { at, seat, op, n, d, truncated }.
//   at         unix seconds
//   seat       the reader socket name the daemon bound the connection to (never a client-supplied name)
//   op         'wake' | 'query' | 'get' (a query that names one fact key)
//   n          how many records the reply carried (a record whose key could not be resolved counts here but is not in d)
//   d          the fact keys of those records (the d-keys the issue asks for), at most MAX_KEYS
//   truncated  true when the reply carried more records than MAX_KEYS
// Never logged: claim text, because, evidence, the query's text, linked_to, author or any filter value. The reader's
// own ACL has already been applied, so the log holds only what the seat could actually see.
//
// The file is append-only for the daemon (mode 0640: the service user and its group read it; nobody else). Retention is
// a day limit plus a size cap, applied at start and then at most once an hour by an atomic rewrite that keeps the mode.
// A failed append never fails the read: the miss is counted, the first of each run is logged, and `failures` is exposed
// so a gap in the log is visible instead of silent.
import { chmodSync, closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { dirname } from 'node:path'

export const READ_LOG_MAX_KEYS = 500
export const READ_LOG_DEFAULT_DAYS = 30
export const READ_LOG_DEFAULT_MAX_BYTES = 64 * 1024 * 1024
const PRUNE_EVERY_SEC = 3600
const OPS = new Set(['wake', 'query', 'get'])
const SCAN_BYTES = 64 * 1024
// Entries written by record() are small. A larger line cannot be parsed without holding it all in memory;
// treat it as a damaged line, as we do for invalid JSON.
const MAX_LINE_BYTES = 1024 * 1024

function scanLines(fd, size, visit) {
  const chunk = Buffer.allocUnsafe(SCAN_BYTES)
  let pending = Buffer.alloc(0)
  let oversized = false
  let position = 0
  while (position < size) {
    const n = readSync(fd, chunk, 0, Math.min(chunk.length, size - position), position)
    if (!n) throw new Error('read log changed during prune')
    position += n
    let start = 0
    for (let i = 0; i < n; i++) {
      if (chunk[i] !== 10) continue
      const part = chunk.subarray(start, i)
      visit(oversized || pending.length + part.length > MAX_LINE_BYTES ? null
        : pending.length ? Buffer.concat([pending, part]) : part)
      pending = Buffer.alloc(0)
      oversized = false
      start = i + 1
    }
    const part = chunk.subarray(start, n)
    if (!oversized && part.length) {
      if (pending.length + part.length > MAX_LINE_BYTES) {
        pending = Buffer.alloc(0)
        oversized = true
      } else {
        pending = pending.length ? Buffer.concat([pending, part]) : Buffer.from(part)
      }
    }
  }
  if (pending.length || oversized) visit(oversized ? null : pending)
}

function retainedLine(line, cutoff) {
  if (!line?.length) return null
  const text = line.toString('utf8')
  try {
    if (!(Number(JSON.parse(text).at) >= cutoff)) return null
  } catch { return null } // an unparseable line is damage, not evidence
  return { text, bytes: Buffer.byteLength(text) + 1 }
}

function writeAll(fd, text) {
  const bytes = Buffer.from(`${text}\n`)
  for (let offset = 0; offset < bytes.length;) offset += writeSync(fd, bytes, offset, bytes.length - offset)
}

export class ReadLog {
  constructor({ path, retentionDays = READ_LOG_DEFAULT_DAYS, maxBytes = READ_LOG_DEFAULT_MAX_BYTES, now = () => Math.floor(Date.now() / 1000), log = () => {} } = {}) {
    if (!path || typeof path !== 'string') throw new Error('read log needs a path')
    if (!Number.isFinite(retentionDays) || retentionDays <= 0) throw new Error('read log retention must be a positive number of days')
    if (!Number.isInteger(maxBytes) || maxBytes < 4096) throw new Error('read log size cap must be at least 4096 bytes')
    this.path = path
    this.retentionDays = retentionDays
    this.maxBytes = maxBytes
    this.now = now
    this.log = log
    this.failures = 0
    this.lastPrune = 0
    mkdirSync(dirname(path), { recursive: true, mode: 0o750 })
    this.#ensureRegular(true)
    chmodSync(path, 0o640)
    this.prune()
  }

  // The log must be a plain file this process made or already owns: a symlink (or anything else) planted at the path is refused,
  // never followed, so the daemon cannot be steered into appending to or truncating another file. `create` makes a missing file.
  #ensureRegular(create) {
    let st = null
    try { st = lstatSync(this.path) } catch (e) { if (e.code !== 'ENOENT') throw e }
    if (!st) {
      if (!create) throw new Error('read log file is missing')
      closeSync(openSync(this.path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o640))
      return
    }
    if (!st.isFile() || st.isSymbolicLink()) throw new Error('read log path is not a regular file')
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw new Error('read log file is not owned by this service')
  }

  // Appends one entry; returns true when written. Never throws.
  record({ seat, op, keys = [], count = null }) {
    try {
      if (!OPS.has(op) || typeof seat !== 'string' || !seat) throw new Error('bad read log entry')
      const all = (Array.isArray(keys) ? keys : []).filter(k => typeof k === 'string' && k)
      const at = this.now()
      const entry = { at, seat, op, n: Number.isSafeInteger(count) && count >= all.length ? count : all.length, d: all.slice(0, READ_LOG_MAX_KEYS), truncated: all.length > READ_LOG_MAX_KEYS }
      const line = JSON.stringify(entry)
      if (Buffer.byteLength(line) > MAX_LINE_BYTES) throw new Error('read log entry exceeds line limit')
      this.#ensureRegular(false)
      const fd = openSync(this.path, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW)
      try { writeSync(fd, `${line}\n`) } finally { closeSync(fd) }
      if (at - this.lastPrune >= PRUNE_EVERY_SEC) this.prune()
      return true
    } catch (e) {
      this.failures += 1
      if (this.failures === 1) this.log(`hive-memory: read log append failed (${e.code || e.message}); reads continue, gaps are counted`)
      return false
    }
  }

  // Drops lines older than the retention window, then oldest lines until the file fits the size cap (to 80%).
  prune() {
    const nowSec = this.now()
    this.lastPrune = nowSec
    let tmp = null
    let source = null
    try {
      this.#ensureRegular(false)
      const cutoff = nowSec - Math.floor(this.retentionDays * 86400)
      source = openSync(this.path, constants.O_RDONLY | constants.O_NOFOLLOW)
      const initial = fstatSync(source)
      if (!initial.isFile() || (typeof process.getuid === 'function' && initial.uid !== process.getuid())) {
        throw new Error('read log file is not owned by this service')
      }
      let bytes = 0
      let changed = false
      scanLines(source, initial.size, line => {
        const kept = retainedLine(line, cutoff)
        if (kept) {
          bytes += kept.bytes
          if (kept.bytes !== line.length + 1) changed = true
        } else changed = true
      })
      if (!changed && bytes === initial.size && bytes <= this.maxBytes) return false
      let dropBytes = bytes > this.maxBytes ? bytes - Math.floor(this.maxBytes * 0.8) : 0
      // An unpredictable name made with O_EXCL: an existing file or symlink of any name is never opened, so nothing planted
      // beside the log can be followed or truncated. The data is synced, renamed over the log, and the directory synced so the
      // rename itself survives a crash.
      tmp = `${this.path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`
      const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o640)
      try {
        scanLines(source, initial.size, line => {
          const kept = retainedLine(line, cutoff)
          if (!kept) return
          if (dropBytes > 0) { dropBytes -= kept.bytes; return }
          writeAll(fd, kept.text)
        })
        fsyncSync(fd)
      } finally { closeSync(fd) }
      const current = lstatSync(this.path)
      const after = fstatSync(source)
      if (current.ino !== initial.ino || current.dev !== initial.dev || after.size !== initial.size || after.mtimeMs !== initial.mtimeMs) {
        throw new Error('read log changed during prune')
      }
      chmodSync(tmp, 0o640)
      renameSync(tmp, this.path)
      tmp = null
      const dfd = openSync(dirname(this.path), constants.O_RDONLY)
      try { fsyncSync(dfd) } finally { closeSync(dfd) }
      return true
    } catch (e) {
      if (tmp) { try { unlinkSync(tmp) } catch { /* nothing to clean */ } }
      this.failures += 1
      this.log(`hive-memory: read log prune failed (${e.code || e.message}); the log is left as it was`)
      return false
    } finally {
      if (source !== null) closeSync(source)
    }
  }
}
