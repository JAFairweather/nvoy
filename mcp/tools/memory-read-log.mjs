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
import { appendFileSync, chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from 'node:fs'
import { dirname } from 'node:path'

export const READ_LOG_MAX_KEYS = 500
export const READ_LOG_DEFAULT_DAYS = 30
export const READ_LOG_DEFAULT_MAX_BYTES = 64 * 1024 * 1024
const PRUNE_EVERY_SEC = 3600
const OPS = new Set(['wake', 'query', 'get'])

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
    if (!existsSync(path)) closeSync(openSync(path, 'a', 0o640))
    chmodSync(path, 0o640)
    this.prune()
  }

  // Appends one entry; returns true when written. Never throws.
  record({ seat, op, keys = [], count = null }) {
    try {
      if (!OPS.has(op) || typeof seat !== 'string' || !seat) throw new Error('bad read log entry')
      const all = (Array.isArray(keys) ? keys : []).filter(k => typeof k === 'string' && k)
      const at = this.now()
      const entry = { at, seat, op, n: Number.isSafeInteger(count) && count >= all.length ? count : all.length, d: all.slice(0, READ_LOG_MAX_KEYS), truncated: all.length > READ_LOG_MAX_KEYS }
      appendFileSync(this.path, `${JSON.stringify(entry)}\n`, { mode: 0o640 })
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
    try {
      const size = statSync(this.path).size
      const cutoff = nowSec - Math.floor(this.retentionDays * 86400)
      const raw = size ? readFileSync(this.path, 'utf8') : ''
      let lines = raw ? raw.split('\n').filter(Boolean) : []
      const keep = lines.filter(l => {
        try { return Number(JSON.parse(l).at) >= cutoff } catch { return false }   // an unparseable line is damage, not evidence
      })
      lines = keep
      let bytes = lines.reduce((n, l) => n + Buffer.byteLength(l) + 1, 0)
      if (bytes > this.maxBytes) {
        const target = Math.floor(this.maxBytes * 0.8)
        while (lines.length && bytes > target) bytes -= Buffer.byteLength(lines.shift()) + 1
      }
      if (lines.length === raw.split('\n').filter(Boolean).length && bytes === Buffer.byteLength(raw)) return false
      const tmp = `${this.path}.tmp-${process.pid}`
      const fd = openSync(tmp, 'w', 0o640)
      try {
        writeSync(fd, lines.length ? `${lines.join('\n')}\n` : '')
        fsyncSync(fd)
      } finally { closeSync(fd) }
      chmodSync(tmp, 0o640)
      renameSync(tmp, this.path)
      return true
    } catch (e) {
      this.failures += 1
      this.log(`hive-memory: read log prune failed (${e.code || e.message}); the log is left as it was`)
      return false
    }
  }
}
