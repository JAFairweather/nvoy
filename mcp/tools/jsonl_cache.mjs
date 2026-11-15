// A strict, cached view of an append-only JSONL file. Each call reads only the bytes appended since
// the last call, parses the complete new lines with `parse`, and returns every record parsed so far.
//
// Why: the Claude channel polls its admitted queue and read log every second. Both only ever grow,
// and each admitted record carries its context transcript, so re-reading and re-parsing the whole
// file every poll cost a busy seat 20-40 % of a CPU on nvoy-fleet (15 Nov 2026: about 125 ms of CPU
// per poll at 400 records). A seat's cost then grew with every envelope it had ever received.
//
// It keeps the fail-closed contract of a full re-read:
// - a line that `parse` rejects throws, and keeps throwing on every later call, exactly as a full
//   re-read of the same file would, until the file is replaced (new inode) or shrinks;
// - a file that is replaced or shrank is read again from its head;
// - a missing required file, a non-regular file, a symlink, or a file over its bound throws.
// One deliberate difference: an unterminated last line (a writer mid-append) is held back until its
// newline arrives, instead of failing that poll as malformed. Every writer appends whole lines.

import { closeSync, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { StringDecoder } from 'node:string_decoder'

const CHUNK = 1024 * 1024

// `lstat` is a test seam only: it lets a test present a stale first stat, as a file that grows or is swapped
// between the lstat and the open would.
export function jsonlCache(path, label, { parse, required = true, maxBytes = 64 * 1024 * 1024, lstat = lstatSync } = {}) {
  if (typeof parse !== 'function') throw new Error('jsonlCache needs a parse function')
  let ino = null, dev = null, offset = 0, partial = '', decoder = new StringDecoder('utf8'), items = [], failure = null
  const restart = st => {
    ino = st ? st.ino : null; dev = st ? st.dev : null
    offset = 0; partial = ''; decoder = new StringDecoder('utf8'); items = []; failure = null
  }
  return function read() {
    let st
    try { st = lstat(path) } catch (error) {
      if (error.code !== 'ENOENT') throw error
      restart(null)
      if (required) throw new Error(`${label} is missing`)
      return []
    }
    if (!st.isFile() || st.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`)
    if (st.size > maxBytes) throw new Error(`${label} exceeds its ${Math.round(maxBytes / 1024 / 1024)} MiB bound`)
    if (st.ino !== ino || st.dev !== dev || st.size < offset) restart(st)
    if (failure) throw failure
    if (st.size > offset) {
      const fd = openSync(path, 'r')
      try {
        const opened = fstatSync(fd)
        // The path was swapped between the lstat and the open: start again on the next call.
        if (opened.ino !== ino || opened.dev !== dev) { restart(null); throw new Error(`${label} changed while it was being read`) }
        // The bound and the file type are checked again on the file that was actually opened. It may have grown past
        // the bound since the lstat; reading only a prefix of it would return records from an oversized file for
        // this poll (My Dude, PR 407 lead read). Refuse before parsing anything.
        if (!opened.isFile()) throw new Error(`${label} must be a regular non-symlink file`)
        if (opened.size > maxBytes) throw new Error(`${label} exceeds its ${Math.round(maxBytes / 1024 / 1024)} MiB bound`)
        const size = opened.size, chunk = Buffer.alloc(Math.min(CHUNK, Math.max(1, size - offset)))
        while (offset < size) {
          const n = readSync(fd, chunk, 0, Math.min(chunk.length, size - offset), offset)
          if (n <= 0) break
          offset += n
          const parts = (partial + decoder.write(chunk.subarray(0, n))).split('\n')
          partial = parts.pop()
          for (const line of parts) {
            if (!line) continue
            try { items.push(parse(line)) } catch (error) { failure = error; throw error }
          }
        }
      } finally { closeSync(fd) }
    }
    return items.slice()
  }
}
