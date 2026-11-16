// Incremental views of the four append-only logs the Codex app-server adapter polls.
// Preserve its old tolerance for malformed complete lines, while refusing files that are
// non-regular, symlinks or over the same 64 MiB bound as the Claude channel queue.
import { jsonlCache } from './jsonl_cache.mjs'

const SKIP = Symbol('malformed Codex adapter log line')

export function codexAdapterRecords(paths, { parse = JSON.parse, maxBytes = 64 * 1024 * 1024 } = {}) {
  const readers = new Map(Object.entries(paths).map(([name, path]) => [name,
    jsonlCache(path, `Codex adapter ${name} log`, {
      required: false,
      maxBytes,
      parse: line => { try { return parse(line) } catch { return SKIP } },
    })]))
  return name => {
    const read = readers.get(name)
    if (!read) throw new Error(`unknown Codex adapter log: ${name}`)
    return read().filter(row => row !== SKIP)
  }
}
