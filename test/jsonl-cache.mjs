// The Claude channel's incremental reader for its append-only admitted queue and read log
// (jsonl_cache.mjs). Before, every 1 s poll re-read and re-parsed both whole files, so a seat's CPU
// cost grew with every envelope it had ever received (nvoy-fleet, 15 Nov 2026). The cache must parse
// each line once and still fail closed exactly as a full re-read would.
import assert from 'node:assert/strict'
import { appendFileSync, mkdtempSync, renameSync, rmSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { jsonlCache } from '../mcp/tools/jsonl_cache.mjs'

const dir = mkdtempSync(join(tmpdir(), 'jsonl-cache-'))
const file = join(dir, 'q.jsonl')
let parsed = 0
const parse = line => { parsed++; const r = JSON.parse(line); if (r.bad) throw new Error('invalid record'); return r.n }

// Missing: a required file throws, an optional one reads as empty.
assert.throws(() => jsonlCache(file, 'queue', { parse })(), /queue is missing/)
assert.deepEqual(jsonlCache(file, 'queue', { parse, required: false })(), [])

// Incremental: each line is parsed once, however many polls run.
writeFileSync(file, '{"n":1}\n{"n":2}\n')
const read = jsonlCache(file, 'queue', { parse })
assert.deepEqual(read(), [1, 2])
assert.equal(parsed, 2)
for (let i = 0; i < 50; i++) assert.deepEqual(read(), [1, 2])
assert.equal(parsed, 2, 'unchanged polls parse nothing')
appendFileSync(file, '{"n":3}\n')
assert.deepEqual(read(), [1, 2, 3])
assert.equal(parsed, 3, 'an append parses only the new line')

// Returned arrays are copies: a caller cannot change what the next poll sees.
read().push(99)
assert.deepEqual(read(), [1, 2, 3])

// Blank lines are skipped, as filter(Boolean) did; an unterminated tail waits for its newline.
appendFileSync(file, '\n{"n":4')
assert.deepEqual(read(), [1, 2, 3], 'a half-written line is held back, not reported as malformed')
appendFileSync(file, '}\n')
assert.deepEqual(read(), [1, 2, 3, 4])

// Multi-byte text split across reads decodes intact.
appendFileSync(file, JSON.stringify({ n: 5, s: 'é'.repeat(700000) }) + '\n')
assert.deepEqual(read(), [1, 2, 3, 4, 5])

// Fail closed: a rejected line throws now and on every later poll, like a full re-read would.
appendFileSync(file, '{"bad":true}\n')
assert.throws(() => read(), /invalid record/)
appendFileSync(file, '{"n":6}\n')
assert.throws(() => read(), /invalid record/, 'a later valid line does not clear the failure')
assert.throws(() => read(), /invalid record/)
// Malformed JSON fails the same way.
writeFileSync(join(dir, 'm.jsonl'), '{"n":1}\nnot json\n')
const malformed = jsonlCache(join(dir, 'm.jsonl'), 'queue', { parse })
assert.throws(() => malformed(), SyntaxError)
assert.throws(() => malformed(), SyntaxError)

// A replaced file (new inode) is read again from its head, which also clears a failure.
writeFileSync(join(dir, 'next'), '{"n":10}\n')
renameSync(join(dir, 'next'), file)
assert.deepEqual(read(), [10])
// A file that shrank in place is read again from its head.
writeFileSync(file, '{"n":10}\n{"n":11}\n{"n":12}\n')
assert.deepEqual(read(), [10, 11, 12])
writeFileSync(file, '{"n":20}\n')
assert.deepEqual(read(), [20])

// Shape and bounds: symlinks, non-files and oversized files are refused.
symlinkSync(file, join(dir, 'link.jsonl'))
assert.throws(() => jsonlCache(join(dir, 'link.jsonl'), 'queue', { parse })(), /regular non-symlink/)
assert.throws(() => jsonlCache(dir, 'queue', { parse })(), /regular non-symlink/)
writeFileSync(join(dir, 'big.jsonl'), '{"n":1}\n'.repeat(200))
assert.throws(() => jsonlCache(join(dir, 'big.jsonl'), 'queue', { parse, maxBytes: 1000 })(), /exceeds its/)
// A file that disappears reads as missing again.
rmSync(file)
assert.throws(() => read(), /queue is missing/)

// The channel uses the cache for both polled files, not a whole-file re-read.
const channel = readFileSync(new URL('../mcp/tools/claude-channel.mjs', import.meta.url), 'utf8')
assert.match(channel, /jsonlCache\(queuePath, 'admitted queue'/)
assert.match(channel, /jsonlCache\(readPath, 'Claude channel read log'/)

rmSync(dir, { recursive: true, force: true })
console.log('jsonl-cache: ok')
