import assert from 'node:assert/strict'
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { codexAdapterRecords } from '../mcp/tools/codex_adapter_records.mjs'

const root = mkdtempSync(join(tmpdir(), 'nvoy-codex-adapter-cache-'))
try {
  const paths = Object.fromEntries(['admitted', 'baseline', 'delivered', 'replies'].map(name => [name, join(root, `${name}.jsonl`)]))
  let parsed = 0
  const records = codexAdapterRecords(paths, { maxBytes: 128, parse: line => { parsed++; return JSON.parse(line) } })
  assert.deepEqual(records('admitted'), [], 'a missing optional log starts empty')
  for (const [name, path] of Object.entries(paths)) writeFileSync(path, JSON.stringify({ name, n: 1 }) + '\n')
  for (const name of Object.keys(paths)) assert.deepEqual(records(name), [{ name, n: 1 }])
  assert.equal(parsed, 4)
  for (let poll = 0; poll < 50; poll++) for (const name of Object.keys(paths)) records(name)
  assert.equal(parsed, 4, 'unchanged adapter logs are not parsed again on each poll')

  appendFileSync(paths.admitted, '{"name":"admitted","n":2}\n')
  assert.deepEqual(records('admitted'), [{ name: 'admitted', n: 1 }, { name: 'admitted', n: 2 }])
  assert.equal(parsed, 5, 'only the appended record is parsed')

  appendFileSync(paths.delivered, 'x'.repeat(200))
  assert.throws(() => records('delivered'), /exceeds its/, 'an oversized log is refused before returning cached records')
  assert.equal(parsed, 5, 'the oversized append is not parsed')
  assert.throws(() => records('delivered'), /exceeds its/, 'an unchanged oversized log stays refused')
} finally {
  rmSync(root, { recursive: true, force: true })
}
console.log('codex-adapter-log-cache: ok')
