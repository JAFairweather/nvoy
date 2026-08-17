import assert from 'node:assert/strict'
import { mkdtempSync, appendFileSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { readWakeBatch, runWakeCycle, WakeCircuit, wakePrompt } from '../mcp/tools/codex-wake-adapter.mjs'

const root = mkdtempSync(join(tmpdir(), 'nvoy-wake-adapter-'))
const spool = join(root, 'spool.jsonl'), cursor = join(root, 'cursor.json')
const idA = 'a'.repeat(64), idB = 'b'.repeat(64), idC = 'c'.repeat(64)
const row = (id, wake, extra = {}) => JSON.stringify({ id, wake, content: 'body', ...extra }) + '\n'
appendFileSync(spool, row(idA, false, { mayAct: true }) + row(idB, true, { mayAct: false, receipt: true }) + row(idC, true, { disposition: 'refused' }))

const frames = readWakeBatch(spool, 0)
assert.equal(frames.records.length, 3)
assert.equal(frames.partial, false)
const calls = []
const first = await runWakeCycle({ spoolPath: spool, cursorPath: cursor, dispatch: async record => { calls.push(record); return { accepted: true } } })
assert.equal(first.accepted, 2); assert.equal(first.skipped, 1)
assert.deepEqual(calls.map(x => x.id), [idB, idC])
assert.equal(JSON.parse(readFileSync(cursor, 'utf8')).offset, frames.next)
const replay = await runWakeCycle({ spoolPath: spool, cursorPath: cursor, dispatch: async () => { throw new Error('must not replay') } })
assert.equal(replay.accepted, 0)

const regressedCursor = join(root, 'regressed-cursor.json')
writeFileSync(regressedCursor, JSON.stringify({ version: 1, offset: 999999 }) + '\n')
await assert.rejects(() => runWakeCycle({ spoolPath: spool, cursorPath: regressedCursor, dispatch: async () => { throw new Error('must not dispatch') } }), /beyond .*spool\.jsonl size/)

const failCursor = join(root, 'fail-cursor.json'), failCalls = []
await assert.rejects(() => runWakeCycle({ spoolPath: spool, cursorPath: failCursor, dispatch: async record => { failCalls.push(record.id); throw new Error('app-server unavailable') } }), /app-server unavailable/)
assert.equal(failCalls[0], idB)
assert.equal(JSON.parse(readFileSync(failCursor, 'utf8')).offset, frames.records[0].end)

const circuit = new WakeCircuit({ maxPerWindow: 1, failureLimit: 2, cooldownMs: 1000 })
assert.equal(circuit.allow(0), true); circuit.accepted(0); assert.equal(circuit.allow(1), false)
circuit.failed(2000); circuit.failed(2000); assert.equal(circuit.allow(2001), false)
const prompt = wakePrompt({ id: idB, wake: true, content: 'quoted' }, 'dj-codex')
assert.match(prompt, new RegExp(`NVOY_WAKE_RECORD_ID=${idB}`))
assert.match(prompt, /NVOY_WAKE_RECORD=/)
const source = readFileSync(new URL('../mcp/tools/codex-wake-adapter.mjs', import.meta.url), 'utf8')
assert.match(source, /let inFlight = null/)
assert.match(source, /if \(inFlight\) return inFlight/)
assert.match(source, /finally \{ inFlight = null \}/)
console.log('codex-wake-adapter: all checks passed')
