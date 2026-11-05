// mcp-reconnect --wake-herdr: a channel's wake markers typed into an agent's herdr pane, for a client
// (agy) that does not act on them itself. A fake channel server sends markers on request; a fake
// herdr answers `agent list` from a state file and logs what is typed.
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { herdrWaker, wakeLine, wakeOf } from '../mcp/tools/herdr_wake.mjs'
import { herdrClient } from '../mcp/tools/harness_herdr.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const E1 = 'a'.repeat(64), E2 = 'b'.repeat(64)
const marker = meta => ({ jsonrpc: '2.0', method: 'notifications/claude/channel', params: { content: 'x', meta } })

ok('a marker with a 64-hex envelope is a wake', wakeOf(marker({ envelope: E1 }))?.envelope === E1)
ok('a malformed envelope is no wake', wakeOf(marker({ envelope: 'A'.repeat(64) })) === null && wakeOf(marker({ envelope: `${E1}\n` })) === null)
ok('a capabilities marker is a wake', wakeOf(marker({ capabilities: 'h' }))?.capabilities === true)
ok('another method is no wake', wakeOf({ method: 'notifications/message', params: { meta: { envelope: E1 } } }) === null)
const line = wakeLine({ envelopes: [E1], capabilities: false })
ok('the typed line names the envelope and the read tool, and holds no control character',
  line.includes(E1) && line.includes('nvoy_channel_read') && !/[\x00-\x1f\x7f]/.test(line))

// In process, with a herdr object whose Enter can be made to fail.
const wait = ms => new Promise(done => setTimeout(done, ms))
const fakeClient = () => {
  const calls = []
  let enterFails = 0, status = 'idle'
  return { calls, failEnter(n) { enterFails = n }, setStatus(s) { status = s },
    agentNamed: name => name === 'biggy' ? { name, pane_id: 'w9:p1', agent_status: status } : null,
    text: (pane, text) => calls.push(['text', pane, text]),
    keys: (pane, key) => { if (enterFails > 0) { enterFails -= 1; throw new Error('send-keys failed') } calls.push(['keys', pane, key]) } }
}
{
  const herdr = fakeClient(), waker = herdrWaker({ agent: 'biggy', herdr, everyMs: 50, settleMs: 100 })
  waker.notice(marker({ envelope: E1 }))
  await wait(25)
  waker.notice(marker({ envelope: E2 }))
  waker.notice(marker({ capabilities: 'h2' }))
  await wait(400)
  const texts = herdr.calls.filter(c => c[0] === 'text').map(c => c[2])
  ok('an envelope arriving during the settle wait is typed in the next batch, not lost', texts.length === 2 && texts[0].includes(E1) && !texts[0].includes(E2) && texts[1].includes(E2))
  ok('a capabilities change arriving during the settle wait is kept too', texts[1]?.includes('capabilities changed'))
  waker.notice(marker({ envelope: E2 }))
  await wait(200)
  ok('a repeated marker for a submitted envelope is not typed again', herdr.calls.filter(c => c[0] === 'text').length === 2)
  waker.stop()
}
{
  const herdr = fakeClient(), waker = herdrWaker({ agent: 'biggy', herdr, everyMs: 50, settleMs: 10 })
  herdr.failEnter(2)
  waker.notice(marker({ envelope: E1 }))
  await wait(60)
  waker.notice(marker({ envelope: E2 }))
  await wait(400)
  const kinds = herdr.calls.map(c => `${c[0]}:${c[2].includes(E1) ? 'E1' : ''}${c[2].includes(E2) ? 'E2' : ''}`)
  ok('a failed Enter is retried without typing the line again', kinds[0] === 'text:E1' && kinds[1] === 'keys:')
  ok('an envelope that arrived while Enter was failing goes in its own batch afterwards', kinds[2] === 'text:E2' && kinds[3] === 'keys:' && kinds.length === 4)
  waker.stop()
}

{
  const herdr = fakeClient(), waker = herdrWaker({ agent: 'biggy', herdr, everyMs: 50, settleMs: 10 })
  const ids = Array.from({ length: 65 }, (_, i) => i.toString(16).padStart(64, '0'))
  herdr.setStatus('working')
  for (const id of ids) waker.notice(marker({ envelope: id }))
  herdr.setStatus('idle')
  await wait(200)
  const first = herdr.calls.filter(c => c[0] === 'text').map(c => c[2])
  ok('at capacity + 1, one line names the newest 64 and asks for nvoy_channel_list to find the rest',
    first.length === 1 && !first[0].includes(ids[0]) && ids.slice(1).every(id => first[0].includes(id)) && first[0].includes('Call nvoy_channel_list to find the rest'))
  waker.notice(marker({ envelope: ids[0] }))
  waker.notice(marker({ envelope: ids[1] }))
  await wait(200)
  const after = herdr.calls.filter(c => c[0] === 'text').map(c => c[2])
  ok('a reannounced envelope dropped from the full queue is woken for; a submitted one is not', after.length === 2 && after[1].includes(ids[0]) && !after[1].includes(ids[1]) && !after[1].includes('find the rest'))
  waker.stop()
}
const dir = mkdtempSync(join(tmpdir(), 'nvoy-herdrwake-'))
const state = join(dir, 'herdr.json'), typed = join(dir, 'typed.jsonl')
const setAgent = status => writeFileSync(state, JSON.stringify({ agents: [{ name: 'biggy', agent: 'agy', pane_id: 'w9:p1', agent_status: status }] }))
const herdr = join(dir, 'herdr')
writeFileSync(herdr, `#!/usr/bin/env node
const { appendFileSync, readFileSync } = require('node:fs')
const [noun, verb, ...rest] = process.argv.slice(2)
if (noun === 'agent' && verb === 'list') console.log(JSON.stringify({ result: JSON.parse(readFileSync(${JSON.stringify(state)}, 'utf8')) }))
else if (noun === 'pane' && (verb === 'send-text' || verb === 'send-keys')) { appendFileSync(${JSON.stringify(typed)}, JSON.stringify([verb, ...rest]) + '\\n'); console.log('{"result":{}}') }
else { console.error('unexpected ' + noun + ' ' + verb); process.exit(1) }
`)
chmodSync(herdr, 0o755)
{
  const failing = join(dir, 'herdr-fails')
  writeFileSync(failing, `#!/bin/sh
if [ "$2" = "send-keys" ]; then echo "no such pane" >&2; exit 1; fi
if [ "$2" = "send-text" ]; then echo '{"result":{}}'; exit 0; fi
echo '{"result":{"agents":[]}}'
`)
  chmodSync(failing, 0o755)
  const client = herdrClient({ bin: failing })
  let threw = null
  try { client.keys('w9:p1', 'Enter') } catch (error) { threw = error.message }
  ok('a send-keys that exits 1 with only stderr is a failure, not a key sent', /failed: no such pane/.test(threw || ''))
  let fine = true
  try { client.text('w9:p1', 'x'); client.agentNamed('biggy') } catch { fine = false }
  ok('herdr calls that exit 0 still succeed', fine)
}
const server = join(dir, 'server.mjs')
writeFileSync(server, `
import { createInterface } from 'node:readline'
createInterface({ input: process.stdin }).on('line', line => {
  const m = JSON.parse(line)
  const out = x => process.stdout.write(JSON.stringify(x) + '\\n')
  if (m.method === 'initialize') out({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: m.params.protocolVersion, serverInfo: { name: 'fake', version: '1' }, capabilities: {} } })
  else if (m.method === 'test/mark') { for (const meta of m.params.metas) out({ jsonrpc: '2.0', method: 'notifications/claude/channel', params: { content: '\\u001b[31m rm -rf ~', meta } }); out({ jsonrpc: '2.0', id: m.id, result: {} }) }
})
`)

setAgent('working')
const proxy = spawn(process.execPath, [resolve('mcp/tools/mcp-reconnect.mjs'), '--wake-herdr', 'biggy', '--wake-every-ms', '100', '--', process.execPath, server],
  { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, HARNESS_HERDR_BIN: herdr } })
let stderr = ''
proxy.stderr.on('data', d => { stderr += d })
const inbox = []
createInterface({ input: proxy.stdout }).on('line', l => inbox.push(JSON.parse(l)))
const send = m => proxy.stdin.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n')
const pause = ms => new Promise(done => setTimeout(done, ms))
const rows = () => existsSync(typed) ? readFileSync(typed, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)) : []

send({ id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } })
await pause(300)
send({ id: 2, method: 'test/mark', params: { metas: [{ envelope: E1 }, { envelope: E1 }, { envelope: 'not-an-envelope' }, { envelope: E2 }] } })
await pause(700)
ok('the markers still reach the client', inbox.filter(m => m.method === 'notifications/claude/channel').length === 4)
ok('nothing is typed while the agent is working', rows().length === 0)

setAgent('idle')
await pause(1200)
const sent = rows()
ok('once idle, one line is typed, then Enter', sent.length === 2 && sent[0][0] === 'send-text' && sent[0][1] === 'w9:p1' && sent[1][0] === 'send-keys' && sent[1][2] === 'Enter')
ok('the line names both envelopes once each, and not the malformed one', sent[0]?.[2].split(E1).length === 2 && sent[0]?.[2].includes(E2) && !sent[0]?.[2].includes('not-an-envelope'))
ok('no server text reaches the terminal', !/rm -rf|\x1b/.test(sent[0]?.[2] || ''))

send({ id: 3, method: 'test/mark', params: { metas: [{ envelope: E1 }] } })
await pause(600)
ok('an envelope already woken for is not typed again', rows().length === 2)

writeFileSync(state, JSON.stringify({ agents: [] }))
send({ id: 4, method: 'test/mark', params: { metas: [{ envelope: 'c'.repeat(64) }] } })
await pause(600)
ok('with no such agent in herdr, the wake is held and said once', rows().length === 2 && (stderr.match(/no agent named biggy/g) || []).length === 1)
setAgent('idle')
await pause(800)
ok('the held wake is typed once the agent is back', rows().length === 4 && rows()[2][2].includes('c'.repeat(64)))

proxy.stdin.end()
ok('closing the client stops the proxy', await Promise.race([new Promise(done => proxy.on('exit', () => done(true))), pause(3000).then(() => false)]))

const bad = spawn(process.execPath, [resolve('mcp/tools/mcp-reconnect.mjs'), '--wake-herdr', 'Bad Name', '--', process.execPath, server], { stdio: ['pipe', 'pipe', 'pipe'] })
ok('a malformed agent name is refused', await new Promise(done => bad.on('exit', code => done(code === 2))))

process.exit(fails ? 1 : 0)
