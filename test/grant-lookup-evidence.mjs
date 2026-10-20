// "No grant" is logged with the relays that answered (status S0, fix 2). On 10-19 nos.lol had
// evicted every grant: every relay answered, every answer was empty, and every mention was dropped
// as data only with nothing logged. An all-empty answer from relays that held grants before is
// now marked suspect, and attention reports what each relay returned so the broker can say so.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { grantLookup, noGrantVerdict, readGrantHistory, relayLabel } from '../mcp/tools/grant_evidence.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-grant-evidence-'))

ok('a public relay is labelled by its host', relayLabel('wss://nos.lol') === 'nos.lol' && relayLabel('wss://relay.ditto.pub/') === 'relay.ditto.pub')
ok('an address literal is never printed', relayLabel('wss://10.1.2.3:7777', 1) === 'relay#2' && relayLabel('wss://[::1]:7000', 0) === 'relay#1')
ok('an unparseable relay is labelled by position', relayLabel('not a url', 2) === 'relay#3')

const history = join(root, 'grant-relays.json')
const answer = (nos, ditto, primal = null) => [
  { relay: 'wss://nos.lol', answered: nos !== null, events: nos ?? 0 },
  { relay: 'wss://relay.ditto.pub', answered: ditto !== null, events: ditto ?? 0 },
  { relay: 'wss://relay.primal.net', answered: primal !== null, events: primal ?? 0 }]

let lookup = grantLookup(history, answer(0, 0))
ok('with no history, an all-empty answer is a confident no-grant', !lookup.suspect && noGrantVerdict(lookup).startsWith('no-grant: '))
ok('the verdict names every relay and what it returned', noGrantVerdict(lookup) === 'no-grant: relays nos.lol=0 relay.ditto.pub=0 relay.primal.net=unanswered')
ok('nothing is recorded when no relay held grants', !existsSync(history))

lookup = grantLookup(history, answer(4, 2), { now: 1000 })
ok('a relay that returned grants is not suspect', !lookup.suspect && /nos\.lol=4 relay\.ditto\.pub=2/.test(lookup.summary))
ok('the history records which relays held grants, and nothing else', JSON.stringify(readGrantHistory(history)) === JSON.stringify({ 'nos.lol': 1000, 'relay.ditto.pub': 1000 }) &&
  Object.keys(JSON.parse(readFileSync(history, 'utf8'))).sort().join() === 'relays,version')
ok('the history is private to the broker', (statSync(history).mode & 0o777) === 0o600)
grantLookup(history, answer(4, 2), { now: 1000 + 30 * 60 * 1000 })
ok('a relay that keeps answering is re-noted at most hourly', readGrantHistory(history)['nos.lol'] === 1000)
grantLookup(history, answer(4, 0), { now: 1000 + 61 * 60 * 1000 })
ok('after an hour it is re-noted', readGrantHistory(history)['nos.lol'] === 1000 + 61 * 60 * 1000 && readGrantHistory(history)['relay.ditto.pub'] === 1000)

lookup = grantLookup(history, answer(0, 0, 0))
ok('every relay empty after grants were seen is suspect', lookup.suspect)
ok('the suspect verdict says who held grants before', noGrantVerdict(lookup) ===
  'no-grant-suspect: every relay returned no grant events, but nos.lol, relay.ditto.pub held them before; relays nos.lol=0 relay.ditto.pub=0 relay.primal.net=0')
lookup = grantLookup(history, answer(0, 3))
ok('one relay still holding grants makes the no confident: the author simply has none', !lookup.suspect && noGrantVerdict(lookup).startsWith('no-grant: '))
lookup = grantLookup(history, answer(null, null, null))
ok('no relay answering is not a suspect no: it is no answer, which already requeues', !lookup.suspect)
ok('a malformed answer is summarised, not trusted', grantLookup(history, 'garbage').summary === 'none' &&
  grantLookup(history, [{ relay: 'wss://nos.lol', answered: 'yes', events: -4 }]).summary === 'nos.lol=unanswered')
writeFileSync(history, 'not json')
ok('a corrupt history reads as none rather than failing a delivery', JSON.stringify(readGrantHistory(history)) === '{}')

// --- attention reports what each relay returned ---
const grantorSk = generateSecretKey(), grantor = getPublicKey(grantorSk)
const grants = [1, 2].map(n => finalizeEvent({ kind: 440, created_at: Math.floor(Date.now() / 1000) - n, content: '', tags: [['p', 'a'.repeat(64)]] }, grantorSk))
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const wss = new WebSocketServer({ server: http })
wss.on('connection', ws => ws.on('message', raw => {
  const m = JSON.parse(raw.toString())
  if (m[0] !== 'REQ') return
  for (const ev of grants) ws.send(JSON.stringify(['EVENT', m[1], ev]))
  ws.send(JSON.stringify(['EOSE', m[1]]))
}))
const DEAD = 'ws://127.0.0.1:1'
const policy = await new Promise(resolve => {
  const child = spawn(process.execPath, ['mcp/tools/attention.mjs', '--policy-only'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: root, NVOY_NSEC: Buffer.from(generateSecretKey()).toString('hex'), GRANTORS: grantor, NVOY_RELAYS: `${RELAY},${DEAD}` } })
  let out = ''
  child.stdout.on('data', c => { out += c })
  child.on('exit', () => { try { resolve(JSON.parse(out)) } catch { resolve({}) } })
})
ok('attention --policy-only reports each relay, whether it answered, and how many events it returned',
  JSON.stringify(policy.relays) === JSON.stringify([{ relay: RELAY, answered: true, events: 2 }, { relay: DEAD, answered: false, events: 0 }]))
ok('the per-relay report sits beside the existing verdict, which is unchanged', policy.policyUsable === true && policy.relaysAnswered === 1)
wss.close(); http.close()

// --- wiring: both brokers log the no-grant verdict, with the sender prefix ---
const nativeSrc = readFileSync('mcp/tools/instance-broker-native.mjs', 'utf8'), carrySrc = readFileSync('mcp/tools/instance-broker.mjs', 'utf8')
ok('the native broker consults the relay evidence on every policy answer', /grantLookup\(resolve\(manifest\.stateDir, 'grant-relays\.json'\), policy\.relays\)/.test(nativeSrc))
ok('the native no-grant verdict names the author prefix and the relays', /finish\(`author \$\{mention\.author\.slice\(0, 8\)\} holds no live task grant; heard as data only \[\$\{noGrantVerdict\(lookup\)\}\]`\)/.test(nativeSrc))
ok('the wrapped-mail broker does the same for data-only mail', /grantLookup\(resolve\(manifest\.stateDir, 'grant-relays\.json'\), report\.relays\)/.test(carrySrc) && /heard as data only \[\$\{noGrantVerdict\(lookup\)\}\]/.test(carrySrc))
ok('attention --json carries the per-relay report too', /relaysAnswered, relays: relayAnswers, policyUsable/.test(readFileSync('mcp/tools/attention.mjs', 'utf8')))

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
