import { spawn, spawnSync } from 'node:child_process'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import WebSocket from 'ws'
import { startWsRelay } from './wsrelay.mjs'

let pass = 0, fail = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? pass++ : fail++ }
const sk = generateSecretKey(), pk = getPublicKey(sk), nsec = nip19.nsecEncode(sk)
const MINE = nip19.npubEncode(pk)
const run = expected => spawnSync(process.execPath, ['mcp/tools/relay-send.mjs'], {
  encoding: 'utf8', input: 'identity-bound dry run', env: { ...process.env, NVOY_NSEC: nsec, EXPECT_PUBKEY: expected, DRY_RUN: '1' },
})
const match = run(MINE)
ok('relay send accepts the explicitly expected signer identity', match.status === 0 && /DRY_RUN/.test(match.stderr))
const mismatch = run('f'.repeat(64))
ok('relay send refuses a valid credential that resolves to another identity', mismatch.status !== 0 && /signer identity mismatch/.test(mismatch.stderr) && !/sealed wrap/.test(mismatch.stderr))
const malformed = run('npub1not-valid')
ok('relay send fails closed on a malformed expected identity', malformed.status !== 0 && /EXPECT_PUBKEY must/.test(malformed.stderr))

// ---- #382: the identity is named on SUCCESS, not only when it is wrong --------------------------
//
// Asserting only the refusal cannot tell "names the identity" from "names it when it disagrees",
// which is the state this fixed: the operator learned their own key by getting it wrong.
ok('success names the resolved signer identity', match.stderr.includes(`signing as ${MINE}`))
ok('  …and says the identity was CHECKED when EXPECT_PUBKEY is set', /matches EXPECT_PUBKEY/.test(match.stderr))

const unchecked = spawnSync(process.execPath, ['mcp/tools/relay-send.mjs'], {
  encoding: 'utf8', input: 'unchecked identity', env: { ...process.env, NVOY_NSEC: nsec, DRY_RUN: '1', EXPECT_PUBKEY: '' },
})
ok('with no EXPECT_PUBKEY the key is still named', unchecked.status === 0 && unchecked.stderr.includes(`signing as ${MINE}`))
ok('  …and is marked NOT verified — naming a key is not the same as checking it',
  /identity NOT verified/.test(unchecked.stderr) && !/matches EXPECT_PUBKEY/.test(unchecked.stderr))

// The mismatch message is what an operator acts on, so assert the REASON carries both keys and
// not merely that it refused.
ok('the mismatch refusal names both the resolved and the expected key',
  mismatch.stderr.includes(MINE) && mismatch.stderr.includes(nip19.npubEncode('f'.repeat(64))))

// ---- #182: the full event id, and the cold read-back it makes possible --------------------------
ok('DRY_RUN publishes nothing, so it prints no event id on stdout', match.stdout.trim() === '')

// Spawned ASYNCHRONOUSLY, unlike the DRY_RUN cases above. wsrelay runs on this process's event
// loop, so spawnSync here deadlocks: relay-send waits for an OK the relay cannot send until the
// test resumes, and the test cannot resume until relay-send exits. It fails as a 9s timeout and
// "accepted by 0/1" — which reads exactly like a relay that rejected the event.
const runLive = (env, input) => new Promise(res => {
  const p = spawn(process.execPath, ['mcp/tools/relay-send.mjs'], { env: { ...process.env, ...env } })
  let stdout = '', stderr = ''
  p.stdout.on('data', d => stdout += d)
  p.stderr.on('data', d => stderr += d)
  p.on('close', status => res({ status, stdout, stderr }))
  p.stdin.end(input)
})

const relay = await startWsRelay(0)
const live = await runLive({ NVOY_NSEC: nsec, RELAY_RELAYS: relay.url }, 'cold read-back proof')
const printed = live.stdout.trim()
ok('a real send exits 0 against a live relay', live.status === 0)
ok('  …prints the FULL 64-hex event id on stdout, alone', /^[0-9a-f]{64}$/.test(printed))
ok('  …while stderr keeps the readable 12-character summary', /sealed wrap [0-9a-f]{12}…/.test(live.stderr))
ok('  …and no longer offers a relay ack as proof of delivery',
  /ACKNOWLEDGEMENT, not delivery/.test(live.stderr))

// A fresh connection, not the store handle: the rule is that a publish is proven by fetching it
// back from one, and a test that reaches into the relay's memory proves something weaker.
const fetchById = (url, id) => new Promise(res => {
  const found = []
  let ws
  try { ws = new WebSocket(url) } catch { return res(found) }
  const t = setTimeout(() => { try { ws.close() } catch { /* */ } res(found) }, 4000)
  ws.on('open', () => ws.send(JSON.stringify(['REQ', 'rb', { ids: [id] }])))
  ws.on('message', d => {
    try {
      const m = JSON.parse(d.toString())
      if (m[0] === 'EVENT') found.push(m[2])
      if (m[0] === 'EOSE') { clearTimeout(t); ws.close(); res(found) }
    } catch { /* */ }
  })
  ws.on('error', () => { clearTimeout(t); res(found) })
})

const servedBack = await fetchById(relay.url, printed)
ok('  …and that id fetches the wrap back from a FRESH connection — published, not merely acked',
  servedBack.length === 1 && servedBack[0].id === printed && servedBack[0].kind === 1059)

// Negative control. A read-back that has only ever succeeded cannot tell "the relay has it" from
// "this fetch always says yes".
const neverSent = await fetchById(relay.url, 'a'.repeat(64))
ok('  …negative control: a well-formed id that was never published comes back empty', neverSent.length === 0)

await relay.close()

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
