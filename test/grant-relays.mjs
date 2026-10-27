// One grant relay set (waggle#613 C3). Grants are issued to the console's four relays, and the
// broker's policy read now asks those four as well as the manifest's relays, so a manifest that
// leaves one out can no longer hide a grant or a revocation from its own broker.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { GRANT_RELAYS, grantReadRelays } from '../mcp/tools/grant_relays.mjs'
import { DEFAULT_RELAYS } from '../console/config.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

ok('the console issues grants to exactly the set the broker reads', same(DEFAULT_RELAYS, GRANT_RELAYS))
ok('the set leads with the relays that retain grants', same(GRANT_RELAYS.slice(0, 2), ['wss://relay.nave.pub', 'wss://relay.ditto.pub']))
ok('the module imports nothing, so the console and the bridge can vendor it',
  !/^\s*import\b/m.test(readFileSync('mcp/tools/grant_relays.mjs', 'utf8')))

const fleet = ['wss://nos.lol', 'wss://relay.ditto.pub', 'wss://relay.primal.net']
ok('a fleet manifest that leaves out relay.nave.pub still has its grants read from it',
  same(grantReadRelays(fleet), GRANT_RELAYS))
ok('a relay the manifest adds is read too, after the grant set, once',
  same(grantReadRelays(['wss://relay.ditto.pub', 'wss://extra.example', 'wss://extra.example']), [...GRANT_RELAYS, 'wss://extra.example']))
ok('no relays given still reads the grant set', same(grantReadRelays(), GRANT_RELAYS) && same(grantReadRelays(undefined, ''), GRANT_RELAYS))
ok('a set made only of loopback relays is a local test, and is kept exactly',
  same(grantReadRelays(['ws://127.0.0.1:7000', ' ws://localhost:7001 ', 'ws://[::1]:7002/']), ['ws://127.0.0.1:7000', 'ws://localhost:7001', 'ws://[::1]:7002/']))
ok('one public relay among loopback ones brings the grant set back',
  same(grantReadRelays(['ws://127.0.0.1:7000', 'wss://nos.lol']), [...GRANT_RELAYS, 'ws://127.0.0.1:7000']))
ok('a host that only starts like loopback is not loopback',
  grantReadRelays(['ws://127.0.0.1.evil.example']).includes('wss://relay.nave.pub') && grantReadRelays(['ws://localhost.evil.example:1']).includes('wss://relay.nave.pub'))
ok('an explicit override replaces the set outright', same(grantReadRelays(fleet, 'ws://127.0.0.1:9, wss://b.example ,'), ['ws://127.0.0.1:9', 'wss://b.example']))

// --- attention --policy-only reads the grant set, not only NVOY_RELAYS ---
// NVOY_RELAYS names one relay holding a grant; the override names it plus a second relay holding
// the revocation. Only a read of the full grant set sees both, so the grant must come back revoked.
const root = mkdtempSync(join(tmpdir(), 'nvoy-grant-relays-'))
const grantorSk = generateSecretKey(), grantor = getPublicKey(grantorSk)
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const author = getPublicKey(generateSecretKey())
const now = Math.floor(Date.now() / 1000)
const { scopeHash } = await import('../mcp/tools/grant_fold.mjs')
const salt = 'ab'.repeat(16)
const grant = finalizeEvent({ kind: 440, created_at: now - 60, content: '', tags: [['p', author], ['da-cap', 'task'],
  ['da-scope', scopeHash(agent, salt), salt]] }, grantorSk)
const revocation = finalizeEvent({ kind: 441, created_at: now - 30, content: '', tags: [['e', grant.id]] }, grantorSk)

async function relay(events) {
  const http = createServer((req, res) => { res.writeHead(404); res.end() })
  await new Promise(r => http.listen(0, '127.0.0.1', r))
  const wss = new WebSocketServer({ server: http })
  wss.on('connection', ws => ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] !== 'REQ') return
    for (const ev of events) ws.send(JSON.stringify(['EVENT', m[1], ev]))
    ws.send(JSON.stringify(['EOSE', m[1]]))
  }))
  return { url: `ws://127.0.0.1:${http.address().port}`, close: () => { wss.close(); http.close() } }
}
const holdsGrant = await relay([grant]), holdsRevocation = await relay([grant, revocation])

const policy = env => new Promise(resolve => {
  const child = spawn(process.execPath, ['mcp/tools/attention.mjs', '--policy-only'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: root, NVOY_NSEC: Buffer.from(agentSk).toString('hex'), GRANTORS: grantor, ...env } })
  let out = ''
  child.stdout.on('data', c => { out += c })
  child.on('exit', () => { try { resolve(JSON.parse(out)) } catch { resolve({}) } })
})
const holds = p => (p.grants || []).some(g => g.pubkey === author && g.cap === 'task')

const narrow = await policy({ NVOY_RELAYS: holdsGrant.url })
ok('reading only the relay that missed the revocation sees the grant as live (the hazard)', holds(narrow))
const full = await policy({ NVOY_RELAYS: holdsGrant.url, NVOY_GRANT_RELAYS: `${holdsGrant.url},${holdsRevocation.url}` })
ok('the policy read asks every relay in the grant set and reports each one',
  same((full.relays || []).map(r => r.relay), [holdsGrant.url, holdsRevocation.url]) && full.relaysAnswered === 2)
ok('so a revocation held on another grant relay ends the grant', full.policyUsable === true && !holds(full))
holdsGrant.close(); holdsRevocation.close()

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
