// #166 — pair a staged identity by nostrconnect, and seat its credential files, with no bunker://
// secret copied anywhere. Drives the real nave-connect handshake and the broker's real NIP-46 client
// against an in-memory Bunker, so "seated" is proven by the broker signing with what was written.
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, statSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, nip19, nip44, verifyEvent } from 'nostr-tools'
import { nostrConnectSigner } from '../lib/nave-connect.mjs'
import { makeBunkerSigner } from '../mcp/tools/nip46-signer.mjs'
import { pairInstance, brokerPerms, bunkerPointer, BROKER_SIGN_KINDS } from '../mcp/tools/instance-pair.mjs'

let failed = 0
const check = (name, ok) => { console.log(ok ? '  ok' : 'FAIL', name); if (!ok) failed++ }
const rejects = async (p, re) => { try { await p; return false } catch (e) { return re.test(e.message) } }

// An in-memory relay with a Bunker on it. `user` is the key the Bunker signs as; `bunker` is its own
// transport key. `approve(uri)` is the owner pressing Approve on a nostrconnect link.
function hive({ user, refuseSign = false, signAs = null }) {
  const bunker = generateSecretKey(), bunkerPub = getPublicKey(bunker)
  const subs = new Set()
  const deliver = ev => { for (const s of subs) if ((s.filter['#p'] || []).includes(ev.tags.find(t => t[0] === 'p')?.[1])) queueMicrotask(() => s.cb.onevent(ev)) }
  const reply = (to, body) => deliver(finalizeEvent({ kind: 24133, created_at: Math.floor(Date.now() / 1000), tags: [['p', to]],
    content: nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(bunker, to)) }, bunker))
  const pool = {
    subscribe(_r, filter, cb) { const s = { filter, cb }; subs.add(s); return { close: () => subs.delete(s) } },
    subscribeMany(r, filter, cb) { return this.subscribe(r, filter, cb) },
    ensureRelay: async () => ({}),
    publish(_r, ev) {
      const req = JSON.parse(nip44.v2.decrypt(ev.content, nip44.v2.utils.getConversationKey(bunker, ev.pubkey)))
      const u = signAs || user
      if (req.method === 'get_public_key') reply(ev.pubkey, { id: req.id, result: getPublicKey(user) })
      else if (req.method === 'sign_event') {
        if (refuseSign) reply(ev.pubkey, { id: req.id, error: 'not allowed' })
        else reply(ev.pubkey, { id: req.id, result: JSON.stringify(finalizeEvent(JSON.parse(req.params[0]), u)) })
      } else reply(ev.pubkey, { id: req.id, result: 'ack' })
      return [Promise.resolve('ok')]
    },
    close() {},
  }
  const approve = uri => {
    const u = new URL(uri.replace(/^nostrconnect:/, 'http:'))
    queueMicrotask(() => reply(u.hostname, { id: 'connect', result: u.searchParams.get('secret') }))
  }
  return { pool, bunkerPub, approve }
}

const dir = mkdtempSync(join(tmpdir(), 'nvoy-pair-'))
const user = generateSecretKey()
const manifestFor = (sub, pubkey = getPublicKey(user)) => {
  const cred = join(dir, sub); mkdirSync(cred, { recursive: true })
  return { id: 'crystalclaude', pubkey, relays: ['wss://relay.invalid'], bunkerUriRef: join(cred, 'crystalclaude.bunker-uri'), bunkerClientRef: join(cred, 'crystalclaude.nip46-client') }
}
const run = (m, h, extra = {}) => {
  const seen = []
  const p = pairInstance(m, { pair: o => nostrConnectSigner({ ...o, _pool: h.pool, timeoutMs: 2000, pubkeyTimeoutMs: 2000 }), timeoutMs: 2000,
    onUri: uri => { seen.push(uri); h.approve(uri) }, ...extra })
  return { p, seen }
}

try {
  // ── The happy path, end to end ──────────────────────────────────────────────────────────────────
  {
    const m = manifestFor('ok'), h = hive({ user })
    const { p, seen } = run(m, h)
    const r = await p
    check('pairs and reports the agent npub', r.npub === nip19.npubEncode(m.pubkey))
    const link = new URL(seen[0].replace(/^nostrconnect:/, 'http:'))
    check('the link asks for exactly the broker permissions', link.searchParams.get('perms') === brokerPerms().join(','))
    check('…which cover every kind the runtime signs, and NIP-44', BROKER_SIGN_KINDS.every(k => brokerPerms().includes(`sign_event:${k}`)) && brokerPerms().includes('nip44_decrypt'))
    check('…including joining an open room, but never adding or removing someone else', brokerPerms().includes('sign_event:9021') && !brokerPerms().some(p => /^sign_event:900[01]$/.test(p)))
    const client = readFileSync(m.bunkerClientRef, 'utf8').trim(), pointer = readFileSync(m.bunkerUriRef, 'utf8').trim()
    check('both credential files are seated 0600', [m.bunkerClientRef, m.bunkerUriRef].every(f => (statSync(f).mode & 0o777) === 0o600))
    check('the client file is the key the link was made for', getPublicKey(Uint8Array.from(Buffer.from(client, 'hex'))) === link.hostname)
    check('the pointer names the Bunker\'s own key and the relays', pointer.startsWith(`bunker://${h.bunkerPub}?relay=`))
    check('the pointer carries no spent secret (#171)', !/secret=/.test(pointer))
    check('no temporary file is left behind', readdirSync(join(dir, 'ok')).every(f => !f.startsWith('.')))
    // The proof that matters: the broker's own client, given exactly what was written, signs as the agent.
    const broker = makeBunkerSigner(pointer, nip19.nsecEncode(Uint8Array.from(Buffer.from(client, 'hex'))), { pool: h.pool, idleMs: 5 })
    const ev = await broker.signEvent({ kind: 9, created_at: 1, tags: [], content: 'hello' })
    check('the broker signs as the agent with the seated files', verifyEvent(ev) && ev.pubkey === m.pubkey)
    broker.close()
  }

  // ── Refusals, each with nothing written ──────────────────────────────────────────────────────────
  {
    const m = manifestFor('wrong', getPublicKey(generateSecretKey())), h = hive({ user })
    check('approving with a key that is not the agent\'s seats nothing, and says which key it got',
      await rejects(run(m, h).p, /approved with npub1.*Nothing was seated/) && !existsSync(m.bunkerClientRef) && !existsSync(m.bunkerUriRef))
  }
  {
    const m = manifestFor('nosign'), h = hive({ user, refuseSign: true })
    check('a Bunker that pairs but will not sign seats nothing', await rejects(run(m, h).p, /would not sign/) && !existsSync(m.bunkerClientRef))
  }
  {
    const m = manifestFor('forged'), h = hive({ user, signAs: generateSecretKey() })
    check('a probe signed by another key seats nothing', await rejects(run(m, h).p, /does not verify as this agent/) && !existsSync(m.bunkerUriRef))
  }
  {
    const m = manifestFor('exists'); writeFileSync(m.bunkerUriRef, 'old\n', { mode: 0o600 })
    let asked = false
    check('an existing credential file stops it before any link is made', await rejects(pairInstance(m, { pair: async () => { asked = true } }), /already exists/) && !asked)
    check('…and the file is untouched', readFileSync(m.bunkerUriRef, 'utf8') === 'old\n')
  }
  {
    const m = { ...manifestFor('none'), bunkerUriRef: '', bunkerClientRef: '' }
    check('an identity with no Bunker files is refused', await rejects(pairInstance(m, { pair: async () => {} }), /names no Bunker credential files/))
  }
  check('a pointer refuses a bad key or relay', (() => { try { bunkerPointer('nope', ['wss://x']); return false } catch { try { bunkerPointer('a'.repeat(64), ['http://x']); return false } catch { return true } } })())

  // ── What it prints ───────────────────────────────────────────────────────────────────────────────
  const src = readFileSync(new URL('../mcp/tools/instance-pair.mjs', import.meta.url), 'utf8')
  check('it never prints the client key or the pointer it writes', !/console\.(log|error)\([^)]*(clientSecretHex|pointer)/.test(src))
  check('the CLI refuses to run as anyone but root', /getuid\(\) !== 0/.test(src))
} finally { rmSync(dir, { recursive: true, force: true }) }

if (failed) { console.log(`\n${failed} FAILED`); process.exit(1) }
console.log('\nall passed')
