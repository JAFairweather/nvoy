// Native Buzz participation (salvage Phase 2): an agent key logs in to a community relay as
// itself and posts kind:9 with no carrier. The stub relay below enforces the Buzz rules the
// library exists to satisfy — challenge on connect, a deadline, one AUTH attempt, membership,
// #h on every channel event and filter, event author == authenticated key — so a regression
// shows up as a refusal here instead of silence on the live relay.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import { channelReply, checkAuthTemplate, nativeMention, normalizeBuzzRelay, openBuzzSession } from '../mcp/tools/buzz_native.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const rejects = async (promise, pattern) => { try { await promise; return false } catch (e) { return pattern.test(e.message) } }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const now = () => Math.floor(Date.now() / 1000)

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607', OTHER = '00000000-0000-4000-8000-000000000000'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const humanSk = generateSecretKey(), human = getPublicKey(humanSk)
const strangerSk = generateSecretKey()
const local = sk => ({ getPublicKey: async () => getPublicKey(sk), signEvent: async t => finalizeEvent(t, sk) })

// --- a Buzz-shaped relay ---
const members = new Set([agent, human]), stored = [], sockets = []
let deadlineMs = 1500
const server = new WebSocketServer({ host: '127.0.0.1', port: 0 })
await new Promise(r => server.on('listening', r))
const RELAY = `ws://127.0.0.1:${server.address().port}`
server.on('connection', ws => {
  sockets.push(ws)
  const challenge = Buffer.from(generateSecretKey()).toString('hex')
  let authed = null, tried = false
  const deadline = setTimeout(() => { if (!authed) ws.close() }, deadlineMs)
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('close', () => clearTimeout(deadline))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      const ev = m[1]
      if (tried) return ws.send(JSON.stringify(['OK', ev.id, false, 'auth-required: authentication already failed']))
      tried = true
      const tag = n => ev.tags.find(t => t[0] === n)?.[1]
      const valid = verifyEvent(ev) && ev.kind === 22242 && tag('challenge') === challenge && tag('relay') === RELAY && Math.abs(ev.created_at - now()) <= 60
      if (!valid) return ws.send(JSON.stringify(['OK', ev.id, false, 'auth-required: invalid auth event']))
      if (!members.has(ev.pubkey)) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted: not a relay member']))
      authed = ev.pubkey
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'EVENT') {
      const ev = m[1]
      if (!authed) return ws.send(JSON.stringify(['OK', ev.id, false, 'auth-required: authenticate first']))
      if (ev.pubkey !== authed) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted: pubkey does not match authenticated key']))
      if (!ev.tags.some(t => t[0] === 'h')) return ws.send(JSON.stringify(['OK', ev.id, false, 'invalid: channel-scoped events must include an h tag']))
      if (!verifyEvent(ev)) return ws.send(JSON.stringify(['OK', ev.id, false, 'invalid: bad signature']))
      stored.push(ev)
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'REQ') {
      if (!authed) return ws.send(JSON.stringify(['CLOSED', m[1], 'auth-required: authenticate first']))
      const filters = m.slice(2)
      // Buzz: any filter without #h makes the whole subscription community-wide — no channel events.
      if (filters.some(f => !f['#h'])) return ws.send(JSON.stringify(['EOSE', m[1]]))
      for (const ev of stored) {
        const h = ev.tags.find(t => t[0] === 'h')?.[1]
        if (filters.some(f => f['#h'].includes(h) && (!f.ids || f.ids.includes(ev.id)) && (!f.kinds || f.kinds.includes(ev.kind))))
          ws.send(JSON.stringify(['EVENT', m[1], ev]))
      }
      return ws.send(JSON.stringify(['EOSE', m[1]]))
    }
  })
})

try {
  // --- pure helpers ---
  ok('the relay origin is normalised and a path is refused', normalizeBuzzRelay('wss://buzz.example/') === 'wss://buzz.example' &&
    (() => { try { normalizeBuzzRelay('wss://buzz.example/relay'); return false } catch { return true } })())
  ok('plaintext ws:// is refused off loopback', (() => { try { normalizeBuzzRelay('ws://buzz.example'); return false } catch { return true } })())

  const tpl = { kind: 22242, created_at: now(), content: '', tags: [['relay', 'wss://buzz.example'], ['challenge', 'c'.repeat(64)]] }
  ok('the AUTH oracle accepts exactly a fresh 22242 for this relay', checkAuthTemplate(tpl, { relay: 'wss://buzz.example' }) === null)
  ok('the AUTH oracle refuses another relay', checkAuthTemplate(tpl, { relay: 'wss://other.example' }) !== null)
  ok('the AUTH oracle refuses an extra tag (e.g. a smuggled NIP-OA auth tag)',
    checkAuthTemplate({ ...tpl, tags: [...tpl.tags, ['auth', 'a'.repeat(64), '', 'b'.repeat(128)]] }, { relay: 'wss://buzz.example' }) !== null)
  ok('the AUTH oracle refuses another kind, content, or a stale time',
    checkAuthTemplate({ ...tpl, kind: 9 }, { relay: 'wss://buzz.example' }) !== null &&
    checkAuthTemplate({ ...tpl, content: 'x' }, { relay: 'wss://buzz.example' }) !== null &&
    checkAuthTemplate({ ...tpl, created_at: now() - 120 }, { relay: 'wss://buzz.example' }) !== null)

  const top = finalizeEvent({ kind: 9, created_at: now(), content: 'hi', tags: [['h', CH], ['p', agent]] }, humanSk)
  const topReply = channelReply({ channel: CH, parent: top, content: 'hello' })
  ok('a reply to a top-level message carries only h, reply-e and p', JSON.stringify(topReply.tags) === JSON.stringify([['h', CH], ['e', top.id, '', 'reply'], ['p', human]]))
  const deep = finalizeEvent({ kind: 9, created_at: now(), content: 'more', tags: [['h', CH], ['e', top.id, '', 'reply'], ['p', agent]] }, humanSk)
  ok('a reply deeper in a thread keeps the root', JSON.stringify(channelReply({ channel: CH, parent: deep, content: 'x' }).tags) ===
    JSON.stringify([['h', CH], ['e', top.id, '', 'root'], ['e', deep.id, '', 'reply'], ['p', human]]))

  const opts = { me: agent, channels: [CH] }
  ok('a p-tagged message in an allowed channel is a mention', nativeMention(top, opts)?.author === human)
  ok('a Desktop mention tag counts too', !!nativeMention(finalizeEvent({ kind: 9, created_at: now(), content: 'x', tags: [['h', CH], ['mention', agent]] }, humanSk), opts))
  ok('another channel is not a mention', nativeMention(finalizeEvent({ kind: 9, created_at: now(), content: 'x', tags: [['h', OTHER], ['p', agent]] }, humanSk), opts) === null)
  ok('two h tags are not a mention', nativeMention(finalizeEvent({ kind: 9, created_at: now(), content: 'x', tags: [['h', CH], ['h', OTHER], ['p', agent]] }, humanSk), opts) === null)
  ok('the agent\'s own message is not a mention', nativeMention(finalizeEvent({ kind: 9, created_at: now(), content: 'x', tags: [['h', CH], ['p', agent]] }, agentSk), opts) === null)
  ok('a forged signature is not a mention', nativeMention({ ...top, content: 'tampered' }, opts) === null)
  ok('a kind:1 note is not a mention', nativeMention(finalizeEvent({ kind: 1, created_at: now(), content: 'x', tags: [['h', CH], ['p', agent]] }, humanSk), opts) === null)

  // --- live against the stub ---
  const session = await openBuzzSession({ relay: RELAY, signer: local(agentSk) })
  ok('a member key logs in as itself', session.pubkey === agent)
  const posted = await session.publish(topReply)
  ok('a native kind:9 reply is accepted under the agent key', posted.accepted && posted.event.pubkey === agent)
  ok('a filter without #h is refused locally rather than silently empty', await rejects(session.fetch({ kinds: [9] }), /#h/))
  const back = await session.fetch({ kinds: [9], '#h': [CH], ids: [posted.event.id] })
  ok('the post reads back from the relay', back.length === 1 && back[0].pubkey === agent)
  ok('a channel event without an h tag is refused before sending',
    await rejects(session.publish({ kind: 9, created_at: now(), content: 'x', tags: [] }), /h tag/))
  session.close()

  ok('a non-member key is refused with the relay\'s reason', await rejects(openBuzzSession({ relay: RELAY, signer: local(strangerSk) }), /not a relay member/))
  const liar = { getPublicKey: async () => agent, signEvent: async t => finalizeEvent(t, strangerSk) }
  ok('a signer that answers for another key is caught before AUTH is sent', await rejects(openBuzzSession({ relay: RELAY, signer: liar }), /not ours/))
  deadlineMs = 200
  const slow = { getPublicKey: async () => agent, signEvent: async t => { await sleep(500); return finalizeEvent(t, agentSk) } }
  ok('a signer slower than the relay deadline fails loudly, not silently', await rejects(openBuzzSession({ relay: RELAY, signer: slow, timeoutMs: 2000 }), /closed|timed out/))
  deadlineMs = 1500

  // --- the join-test CLI ---
  const dir = mkdtempSync(join(tmpdir(), 'nvoy-buzz-probe-'))
  const keyFile = join(dir, 'test.nsec'), nsec = nip19.nsecEncode(agentSk)
  writeFileSync(keyFile, `${nsec}\n`, { mode: 0o600 })
  const probe = (args, env = {}, input = '') => new Promise(res => {
    const child = spawn(process.execPath, [resolve('mcp/tools/buzz-probe.mjs'), ...args], {
      env: { ...process.env, NVOY_NSEC: '', NVOY_BUNKER_URI_FILE: '', NVOY_NIP46_CLIENT_FILE: '', NVOY_NIP46_CLIENT_NSEC_FILE: '',
        BUZZ_RELAY: RELAY, BUZZ_CHANNEL: CH, NVOY_NSEC_FILE: keyFile, ...env }, stdio: ['pipe', 'pipe', 'pipe'] })
    let out = '', err = ''
    child.stdout.on('data', d => { out += d }); child.stderr.on('data', d => { err += d })
    child.on('close', code => { let v = null; try { v = JSON.parse(out) } catch { /* judged by caller */ } res({ code, out, err, v }) })
    child.stdin.end(input)
  })
  const count = stored.length
  const dry = await probe(['--post'], {}, 'native join test')
  ok('the probe logs in and reads', dry.code === 0 && dry.v?.auth?.ok && dry.v?.read?.ok && dry.v.read.count === count)
  ok('--post without --confirm publishes nothing', stored.length === count && dry.v?.post?.ok === null)
  const live = await probe(['--post', '--confirm'], {}, 'native join test')
  ok('--post --confirm posts and proves it by a cold read-back', live.code === 0 && live.v?.post?.ok && live.v.post.readback === true && stored.length === count + 1)
  ok('the probe never prints the key or the message body', ![dry, live].some(r => `${r.out}${r.err}`.includes(nsec) || r.out.includes('native join test')))
  members.delete(agent)
  const refused = await probe([])
  ok('a key with no membership row gets a recorded no, not a crash', refused.code === 10 && refused.v?.auth?.ok === false && /not a relay member/.test(refused.v.auth.reason))
  members.add(agent)
  chmodSync(keyFile, 0o644)
  const exposed = await probe([])
  ok('a group/world-readable key file fails closed', exposed.code === 1 && /mode 0600/.test(exposed.err))
  chmodSync(keyFile, 0o600)
  const rawEnv = await probe([], { NVOY_NSEC: nsec })
  ok('a raw key in the environment is refused', rawEnv.code === 1 && /NVOY_NSEC is refused/.test(rawEnv.err) && !rawEnv.err.includes(nsec))
  const wrong = await probe([], { EXPECT_PUBKEY: 'f'.repeat(64) })
  ok('EXPECT_PUBKEY pins the identity before anything is sent', wrong.code === 1 && /identity mismatch/.test(wrong.err))
} finally {
  server.close()
  for (const ws of sockets) ws.terminate()
}

console.log(fails ? `\nbuzz-native: ${fails} FAILED` : '\nbuzz-native: all passed')
process.exit(fails ? 1 : 0)
