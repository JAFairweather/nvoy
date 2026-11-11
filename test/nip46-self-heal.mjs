// NIP-46 session self-heal (status S0, fix 3). After the 10-16 fleet reboot the brokers kept
// Bunker46 sessions that answered nothing; every signature timed out until a human restarted them.
// A run of consecutive timeouts must rebuild the session from the same credentials, and nothing
// else may: not a refusal, not one slow answer between good ones, not a call left on a retired session.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { decode } from 'nostr-tools/nip19'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip44 from 'nostr-tools/nip44'
import { makeBunkerSigner } from '../mcp/tools/nip46-signer.mjs'
import { brokerSigner, HEAL_AFTER_TIMEOUTS, selfHealingSigner } from '../mcp/tools/broker_signer.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }

// Each opened session follows a script of outcomes: 'ok', 'timeout', 'refused', or 'hang' (settled later).
function sessions(...scripts) {
  const opened = []
  const open = () => {
    const script = [...(scripts[opened.length] || [])], s = { closed: false, pubkey: 'p'.repeat(64), hung: [] }
    const outcome = () => new Promise((resolve, reject) => {
      const next = script.shift() || 'ok'
      if (next === 'ok') resolve({ signedBy: opened.indexOf(s) })
      else if (next === 'timeout') reject(new Error('nip46 sign_event timed out'))
      else if (next === 'refused') reject(new Error('bunker: permission denied'))
      else s.hung.push(reject)
    })
    Object.assign(s, { signEvent: outcome, getPublicKey: outcome, nip44Encrypt: outcome, nip44Decrypt: outcome,
      close() { s.closed = true; for (const r of s.hung) r(new Error('nip46 signer closed')) } })
    opened.push(s)
    return s
  }
  return { open, opened }
}
const settle = p => p.then(v => ({ v }), e => ({ e: e.message }))

ok('the default threshold is three consecutive timeouts', HEAL_AFTER_TIMEOUTS === 3)
{
  const { open, opened } = sessions(['timeout', 'timeout', 'timeout'], [])
  const logs = [], signer = selfHealingSigner(open, { log: m => logs.push(m) })
  await settle(signer.signEvent({})); await settle(signer.signEvent({}))
  ok('two timeouts are not yet a dead session', opened.length === 1 && !logs.length)
  const third = await settle(signer.signEvent({}))
  ok('the third timeout still fails its own call', /timed out/.test(third.e || ''))
  ok('the third consecutive timeout rebuilds the session', opened.length === 2 && opened[0].closed && !opened[1].closed)
  ok('the rebuild is logged, and says it did not re-pair', logs.length === 1 && /rebuilt after 3 consecutive timeouts/.test(logs[0]) && /no re-pair/.test(logs[0]))
  ok('the next signature comes from the new session', (await signer.signEvent({})).signedBy === 1)
  ok('the wrapper still reports the session pubkey', signer.pubkey === 'p'.repeat(64))
}
{
  const { open, opened } = sessions(['timeout', 'timeout', 'ok', 'timeout', 'timeout'])
  const signer = selfHealingSigner(open, { log: () => {} })
  for (let i = 0; i < 5; i++) await settle(signer.signEvent({}))
  ok('a success between timeouts resets the count: they must be consecutive', opened.length === 1)
}
{
  const { open, opened } = sessions(['refused', 'refused', 'refused', 'refused'])
  const signer = selfHealingSigner(open, { log: () => {} })
  for (let i = 0; i < 4; i++) await settle(signer.signEvent({}))
  ok('a Bunker refusal is an answer, not a dead session', opened.length === 1)
}
{
  const { open, opened } = sessions(['timeout', 'timeout', 'timeout', 'timeout', 'timeout'], ['timeout', 'ok'])
  const signer = selfHealingSigner(open, { log: () => {} })
  for (let i = 0; i < 3; i++) await settle(signer.getPublicKey())
  ok('other Bunker calls (get_public_key) count as well as signatures', opened.length === 2)
}
{
  const { open, opened } = sessions(['hang', 'timeout', 'timeout', 'timeout'], ['timeout', 'ok'])
  const signer = selfHealingSigner(open, { log: () => {} })
  const stranded = settle(signer.signEvent({}))
  for (let i = 0; i < 3; i++) await settle(signer.signEvent({}))
  ok('a call stranded on the retired session is closed with it', (await stranded).e === 'nip46 signer closed')
  await settle(signer.signEvent({}))
  ok('a stranded call never counts against the new session', opened.length === 2)
}
{
  const { open, opened } = sessions(['timeout', 'timeout'])
  const signer = selfHealingSigner(open, { healAfter: 2, log: () => {} })
  await settle(signer.signEvent({})); await settle(signer.signEvent({}))
  ok('the threshold is configurable', opened.length === 2)
  signer.close()
  ok('close closes the live session', opened[1].closed)
}

// --- wiring: every Bunker-backed broker signer heals, from credentials it already holds ---
const src = readFileSync('mcp/tools/broker_signer.mjs', 'utf8')
ok('brokerSigner wraps the Bunker signer in the healer, reusing the URI and transport key in memory',
  /selfHealingSigner\(\(\) => makeBunkerSigner\(uri, client, options\)\)/.test(src))
ok('the healer never reads or writes a credential file', !/readFileSync|writeFileSync/.test(src.slice(src.indexOf('export function selfHealingSigner'), src.indexOf('export function brokerSigner'))))
ok('the AUTH oracle gets its signer from brokerSigner', /brokerSigner\(die/.test(readFileSync('mcp/tools/instance-broker-auth.mjs', 'utf8')))

// --- a hex transport key works with a Bunker (10-23: LukeDog's broker died decoding hex as bech32) ---
{
  const dir = mkdtempSync(join(tmpdir(), 'nvoy-hex-client-')), hex = 'ab'.repeat(32)
  writeFileSync(join(dir, 'client'), `${hex}\n`)
  writeFileSync(join(dir, 'uri'), `bunker://${getPublicKey(Uint8Array.from(Buffer.from('cd'.repeat(32), 'hex')))}?relay=wss://relay.invalid&secret=s\n`)
  const env = { ...process.env }
  Object.assign(process.env, { NVOY_BROKER_CREDENTIAL: join(dir, 'client'), NVOY_BUNKER_URI_FILE: join(dir, 'uri') })
  let built, error
  try { built = brokerSigner(m => { throw new Error(m) }) } catch (e) { error = e.message }
  ok('a hex transport key builds a Bunker signer' + (error ? ` (${error})` : ''), !error && built?.signer)
  const nsec = built?.attentionEnv.NVOY_NIP46_CLIENT_NSEC || ''
  ok('the transport key reaches the attention env as the same key, nsec-encoded',
    nsec.startsWith('nsec1') && Buffer.from(decode(nsec).data).toString('hex') === hex)
  built?.signer.close(); process.env = env; rmSync(dir, { recursive: true, force: true })
}

// --- every Bunker client takes a hex transport key, not only brokerSigner (10-24: the reply and
// attention paths still decoded it as bech32) ---
{
  const bunkerSk = generateSecretKey(), clientSk = generateSecretKey()
  const bunkerPub = getPublicKey(bunkerSk), clientPub = getPublicKey(clientSk)
  const conversation = nip44.v2.utils.getConversationKey(bunkerSk, clientPub)
  // A fake Bunker that can read only requests encrypted by the configured client key.
  const pool = {
    handler: null,
    subscribeMany(_relays, _filter, callbacks) { this.handler = callbacks.onevent; return { close() {} } },
    publish(_relays, event) {
      const request = JSON.parse(nip44.v2.decrypt(event.content, conversation))
      const response = finalizeEvent({ kind: 24133, created_at: 1, tags: [['p', clientPub]],
        content: nip44.v2.encrypt(JSON.stringify({ id: request.id, result: bunkerPub }), conversation) }, bunkerSk)
      queueMicrotask(() => this.handler(response))
      return [Promise.resolve('ok')]
    },
    close() {},
  }
  let resolved, error
  try {
    const signer = makeBunkerSigner(`bunker://${bunkerPub}?relay=wss%3A%2F%2Frelay.invalid&secret=test`, Buffer.from(clientSk).toString('hex'), { pool, idleMs: 5 })
    resolved = await signer.getPublicKey(); signer.close()
  } catch (e) { error = e.message }
  ok('makeBunkerSigner completes a Bunker round trip with a hex transport key' + (error ? ` (${error})` : ''), resolved === bunkerPub)
}

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
