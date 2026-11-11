// The one grant fold the broker, the wake watcher and the status page share, and the shadow grant:
// a voice holds its grantor's own live task grants under one revocable grant, and nothing more.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdirSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { foldGrants, scopeHash } from '../mcp/tools/grant_fold.mjs'

let fails = 0, passes = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }
const now = () => Math.floor(Date.now() / 1000)
const key = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk) } }

const agentSk = generateSecretKey(), agent = getPublicKey(agentSk), other = getPublicKey(generateSecretKey())
const director = key(), second = key(), voice = key(), voice2 = key(), dennis = key(), stranger = key()
const grantors = [director.pk, second.pk]
const salt = 'cd'.repeat(16)
const ev = (signer, kind, tags, at = now() - 100) => finalizeEvent({ kind, created_at: at, content: '', tags }, signer.sk)
const task = (signer, to, cap = 'task', { subject = agent, at, extra = [] } = {}) =>
  ev(signer, 440, [['p', to], ['da-scope', scopeHash(subject, salt), salt], ['da-cap', cap], ...extra], at)
const shadow = (signer, to, { subject = signer.pk, at, extra = [] } = {}) =>
  ev(signer, 440, [['p', to], ['da-scope', scopeHash(subject, salt), salt], ['da-cap', 'shadow'], ...extra], at)
const revoke = (signer, id, at = now() - 50) => ev(signer, 441, [['e', id]], at)
const fold = events => foldGrants(events, { me: agent, grantors })
const caps = (r, pk) => [...(r.live.get(pk)?.keys() || [])].sort()

// --- the fold, as the broker reads it ---
const own = task(director, director.pk, 'task+act'), sh = shadow(director, voice.pk)
let r = fold([own, sh])
const held = r.live.get(voice.pk)?.get('task+act')
ok('a voice holds the grantor\'s own task grant', !!held)
ok('under the shadow grant\'s id, not the grantor\'s', held?.grantId === sh.id && held?.grantor === director.pk && held?.shadow === true)
ok('the grantor\'s own grant is untouched', r.live.get(director.pk)?.get('task+act')?.grantId === own.id && !r.live.get(director.pk)?.get('task+act')?.shadow)
ok('a shadow older than the grantor\'s grant still sees it', !!fold([shadow(director, voice.pk, { at: now() - 500 }), own]).live.get(voice.pk))
ok('a grantor with no grant of its own here gives its voice nothing', !fold([sh]).live.has(voice.pk))
ok('the voice inherits every task cap the grantor holds', caps(fold([own, task(director, director.pk, 'task'), sh]), voice.pk).join() === 'task,task+act')

r = fold([own, sh, revoke(director, sh.id)])
ok('one revocation of the shadow silences the voice', !r.live.has(voice.pk) && r.ended.get(voice.pk) === 'revoked')
ok('and leaves the grantor\'s own grant live', r.live.get(director.pk)?.has('task+act'))
r = fold([own, sh, revoke(director, own.id)])
ok('revoking the grantor\'s own grant here takes the voice\'s reach here too', !r.live.has(voice.pk) && !r.live.has(director.pk))
r = fold([own, shadow(director, voice.pk, { extra: [['expiration', String(now() - 1)]] })])
ok('an expired shadow is ended like a revocation', !r.live.has(voice.pk) && r.ended.get(voice.pk) === 'expired')
ok('a shadow expiring later is live', fold([own, shadow(director, voice.pk, { extra: [['expiration', String(now() + 3600)]] })]).live.has(voice.pk))

ok('a shadow scoped to anyone but its signer is ignored', !fold([own, shadow(director, voice.pk, { subject: agent })]).live.has(voice.pk))
ok('a shadow scoped to another grantor is ignored', !fold([own, shadow(director, voice.pk, { subject: second.pk })]).live.has(voice.pk))
ok('a grantor cannot shadow itself', fold([own, shadow(director, director.pk)]).live.get(director.pk)?.get('task+act')?.grantId === own.id)
ok('a shadow from a non-grantor counts for nothing', !fold([own, task(stranger, stranger.pk), shadow(stranger, voice.pk)]).live.has(voice.pk))
// Through JSON, as off a relay: a spread copy would carry nostr-tools' cached verified symbol.
const forged = JSON.parse(JSON.stringify({ ...sh, tags: [['p', voice2.pk], ...sh.tags.slice(1)] }))
r = fold([own, forged])
ok('a shadow whose signature does not cover its tags is rejected', !r.live.has(voice2.pk) && r.rejected === 1)
ok('a shadow cap is never a task grant on its own', !fold([shadow(director, voice.pk, { subject: agent })]).live.has(voice.pk))

// The second grantor is the director's voice here and holds nothing of its own; its voice gets nothing.
r = fold([own, shadow(director, second.pk), shadow(second, voice2.pk)])
ok('shadows do not chain: a grantor\'s voice reach is not passed on to its own voice', r.live.get(second.pk)?.get('task+act')?.shadow === true && !r.live.has(voice2.pk))
ok('a voice cannot sign grants: its task grant and shadow are not read', !fold([own, sh, task(voice, voice2.pk), shadow(voice, voice2.pk)]).live.has(voice2.pk))
ok('a voice inherits the grantor\'s own grants, never another voice\'s', !fold([task(director, dennis.pk), shadow(director, voice.pk)]).live.has(voice.pk))
const direct = task(director, voice.pk, 'task')
r = fold([own, task(director, director.pk, 'task'), direct, sh])
ok('a voice\'s own direct grant wins over the inherited one for that cap', r.live.get(voice.pk)?.get('task')?.grantId === direct.id && !r.live.get(voice.pk)?.get('task')?.shadow)
ok('and the caps it lacks still come from the shadow', r.live.get(voice.pk)?.get('task+act')?.grantId === sh.id)
r = fold([own, direct, sh, revoke(director, sh.id)])
ok('revoking the shadow leaves the voice\'s direct grant live', r.live.get(voice.pk)?.get('task')?.grantId === direct.id && !r.live.get(voice.pk)?.has('task+act'))
ok('a grant from the second grantor is voiced only by that grantor\'s shadow', !fold([task(second, second.pk), sh]).live.has(voice.pk) &&
  fold([task(second, second.pk), shadow(second, voice.pk)]).live.get(voice.pk)?.get('task')?.grantor === second.pk)
ok('a grant scoped to another agent is still not a grant here, for the grantor or its voice', !fold([task(director, director.pk, 'task', { subject: other }), sh]).live.size)

// --- attention --policy-only, as every broker and the reply recheck call it ---
const grants = [own, sh, task(director, dennis.pk), shadow(stranger, voice2.pk)]
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(res => http.listen(0, '127.0.0.1', res))
const relay = new WebSocketServer({ server: http })
relay.on('connection', ws => ws.on('message', raw => {
  const m = JSON.parse(raw.toString())
  if (m[0] !== 'REQ') return
  for (const e of grants) if (m[2].kinds.includes(e.kind) && m[2].authors.includes(e.pubkey)) ws.send(JSON.stringify(['EVENT', m[1], e]))
  ws.send(JSON.stringify(['EOSE', m[1]]))
}))
const root = mkdtempSync(join(tmpdir(), 'grant-fold-')); mkdirSync(join(root, 'home'))
const out = await new Promise(resolve => {
  const child = spawn(process.execPath, ['mcp/tools/attention.mjs', '--policy-only'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: join(root, 'home'), NVOY_NSEC: Buffer.from(agentSk).toString('hex'),
      GRANTORS: grantors.join(','), NVOY_RELAYS: `ws://127.0.0.1:${http.address().port}` } })
  let stdout = ''; child.stdout.on('data', c => { stdout += c }); child.on('exit', status => resolve({ status, stdout }))
})
let policy = {}; try { policy = JSON.parse(out.stdout) } catch { /* reported below */ }
const row = (policy.grants || []).find(g => g.pubkey === voice.pk)
ok('attention answers with usable policy', out.status === 0 && policy.me === agent && policy.policyUsable === true)
ok('attention lists the voice under the shadow grant, marked as a shadow', row?.grant_id === sh.id && row?.grantor === director.pk && row?.cap === 'task+act' && row?.shadow === true)
ok('attention does not mark a direct grant as a shadow', (policy.grants || []).filter(g => g.pubkey !== voice.pk).every(g => g.shadow === undefined))
ok('attention ignores a non-grantor\'s shadow', !(policy.grants || []).some(g => g.pubkey === voice2.pk))
relay.close(); http.close()

console.log(`\n${passes} passed, ${fails} failed`)
process.exit(fails ? 1 : 0)
