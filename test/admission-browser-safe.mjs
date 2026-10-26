// The admission rules a browser must be able to run (waggle#613, HIVE_MANAGER_SPEC C2): the module
// graph under admission.mjs, invocation_policy.mjs and channel_task_carry.mjs reaches no node builtin
// and no package but nostr-tools/pure, and a browser-side sha256 folds the same grants the broker does.
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256 } from '@noble/hashes/sha2.js'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { foldGrantsWith, nativeGrant } from '../mcp/tools/admission.mjs'
import { foldGrants, scopeHash } from '../mcp/tools/grant_fold.mjs'

let fails = 0, passes = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }

const tools = join(dirname(fileURLToPath(import.meta.url)), '..', 'mcp', 'tools')
const ALLOWED = new Set(['nostr-tools/pure'])
const outside = new Set(), seen = new Set()
const walk = file => {
  if (seen.has(file)) return
  seen.add(file)
  for (const [, spec] of readFileSync(file, 'utf8').matchAll(/^\s*(?:import|export)\b[^'"]*?from\s+['"]([^'"]+)['"]/gm)) {
    if (spec.startsWith('.')) walk(resolve(dirname(file), spec))
    else if (!ALLOWED.has(spec)) outside.add(spec)
  }
}
for (const f of ['admission.mjs', 'invocation_policy.mjs', 'channel_task_carry.mjs']) walk(join(tools, f))
ok(`the admission graph (${seen.size} modules) imports nothing a browser lacks${outside.size ? `: ${[...outside].join(', ')}` : ''}`, outside.size === 0)

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
const browserScopeHash = (subject, salt) => {
  const enc = new TextEncoder()
  const saltBytes = Uint8Array.from((salt || '').match(/../g) || [], h => parseInt(h, 16))
  return hex(sha256(new Uint8Array([...enc.encode('waggle/da-scope/v1'), 0, ...enc.encode(String(subject)), ...saltBytes])))
}

const key = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk) } }
const agent = key().pk, owner = key(), colleague = key(), gone = key(), voice = key()
const salt = 'ab'.repeat(16), now = Math.floor(Date.now() / 1000)
ok('a browser sha256 gives the broker\'s scope hash', browserScopeHash(agent, salt) === scopeHash(agent, salt))

const ev = (kind, tags, at) => finalizeEvent({ kind, created_at: at, content: '', tags }, owner.sk)
const grant = (to, cap, subject = agent, at = now - 50, extra = []) =>
  ev(440, [['p', to], ['da-scope', scopeHash(subject, salt), salt], ['da-cap', cap], ...extra], at)
const revoked = grant(gone.pk, 'task', agent, now - 60)
const events = [
  grant(owner.pk, 'task+act'),
  grant(colleague.pk, 'task'),
  revoked,
  ev(441, [['e', revoked.id]], now - 40),
  grant(key().pk, 'task', agent, now - 50, [['expiration', String(now - 1)]]),
  grant(voice.pk, 'shadow', owner.pk),
]
const flat = r => JSON.stringify({ live: [...r.live].map(([pk, caps]) => [pk, [...caps]]).sort(), ended: [...r.ended].sort(), rejected: r.rejected })
const node = foldGrants(events, { me: agent, grantors: [owner.pk] })
const browser = foldGrantsWith(events, { me: agent, grantors: [owner.pk], scopeHash: browserScopeHash })
ok('the browser fold equals the broker fold', flat(node) === flat(browser))
ok('the fold keeps the owner, the colleague and the voice, and drops the revoked and expired grants',
  node.live.size === 3 && node.live.has(colleague.pk) && node.live.get(voice.pk)?.get('task+act')?.shadow === true && node.ended.get(gone.pk) === 'revoked')

const grants = [...node.live].flatMap(([pubkey, caps]) => [...caps.values()].map(g => ({ pubkey, grantor: g.grantor, cap: g.cap, grant_id: g.grantId })))
ok('a DM admits the owner only', nativeGrant({ author: owner.pk, dm: true, grants, grantors: [owner.pk] })?.cap === 'task+act'
  && nativeGrant({ author: colleague.pk, dm: true, grants, grantors: [owner.pk] }) === null)
ok('in a channel a colleague\'s task grant admits', nativeGrant({ author: colleague.pk, dm: false, grants, grantors: [owner.pk] })?.cap === 'task')

console.log(`\n${passes} passed, ${fails} failed`)
process.exit(fails ? 1 : 0)
