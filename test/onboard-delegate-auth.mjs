// Onboarding delegate, Part 1 piece 2 (waggle docs/DESIGN_ONBOARDING_DELEGATE.md, "Authorization"):
// parseSetupRequest accepts a delegate's request only within the owner's limits, and records the
// grantor as owner and the delegate as signer.
import assert from 'node:assert/strict'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { parseSetupRequest, DELEGATE_DAILY_CAP, RETRY_CODES } from '../mcp/tools/onboard_request.mjs'
import { runnerConfig } from '../mcp/tools/onboard_receipt.mjs'

let n = 0
const ok = (cond, name) => { assert.ok(cond, name); n++; console.log(`ok   ${name}`) }
const code = (f, c) => { try { f(); return false } catch (e) { return e.code === c } }
const owner = generateSecretKey(), ownerHex = getPublicKey(owner)
const del = generateSecretKey(), delHex = getPublicKey(del)
const stranger = generateSecretKey()
const nowMs = Date.now(), at = Math.floor(nowMs / 1000)
const agent = getPublicKey(generateSecretKey())
const manifests = new Map([
  ['crystalclaude', { id: 'crystalclaude', pubkey: getPublicKey(generateSecretKey()), grantors: [ownerHex] }],
  ['mc-claude', { id: 'mc-claude', pubkey: getPublicKey(generateSecretKey()), grantors: [ownerHex] }],
  ['pi-dog', { id: 'pi-dog', pubkey: getPublicKey(generateSecretKey()), grantors: [ownerHex] }],
])
const GRANT = 'a'.repeat(64)
const grant = (over = {}) => ({ grantId: GRANT, grantor: ownerHex, delegate: delHex, created_at: at - 100, policy: 'terms-v3', age: 'confirmed', ...over })
const state = (g = grant()) => ({ known: true, live: new Map([[delHex, [g]]]) })
const delegation = (over = {}) => ({ state: state(), templates: ['mc-claude', 'crystalclaude'], terms: { ok: true, version: 'terms-v3' }, ledger: [], ...over })
const req = (key, { name = 'newagent', op = 'add_agent', like = 'crystalclaude', extra = [], p = agent } = {}) => finalizeEvent({ kind: 30078, created_at: at, content: '',
  tags: [['d', `nvoy-onboard/${name}/${op}`], ['op', op], ['p', p], ['harness', 'claude-code'], ['like', like], ...extra] }, key)
const parse = (event, opts = {}) => parseSetupRequest(event, { name: 'newagent', manifests, now: nowMs, ...opts })

// ── Accepted within the limits ──────────────────────────────────────────────────────────────────
const good = req(del, { extra: [['consent', GRANT]] })
const r = parse(good, { delegation: delegation() })
ok(r.owner === ownerHex && r.signer === delHex && r.delegated && r.grantId === GRANT, "a delegate's request is recorded with the grantor as owner and the delegate as signer")
ok(r.policy === 'terms-v3' && r.ageConfirmed === true, "its terms and age come from the owner's grant, not the request")
const mine = parse(req(owner, { extra: [['policy', 'terms-v3'], ['age', 'confirmed'], ['giver', ownerHex]] }), { delegation: delegation() })
ok(mine.owner === ownerHex && mine.signer === ownerHex && !mine.delegated && mine.givers.length === 1, "an owner's own request reads as before, givers and all")
ok(code(() => parse(good), 'ONBOARD_NOT_OWNER'), 'with no delegation configured, a delegate is refused as not a grantor, as before')

// ── Refused ────────────────────────────────────────────────────────────────────────────────────
ok(code(() => parse(req(stranger, { extra: [['consent', GRANT]] }), { delegation: delegation() }), 'ONBOARD_NOT_OWNER'), 'a key with no live grant is refused')
ok(code(() => parse(good, { delegation: delegation({ state: { known: false, live: new Map() } }) }), 'ONBOARD_NOT_OWNER'), 'an unknown grant state backs no delegate')
ok(code(() => parse(good, { delegation: delegation({ state: state(grant({ grantor: getPublicKey(stranger) })) }) }), 'ONBOARD_NOT_OWNER'), "a grant from someone who is not this template's grantor backs nothing")
ok(code(() => parse(req(del, { like: 'pi-dog', extra: [['consent', GRANT]] }), { delegation: delegation() }), 'ONBOARD_DELEGATE_TEMPLATE'), 'a template outside onboard_templates is refused')
ok(code(() => parse(good, { delegation: delegation({ templates: [] }) }), 'ONBOARD_DELEGATE_TEMPLATE'), 'an empty onboard_templates refuses every delegate request')
ok(code(() => parse(req(del), { delegation: delegation() }), 'ONBOARD_DELEGATE_CONSENT'), 'a delegate request without consent is refused')
ok(code(() => parse(req(del, { extra: [['consent', 'b'.repeat(64)]] }), { delegation: delegation() }), 'ONBOARD_DELEGATE_CONSENT'), 'consent naming another grant is refused')
ok(code(() => parse(req(del, { extra: [['consent', GRANT], ['policy', 'terms-v3']] }), { delegation: delegation() }), 'ONBOARD_DELEGATE_CONSENT'), "a delegate may not carry the owner's policy itself")
ok(code(() => parse(req(del, { extra: [['consent', GRANT], ['age', 'confirmed']] }), { delegation: delegation() }), 'ONBOARD_DELEGATE_CONSENT'), "nor the owner's age confirmation")
ok(code(() => parse(good, { delegation: delegation({ state: state(grant({ policy: null })) }) }), 'ONBOARD_DELEGATE_CONSENT'), 'a grant with no terms version backs nothing')
ok(code(() => parse(good, { delegation: delegation({ state: state(grant({ age: null })) }) }), 'ONBOARD_DELEGATE_CONSENT'), 'a grant with no age confirmation backs nothing')
ok(code(() => parse(good, { delegation: delegation({ terms: { ok: true, version: 'terms-v4' } }) }), 'ONBOARD_DELEGATE_CONSENT'), 'when the terms change, the old grant backs no request until the owner signs a new one')
ok(code(() => parse(good, { delegation: delegation({ terms: { ok: false, reason: 'HTTP 502' } }) }), 'ONBOARD_TERMS_UNKNOWN') && RETRY_CODES.includes('ONBOARD_TERMS_UNKNOWN'), "unreadable terms refuse for now, and the watcher retries rather than setting the request aside")
ok(code(() => parse(req(del, { extra: [['consent', GRANT], ['giver', ownerHex]] }), { delegation: delegation() }), 'ONBOARD_DELEGATE_GIVER'), 'a delegate request that names any giver is refused')
ok(code(() => parse(req(owner, { extra: [['consent', GRANT]] }), { delegation: delegation() }), 'ONBOARD_BAD_TAG'), "an owner's request has no use for consent")

// ── The daily cap ───────────────────────────────────────────────────────────────────────────────
ok(DELEGATE_DAILY_CAP === 1, 'the cap is one new agent a day (James, 12 Nov)')
const row = (name, ago, signer = delHex) => ({ id: name + ago, name, op: 'add_agent', at: nowMs - ago, signer, owner: ownerHex })
ok(code(() => parse(good, { delegation: delegation({ ledger: [row('first', 60 * 60 * 1000)] }) }), 'ONBOARD_DELEGATE_CAP'), 'a second new name within 24 hours is refused')
ok(parse(good, { delegation: delegation({ ledger: [row('first', 25 * 60 * 60 * 1000)] }) }).delegated, 'one more than 24 hours ago does not count')
ok(parse(good, { delegation: delegation({ ledger: [row('first', 60 * 1000, ownerHex)] }) }).delegated, "the owner's own adds do not count against the delegate")
ok(parse(good, { delegation: delegation({ ledger: [row('newagent', 60 * 1000)] }) }).delegated, 'the same name again is not a new name')

// ── bind_runtime ────────────────────────────────────────────────────────────────────────────────
const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'a'.repeat(40)
const bind = parse(req(del, { op: 'bind_runtime', extra: [['consent', GRANT], ['channel_key', KEY]] }), { delegation: delegation() })
ok(bind.delegated && bind.owner === ownerHex && bind.signer === delHex, "a delegate's bind is accepted within the same limits, flagged so the run demands the staged key")

// ── The fleet's onboard_templates ───────────────────────────────────────────────────────────────
const base = { pubkey: 'f'.repeat(64), relays: ['wss://relay.example'], bunker_client_ref: '/a', bunker_uri_ref: '/b', authorized_keys: '/c', ssh_target: 'u@h' }
ok(runnerConfig(base).onboardTemplates.length === 0, 'a runner config without onboard_templates allows no delegate template')
ok(runnerConfig({ ...base, onboard_templates: ['mc-claude', 'crystalclaude', 'mc-claude'] }).onboardTemplates.join() === 'mc-claude,crystalclaude', 'the configured templates are read once each')
ok((() => { try { runnerConfig({ ...base, onboard_templates: 'mc-claude' }); return false } catch { return true } })(), 'onboard_templates that is not a list stops the tick')

// ── A full run: owner and signer in the ledger, terms read for a delegate, the staged key mandatory ──
{
  const { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const { onboard } = await import('../mcp/tools/onboard_run.mjs')
  const harness = staged => {
    const tmp = mkdtempSync(join(tmpdir(), 'nvoy-delegate-run-'))
    const root = join(tmp, 'instances'), out = join(tmp, 'staged'), stateDir = join(tmp, 'state'), creds = join(tmp, 'creds'), backupRoot = join(tmp, 'root')
    for (const d of [root, out, creds, backupRoot]) mkdirSync(d, { recursive: true })
    let uid = 5000
    const raw = (id, pubkey) => {
      const dir = join(tmp, 'var', id)
      for (const x of ['state', 'run', 'spool']) mkdirSync(join(dir, x), { recursive: true })
      uid += 10
      return { id, pubkey, grantors: [ownerHex], relays: ['wss://relay.example'], buzz: { relay: 'wss://buzz.example', channels: ['00000000-0000-4000-8000-000000000000'] },
        broker_mode: 'local', bunker_uri_ref: join(creds, `${id}.bunker-uri`), bunker_client_ref: join(creds, `${id}.nip46-client`),
        delivery_mode: 'notify_only', worker_enabled: false, state_dir: join(dir, 'state'), runtime_dir: join(dir, 'run'), spool_dir: join(dir, 'spool'),
        broker_adapter_gid: uid, worker_handoff_gid: uid + 1, watcher_uid: uid + 2, broker_uid: uid + 3, adapter_uid: uid + 4, worker_uid: uid + 5 }
    }
    writeFileSync(join(root, 'crystalclaude.json'), JSON.stringify(raw('crystalclaude', getPublicKey(generateSecretKey()))))
    const sign = tags => finalizeEvent({ kind: 30078, created_at: at, content: '', tags }, del)
    const add = sign([['d', 'nvoy-onboard/hr/add_agent'], ['op', 'add_agent'], ['p', agent], ['harness', 'claude-code'], ['like', 'crystalclaude'], ['consent', GRANT]])
    const bindEv = sign([['d', 'nvoy-onboard/hr/bind_runtime'], ['op', 'bind_runtime'], ['p', agent], ['harness', 'claude-code'], ['like', 'crystalclaude'], ['consent', GRANT], ['channel_key', KEY]])
    const runTool = (tool, args) => {
      const op = tool === 'instance-pair.mjs' ? 'pair' : args[0], id = args[args.indexOf('--id') + 1]
      if (op === 'allocate') { writeFileSync(join(out, `${id}.json`), JSON.stringify(raw(id, agent))); return 0 }
      if (op === 'pair') { writeFileSync(join(creds, `${id}.bunker-uri`), 'x'); writeFileSync(join(creds, `${id}.nip46-client`), 'x'); return 0 }
      if (op === 'check') return 0
      if (op === 'apply') { copyFileSync(join(out, 'hr.json'), join(root, 'hr.json')); return 0 }
      throw new Error(`unexpected tool ${tool} ${op}`)
    }
    const termsAsked = []
    const run = events => onboard({ command: 'run', name: 'hr', root, out, stateDir, backupRoot, keysPath: join(tmp, 'authorized_keys'), log: () => {},
      fetchEvents: async () => events, runTool, joinWith: () => ({ signer: {}, open: async () => { throw new Error('AUTH refused: not a member') }, close() {} }),
      readDelegates: async () => state(), delegateTemplates: ['crystalclaude'], readTermsFor: async relay => { termsAsked.push(relay); return { ok: true, version: 'terms-v3' } } })
    return { tmp, stateDir, add, bindEv, run, termsAsked, ledger: () => readFileSync(join(stateDir, 'requests.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)) }
  }
  const states = result => Object.fromEntries(result.receipts.map(row => [row.step, row.state]))

  const a = harness(false)
  let res = await a.run([a.add])
  ok(a.termsAsked.join() === 'wss://buzz.example', "a delegate's request reads the hive's terms from the template's hive relay")
  const first = a.ledger().find(row => row.op === 'add_agent')
  ok(first.owner === ownerHex && first.signer === delHex, 'the ledger records the grantor as owner and the delegate as signer')
  res = await a.run([a.add, a.bindEv])
  ok(states(res).started === 'refused' && /needs the channel key staged/.test(res.receipts.find(r => r.step === 'started').detail), "a delegate's bind with no staged key is refused, and nothing is seated")

  const b = harness(true)
  await b.run([b.add])
  writeFileSync(join(b.stateDir, `${b.add.id}.staged-channel.pub`), `${KEY} nvoy-stage:hr:${b.add.id}\n`)
  res = await b.run([b.add, b.bindEv])
  ok(states(res).started === 'done', 'with the staged key matching the bind, the delegate\'s bind is seated')

  const c = harness(false)
  await c.run([c.add])
  writeFileSync(join(c.stateDir, `${c.add.id}.staged-channel.pub`), `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0${'b'.repeat(40)} nvoy-stage:hr:${c.add.id}\n`)
  res = await c.run([c.add, c.bindEv])
  ok(states(res).started === 'refused', "a staged key that differs from the delegate's bind is refused")
}

// ── The hive join opens a delegate's invite with the delegate's key ─────────────────────────────
{
  const { joinHive } = await import('../mcp/tools/onboard_join.mjs')
  let from = null
  const signer = { nip44Decrypt: async (pk) => { from = pk; return '' } }
  await joinHive({ add: { owner: ownerHex, signer: delHex, invite: 'x' }, relay: 'wss://buzz.example', signer, open: async () => { throw new Error('AUTH refused: not a member') } })
  ok(from === delHex, "a delegate's invite is opened as sealed by the delegate")
  await joinHive({ add: { owner: ownerHex, invite: 'x' }, relay: 'wss://buzz.example', signer, open: async () => { throw new Error('AUTH refused: not a member') } })
  ok(from === ownerHex, "an owner's invite is opened as sealed by the owner, as before")
}

console.log(`\nonboard-delegate-auth: ${n} passed`)
