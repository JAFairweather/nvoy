import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { baselineDesktopQueue, deliverPending } from '../mcp/tools/macos_desktop_adapter.mjs'

let passed = 0, failed = 0
const ok = (name, value) => { if (value) { passed++; console.log(`ok - ${name}`) } else { failed++; console.error(`not ok - ${name}`) } }
const sender = getPublicKey(generateSecretKey()), agent = getPublicKey(generateSecretKey()), grantor = getPublicKey(generateSecretKey()), carrier = getPublicKey(generateSecretKey())
const channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e', envelope = 'a'.repeat(64)
const policy = { instance: 'codex-jaf', scopeSubject: agent, grantors: [grantor], carriers: [{ pubkey: carrier, channels: [channel] }] }
const task = { type: 'admitted-task', instance: 'codex-jaf', envelope, messages: [{ from: sender, at: 1, content: 'Visible instruction.', event_id: 'b'.repeat(64), kind: 9 }], authority: {
  version: 2, type: 'scoped-instruction', sender, grant_id: 'c'.repeat(64), grantor, cap: 'task', scope_subject: agent, policy_checked_at: 1,
  carrier, carrier_grant_id: 'd'.repeat(64), carrier_grantor: grantor, source_event: 'b'.repeat(64), reply_channel: channel,
} }
const binding = { appBundleId: 'com.openai.codex', projectLabel: 'connect', chatLabel: 'Waggle live binder',
  threadId: '019fce57-063d-7f50-b837-967d33ee384a', statePath: '/tmp/.codex-global-state.json' }
const dir = mkdtempSync(join(tmpdir(), 'nvoy-macos-adapter-')), queuePath = join(dir, 'queue.jsonl'), baselinePath = join(dir, 'baseline.jsonl'), visiblePath = join(dir, 'visible.jsonl'), completedPath = join(dir, 'completed.jsonl')
writeFileSync(queuePath, JSON.stringify(task) + '\n', { mode: 0o600 })
let calls = 0, observations = 0, replies = 0
const invoke = async request => { calls++; return { version: 1, status: 'visible', envelope: request.envelope,
  app_bundle_id: request.app_bundle_id, project_label: request.project_label, chat_label: request.chat_label, thread_id: request.thread_id,
  receipt: request.receipt, message_sha256: request.message_sha256, project_chat_count: 1,
  active_chat_count: 1, composer_count: 1, visible_match_count: 1 } }
const observe = async () => { observations++; return 'Desktop answer.' }
const queueReply = async request => { replies++; ok('reply stays receipt-bound', request.envelope === envelope && request.content === 'Desktop answer.') }
const first = await deliverPending({ queuePath, baselinePath, visiblePath, completedPath, binding, policy, invoke, observe, queueReply })
ok('one broker-admitted instruction is visibly delivered', first.delivered === 1 && first.replied === 1)
ok('visible evidence is durably journaled', JSON.parse(readFileSync(visiblePath, 'utf8')).envelope === envelope)
ok('completion is journaled only after reply queueing', JSON.parse(readFileSync(completedPath, 'utf8')).status === 'completed' && replies === 1)
const replay = await deliverPending({ queuePath, baselinePath, visiblePath, completedPath, binding, policy, invoke, observe, queueReply })
ok('restart/replay never invokes, observes, or replies twice', replay.delivered === 0 && replay.replied === 0 && calls === 1 && observations === 1 && replies === 1)
writeFileSync(queuePath, JSON.stringify({ ...task, envelope: 'e'.repeat(64), authority: null }) + '\n', { mode: 0o600 })
const ignored = await deliverPending({ queuePath, baselinePath, visiblePath, completedPath, binding, policy, invoke, observe, queueReply })
ok('data-only admitted records never reach Accessibility', ignored.delivered === 0 && calls === 1)
writeFileSync(queuePath, JSON.stringify({ ...task, envelope: 'f'.repeat(64) }) + '\n', { mode: 0o600 })
try { await deliverPending({ queuePath, baselinePath, visiblePath, completedPath, binding, policy, observe, queueReply, invoke: async request => ({ version: 1, status: 'visible', envelope: request.envelope, app_bundle_id: request.app_bundle_id, project_label: request.project_label, chat_label: request.chat_label, thread_id: request.thread_id, receipt: request.receipt, message_sha256: request.message_sha256, project_chat_count: 1, active_chat_count: 1, composer_count: 2, visible_match_count: 1 }) }); ok('ambiguous UI evidence is never journaled', false) } catch { ok('ambiguous UI evidence is never journaled', true) }

// Crash after visible proof but before a final answer: restart must observe, never inject again.
writeFileSync(queuePath, JSON.stringify({ ...task, envelope: '1'.repeat(64) }) + '\n', { mode: 0o600 })
writeFileSync(visiblePath, JSON.stringify({ version: 1, status: 'visible', envelope: '1'.repeat(64) }) + '\n', { mode: 0o600 })
writeFileSync(completedPath, '', { mode: 0o600 })
calls = 0; observations = 0; replies = 0
const recovered = await deliverPending({ queuePath, baselinePath, visiblePath, completedPath, binding, policy, invoke, observe, queueReply: async () => { replies++ } })
ok('post-submit crash resumes observation without duplicate injection', recovered.delivered === 0 && recovered.replied === 1 && calls === 0 && observations === 1 && replies === 1)

// Installation baselines every existing validated record; later drains ignore history.
const historic = '2'.repeat(64)
writeFileSync(queuePath, JSON.stringify({ ...task, envelope: historic }) + '\n', { mode: 0o600 })
writeFileSync(baselinePath, '', { mode: 0o600 }); writeFileSync(visiblePath, '', { mode: 0o600 }); writeFileSync(completedPath, '', { mode: 0o600 })
ok('installation baselines existing queue history', baselineDesktopQueue({ queuePath, baselinePath, policy }) === 1)
calls = 0
const afterBaseline = await deliverPending({ queuePath, baselinePath, visiblePath, completedPath, binding, policy, invoke, observe, queueReply })
ok('baselined history is never visibly replayed', afterBaseline.delivered === 0 && afterBaseline.replied === 0 && calls === 0)
console.log(`${passed}/${passed + failed} passed`)
if (failed) process.exit(1)
