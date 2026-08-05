import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { desktopDeliveryRequest, verifyDesktopEvidence, visibleReceipt } from '../mcp/tools/macos_desktop_delivery.mjs'

let passed = 0, failed = 0
const ok = (name, value) => { if (value) { passed++; console.log(`ok - ${name}`) } else { failed++; console.error(`not ok - ${name}`) } }
const throws = (name, fn) => { try { fn(); ok(name, false) } catch { ok(name, true) } }
const sender = getPublicKey(generateSecretKey()), agent = getPublicKey(generateSecretKey()), grantor = getPublicKey(generateSecretKey()), carrier = getPublicKey(generateSecretKey())
const envelope = 'a'.repeat(64), channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const policy = { instance: 'codex-jaf', scopeSubject: agent, grantors: [grantor], carriers: [{ pubkey: carrier, channels: [channel] }] }
const task = { type: 'admitted-task', instance: 'codex-jaf', envelope, messages: [{ from: sender, at: 1, content: 'Do the visible thing.', event_id: 'b'.repeat(64), kind: 9 }], authority: {
  version: 2, type: 'scoped-instruction', sender, grant_id: 'c'.repeat(64), grantor, cap: 'task', scope_subject: agent, policy_checked_at: 1,
  carrier, carrier_grant_id: 'd'.repeat(64), carrier_grantor: grantor, source_event: 'b'.repeat(64), reply_channel: channel,
} }
const binding = { appBundleId: 'com.openai.codex', projectLabel: 'connect', chatLabel: 'Waggle live binder' }
const request = desktopDeliveryRequest(task, binding, policy)
ok('authenticated words remain first', request.text.startsWith('Do the visible thing.\n\n—'))
ok('visible non-secret receipt binds the envelope', request.receipt === visibleReceipt(envelope) && request.text.endsWith(request.receipt))
ok('request fixes app, project, chat, and message digest', request.app_bundle_id === 'com.openai.codex' && request.project_label === 'connect' && request.chat_label === 'Waggle live binder' && /^[0-9a-f]{64}$/.test(request.message_sha256))
const evidence = { version: 1, status: 'visible', envelope, app_bundle_id: request.app_bundle_id, project_label: request.project_label,
  chat_label: request.chat_label, receipt: request.receipt, message_sha256: request.message_sha256, composer_count: 1, visible_match_count: 1 }
ok('one exact visible bubble is accepted', verifyDesktopEvidence(request, evidence).envelope === envelope)
for (const [name, mutate] of [
  ['wrong app fails closed', x => { x.app_bundle_id = 'com.apple.TextEdit' }],
  ['wrong project fails closed', x => { x.project_label = 'other' }],
  ['wrong chat fails closed', x => { x.chat_label = 'other' }],
  ['missing composer fails closed', x => { x.composer_count = 0 }],
  ['ambiguous composer fails closed', x => { x.composer_count = 2 }],
  ['missing visible bubble fails closed', x => { x.visible_match_count = 0 }],
  ['duplicate visible bubble fails closed', x => { x.visible_match_count = 2 }],
  ['altered message digest fails closed', x => { x.message_sha256 = '0'.repeat(64) }],
]) throws(name, () => { const bad = structuredClone(evidence); mutate(bad); verifyDesktopEvidence(request, bad) })
throws('notification cannot reach the binder', () => desktopDeliveryRequest({ type: 'verified-notification' }, binding, policy))
throws('unauthorized admitted-shaped data cannot reach the binder', () => desktopDeliveryRequest({ ...task, authority: null }, binding, policy))
throws('network input cannot select another application', () => desktopDeliveryRequest(task, { ...binding, appBundleId: 'com.apple.TextEdit' }, policy))
console.log(`${passed}/${passed + failed} passed`)
if (failed) process.exit(1)
