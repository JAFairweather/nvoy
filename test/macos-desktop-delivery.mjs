import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { desktopDeliveryRequest, verifyDesktopEvidence, visibleReceipt } from '../mcp/tools/macos_desktop_delivery.mjs'
import { verifySelectedDesktopProject } from '../mcp/tools/codex_desktop_selection.mjs'

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
const threadId = '019fce57-063d-7f50-b837-967d33ee384a'
const binding = { appBundleId: 'com.openai.codex', projectLabel: 'connect', chatLabel: 'Waggle live binder',
  threadId, statePath: '/tmp/.codex-global-state.json' }
const request = desktopDeliveryRequest(task, binding, policy)
ok('authenticated words remain first', request.text.startsWith('Do the visible thing.\n\n—'))
ok('visible non-secret receipt binds the envelope', request.receipt === visibleReceipt(envelope) && request.text.endsWith(request.receipt))
ok('request fixes app, project, chat, thread, state path, and message digest', request.app_bundle_id === 'com.openai.codex' && request.project_label === 'connect' && request.chat_label === 'Waggle live binder' && request.thread_id === threadId && request.codex_state_path === binding.statePath && /^[0-9a-f]{64}$/.test(request.message_sha256))
const evidence = { version: 1, status: 'visible', envelope, app_bundle_id: request.app_bundle_id, project_label: request.project_label,
  chat_label: request.chat_label, thread_id: request.thread_id, receipt: request.receipt, message_sha256: request.message_sha256,
  project_chat_count: 1, active_chat_count: 1, composer_count: 1, visible_match_count: 1 }
ok('one exact visible bubble is accepted', verifyDesktopEvidence(request, evidence).envelope === envelope)
const nativeSource = readFileSync(new URL('../mcp/tools/codex-macos-ui.swift', import.meta.url), 'utf8')
const adapterSource = readFileSync(new URL('../mcp/tools/codex-macos-desktop-adapter.mjs', import.meta.url), 'utf8')
const selectionSource = readFileSync(new URL('../mcp/tools/codex_desktop_selection.mjs', import.meta.url), 'utf8')
ok('project-qualified sidebar task and active header are independently required',
  /let projectChats = named\.filter/.test(nativeSource) && /let active = named\.compactMap/.test(nativeSource))
ok('selected-project proof precedes every native binder invocation',
  adapterSource.indexOf('verifySelectedDesktopProject({') < adapterSource.indexOf('spawnSync(manifest.codexUiDriver'))
ok('native binder revalidates selected project after staging and before Send', (() => {
  const checks = [...nativeSource.matchAll(/selectedProjectIsBound\(request\)/g)].map(match => match.index)
  return checks.length === 3 && checks[0] < nativeSource.indexOf('request.text as CFTypeRef') &&
    checks[1] > nativeSource.indexOf('let send = ready.filter') && checks[1] < nativeSource.indexOf('kAXPressAction') &&
    checks[2] > nativeSource.indexOf('usleep(300_000)') && checks[2] < nativeSource.indexOf('kAXConfirmAction')
})())
ok('native selection proof is itself descriptor-pinned and no-follow',
  /Darwin\.open\(request\.codex_state_path, O_RDONLY \| O_NOFOLLOW\)/.test(nativeSource) &&
  /fstat\(fd, &info\)/.test(nativeSource) && /Darwin\.read\(fd/.test(nativeSource))
ok('Desktop state validation and reading are pinned to one no-follow descriptor',
  /openSync\(path, constants\.O_RDONLY \| constants\.O_NOFOLLOW\)/.test(selectionSource) &&
  /fstatSync\(fd\)/.test(selectionSource) && /readFileSync\(fd, 'utf8'\)/.test(selectionSource) &&
  !/readFileSync\(path/.test(selectionSource))
ok('Electron semantic accessibility is enabled before the focused window is inspected', (() => {
  const enable = nativeSource.indexOf('"AXManualAccessibility" as CFString')
  const inspect = nativeSource.indexOf('kAXFocusedWindowAttribute')
  return enable >= 0 && inspect > enable && nativeSource.includes('usleep(500_000)')
})())
ok('background delivery requires one Codex process but never steals or requires OS focus',
  nativeSource.includes('apps.count == 1') &&
  !nativeSource.includes('frontmostApplication') && !nativeSource.includes('app.isActive') &&
  !nativeSource.includes('activate(options:'))
ok('whitespace-only AX composer state is empty without permitting draft overwrite',
  nativeSource.includes('trimmingCharacters(in: .whitespacesAndNewlines)') &&
  nativeSource.includes('let composerIsEmpty = normalizedComposer.isEmpty'))
ok('an AX value equal to its non-empty native placeholder is not mistaken for a user draft',
  nativeSource.includes('!composerPlaceholder.isEmpty && composerValue == composerPlaceholder'))
ok('Chromium semantic placeholder values are accepted only when they equal the composer description',
  nativeSource.includes('!composerDescription.isEmpty && normalizedComposer == composerDescription'))
ok('a background Send fallback confirms only the exact bound composer, never global keyboard input',
  nativeSource.includes('if value(composers[0]) == request.text') &&
  nativeSource.includes('kAXConfirmAction') && !nativeSource.includes('CGEvent'))
const fallbackInvariant = source => {
  const wait = source.indexOf('usleep(300_000)')
  const rebind = source.indexOf('selectedProjectIsBound(request)', wait)
  const reinspect = source.indexOf('let rebound = inspect()', wait)
  const sameComposer = source.indexOf('CFEqual(rebound.2[0].element, composers[0].element)', wait)
  const confirm = source.indexOf('kAXConfirmAction', wait)
  return wait >= 0 && rebind > wait && reinspect > rebind && sameComposer > reinspect && confirm > sameComposer
}
ok('fallback wait re-proves project, active chat, and the same composer immediately before AXConfirm',
  fallbackInvariant(nativeSource))
ok('NEGATIVE CONTROL — removing the post-wait project proof breaks the fallback invariant',
  !fallbackInvariant(nativeSource.replace('guard selectedProjectIsBound(request) else {\n    clearExactStagedText()', 'guard true else {\n    clearExactStagedText()')))
const noReceipt = nativeSource.indexOf('guard matches == 1 else')
ok('a no-receipt timeout clears only the exact text this binder staged before failing',
  noReceipt >= 0 && nativeSource.indexOf('clearExactStagedText()', noReceipt) > noReceipt &&
  nativeSource.indexOf('fail("one exact visible receipt was not observed")', noReceipt) >
    nativeSource.indexOf('clearExactStagedText()', noReceipt))
for (const [name, mutate] of [
  ['wrong app fails closed', x => { x.app_bundle_id = 'com.apple.TextEdit' }],
  ['wrong project fails closed', x => { x.project_label = 'other' }],
  ['wrong chat fails closed', x => { x.chat_label = 'other' }],
  ['wrong thread fails closed', x => { x.thread_id = '019fce56-7a71-7f82-9eff-efc731c8bdc6' }],
  ['configured chat present but inactive fails closed', x => { x.active_chat_count = 0 }],
  ['configured chat outside its project fails closed', x => { x.project_chat_count = 0 }],
  ['missing composer fails closed', x => { x.composer_count = 0 }],
  ['ambiguous composer fails closed', x => { x.composer_count = 2 }],
  ['missing visible bubble fails closed', x => { x.visible_match_count = 0 }],
  ['duplicate visible bubble fails closed', x => { x.visible_match_count = 2 }],
  ['altered message digest fails closed', x => { x.message_sha256 = '0'.repeat(64) }],
]) throws(name, () => { const bad = structuredClone(evidence); mutate(bad); verifyDesktopEvidence(request, bad) })
throws('notification cannot reach the binder', () => desktopDeliveryRequest({ type: 'verified-notification' }, binding, policy))
throws('unauthorized admitted-shaped data cannot reach the binder', () => desktopDeliveryRequest({ ...task, authority: null }, binding, policy))
throws('network input cannot select another application', () => desktopDeliveryRequest(task, { ...binding, appBundleId: 'com.apple.TextEdit' }, policy))
const stateDir = mkdtempSync(join(tmpdir(), 'nvoy-codex-selection-'))
const statePath = join(stateDir, 'state.json')
const projectId = '47ad8e40-4c29-4e97-9b31-69903dc37e4e'
const selectedState = {
  'selected-project': { type: 'local', projectId },
  'thread-project-assignments': { [threadId]: { projectKind: 'local', projectId, cwd: '/workspace/connect' } },
  'local-projects': { [projectId]: { id: projectId, name: 'connect', rootPaths: ['/workspace/connect'] } },
}
writeFileSync(statePath, JSON.stringify(selectedState), { mode: 0o600 })
ok('immutable thread is accepted only in its selected project',
  verifySelectedDesktopProject({ statePath, threadId, projectLabel: 'connect' }).projectId === projectId)
for (const [name, mutate] of [
  ['another selected project fails closed', x => { x['selected-project'].projectId = 'other' }],
  ['thread assigned to another project fails closed', x => { x['thread-project-assignments'][threadId].projectId = 'other' }],
  ['wrong project label fails closed', x => { x['local-projects'][projectId].name = 'other' }],
  ['thread outside the project root fails closed', x => { x['thread-project-assignments'][threadId].cwd = '/workspace/other' }],
]) throws(name, () => {
  const bad = structuredClone(selectedState); mutate(bad); writeFileSync(statePath, JSON.stringify(bad), { mode: 0o600 })
  verifySelectedDesktopProject({ statePath, threadId, projectLabel: 'connect' })
})
writeFileSync(statePath, JSON.stringify(selectedState), { mode: 0o600 })
const linkPath = join(stateDir, 'state-link.json'); symlinkSync(statePath, linkPath)
throws('symlinked Desktop state fails closed', () => verifySelectedDesktopProject({ statePath: linkPath, threadId, projectLabel: 'connect' }))
console.log(`${passed}/${passed + failed} passed`)
if (failed) process.exit(1)
