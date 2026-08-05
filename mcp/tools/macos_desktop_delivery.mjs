import { createHash } from 'node:crypto'
import { validateAdmittedTask } from './admitted_task.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const sha256 = value => createHash('sha256').update(value).digest('hex')

export function visibleReceipt(envelope) {
  const id = String(envelope || '').toLowerCase()
  if (!HEX64.test(id)) throw new Error('visible receipt requires a 64-hex envelope')
  return `[nvoy:${id.slice(0, 16)}]`
}

export function visibleDesktopMessage(record, policy = {}) {
  const checked = validateAdmittedTask(record, policy)
  if (!checked.trustedInstruction) throw new Error('Desktop binder requires broker-admitted instruction authority')
  const body = record.messages.map(message => message.content).join('\n\n').trim()
  if (!body || Buffer.byteLength(body) > 256 * 1024) throw new Error('Desktop instruction body is empty or too large')
  const sender = checked.authority.sender
  return `${body}\n\n—\nVerified Nostr instruction from ${sender.slice(0, 12)}… via Waggle/Nvoy.\n${visibleReceipt(record.envelope)}`
}

export function desktopDeliveryRequest(record, binding, policy = {}) {
  const text = visibleDesktopMessage(record, policy)
  if (!binding || binding.appBundleId !== 'com.openai.codex' ||
      typeof binding.projectLabel !== 'string' || !binding.projectLabel.trim() ||
      typeof binding.chatLabel !== 'string' || !binding.chatLabel.trim()) throw new Error('invalid fixed Desktop binding')
  return Object.freeze({ version: 1, envelope: record.envelope, app_bundle_id: binding.appBundleId,
    project_label: binding.projectLabel.trim(), chat_label: binding.chatLabel.trim(),
    receipt: visibleReceipt(record.envelope), message_sha256: sha256(text), text })
}

export function verifyDesktopEvidence(request, evidence) {
  if (!request || !evidence || evidence.version !== 1 || evidence.status !== 'visible' ||
      evidence.envelope !== request.envelope || evidence.app_bundle_id !== request.app_bundle_id ||
      evidence.project_label !== request.project_label || evidence.chat_label !== request.chat_label ||
      evidence.receipt !== request.receipt || evidence.message_sha256 !== request.message_sha256 ||
      evidence.project_chat_count !== 1 || evidence.active_chat_count !== 1 ||
      evidence.composer_count !== 1 || evidence.visible_match_count !== 1) {
    throw new Error('Desktop did not prove one exact visible delivery in the configured chat')
  }
  return Object.freeze({ envelope: request.envelope, receipt: request.receipt,
    messageSha256: request.message_sha256, appBundleId: request.app_bundle_id,
    projectLabel: request.project_label, chatLabel: request.chat_label })
}
