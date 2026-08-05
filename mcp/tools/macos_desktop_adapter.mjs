import { appendFileSync, closeSync, existsSync, fsyncSync, lstatSync, openSync, readFileSync } from 'node:fs'
import { desktopDeliveryRequest, verifyDesktopEvidence } from './macos_desktop_delivery.mjs'
import { validateAdmittedTask, validateDesktopDelivery } from './admitted_task.mjs'

const HEX64 = /^[0-9a-f]{64}$/

function regularRecords(path, label, maxBytes = 32 * 1024 * 1024) {
  if (!existsSync(path)) return []
  const stat = lstatSync(path)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) throw new Error(`${label} must be a bounded regular non-symlink file`)
  return readFileSync(path, 'utf8').split('\n').flatMap(line => {
    if (!line.trim()) return []
    try { return [JSON.parse(line)] } catch { throw new Error(`${label} contains invalid JSON`) }
  })
}

function durableAppend(path, record) {
  const fd = openSync(path, 'a', 0o600)
  try {
    appendFileSync(fd, JSON.stringify(record) + '\n')
    fsyncSync(fd)
  } finally { closeSync(fd) }
}

export function journaledEnvelopes(path, expectedStatus) {
  return new Set(regularRecords(path, 'Desktop delivery journal').map(record => {
    if (record?.version !== 1 || record?.status !== expectedStatus || !HEX64.test(String(record.envelope || ''))) {
      throw new Error('Desktop delivery journal contains an invalid record')
    }
    return record.envelope
  }))
}

export function baselineDesktopQueue({ queuePath, baselinePath, policy }) {
  const seen = journaledEnvelopes(baselinePath, 'baseline')
  let baselined = 0
  for (const record of regularRecords(queuePath, 'admitted task queue')) {
    validateDesktopDelivery(record, policy)
    if (seen.has(record.envelope)) continue
    durableAppend(baselinePath, { version: 1, status: 'baseline', envelope: record.envelope, baselined_at: Date.now() })
    seen.add(record.envelope); baselined++
  }
  return baselined
}

export async function deliverPending({ queuePath, baselinePath, visiblePath, completedPath, binding, policy, invoke, observe, queueReply }) {
  if (typeof invoke !== 'function') throw new Error('Desktop driver invocation is required')
  if (typeof observe !== 'function' || typeof queueReply !== 'function') throw new Error('Desktop observer and reply queue are required')
  const visible = journaledEnvelopes(visiblePath, 'visible')
  const completed = journaledEnvelopes(completedPath, 'completed')
  const baseline = journaledEnvelopes(baselinePath, 'baseline')
  let delivered = 0, replied = 0
  for (const record of regularRecords(queuePath, 'admitted task queue')) {
    if (baseline.has(record?.envelope) || completed.has(record?.envelope)) continue
    if (record?.type === 'verified-notification') { validateDesktopDelivery(record, policy); continue }
    const checked = validateAdmittedTask(record, policy)
    if (!checked.trustedInstruction) continue
    const request = desktopDeliveryRequest(record, binding, policy)
    if (!visible.has(record.envelope)) {
      const evidence = await invoke(request)
      const verified = verifyDesktopEvidence(request, evidence)
      // The visible receipt is durable external evidence. Journal it before observing the turn;
      // a crash after this append resumes observation without injecting a duplicate user bubble.
      const row = { version: 1, status: 'visible', envelope: verified.envelope, receipt: verified.receipt,
        message_sha256: verified.messageSha256, app_bundle_id: verified.appBundleId,
        project_label: verified.projectLabel, chat_label: verified.chatLabel, delivered_at: Date.now() }
      durableAppend(visiblePath, row)
      visible.add(record.envelope)
      delivered++
    }
    const finalText = String(await observe(request)).trim()
    if (!finalText || Buffer.byteLength(finalText) > 4000) throw new Error('Desktop final response is empty or exceeds the Nostr reply bound')
    // queueReply must itself be durable and receipt-deduplicated. Only after it returns may the
    // completion journal suppress future observation of this visible turn.
    await queueReply({ envelope: record.envelope, content: finalText })
    durableAppend(completedPath, { version: 1, status: 'completed', envelope: record.envelope, completed_at: Date.now() })
    completed.add(record.envelope)
    replied++
  }
  return { delivered, replied }
}
