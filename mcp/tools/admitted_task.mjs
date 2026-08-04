// Validation shared by every keyless admitted-task transport boundary. Authority is produced
// only by the keyed broker after live grant verification; legacy records without it remain
// notifications/data, while a malformed or mismatched attestation is rejected outright.

const HEX64 = /^[0-9a-f]{64}$/
const TASK_CAPS = new Set(['task', 'task+act'])

export function validateAdmittedTask(record, { instance = '', scopeSubject = '', grantors = [], carriers = [] } = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('admitted task must be an object')
  const allowed = ['type', 'instance', 'envelope', 'messages', 'received_at', 'authority']
  if (Object.keys(record).some(key => !allowed.includes(key)) || record.type !== 'admitted-task' ||
      (instance && record.instance !== instance) || !HEX64.test(String(record.envelope || '')) ||
      !Array.isArray(record.messages) || !record.messages.length || record.messages.length > 64) throw new Error('invalid admitted task')
  for (const message of record.messages) {
    if (!message || typeof message !== 'object' || Array.isArray(message) ||
        Object.keys(message).some(key => !['from', 'at', 'content', 'event_id', 'kind'].includes(key)) ||
        !HEX64.test(String(message.from || '')) || !Number.isFinite(Number(message.at)) ||
        typeof message.content !== 'string' || Buffer.byteLength(message.content) > 256 * 1024) throw new Error('invalid admitted message')
  }
  if (record.authority == null) return { trustedInstruction: false }
  const a = record.authority
  const v1Keys = ['version', 'type', 'sender', 'grant_id', 'grantor', 'cap', 'scope_subject', 'policy_checked_at']
  const v2Keys = [...v1Keys, 'carrier', 'carrier_grant_id', 'carrier_grantor', 'source_event', 'reply_channel']
  const authorityKeys = a.version === 2 ? v2Keys : v1Keys
  if (!a || typeof a !== 'object' || Array.isArray(a) || Object.keys(a).some(key => !authorityKeys.includes(key)) ||
      ![1, 2].includes(a.version) || a.type !== 'scoped-instruction' || !HEX64.test(String(a.sender || '')) ||
      !HEX64.test(String(a.grant_id || '')) || !HEX64.test(String(a.grantor || '')) ||
      !TASK_CAPS.has(a.cap) || !HEX64.test(String(a.scope_subject || '')) ||
      !Number.isFinite(Number(a.policy_checked_at)) || Number(a.policy_checked_at) <= 0 ||
      record.messages.some(message => message.from !== a.sender) ||
      (scopeSubject && a.scope_subject !== scopeSubject) ||
      (grantors.length && !grantors.includes(a.grantor))) throw new Error('invalid admitted authority')
  if (a.version === 2) {
    const carrier = carriers.find(entry => entry.pubkey === a.carrier)
    if (!HEX64.test(String(a.carrier || '')) || !HEX64.test(String(a.carrier_grant_id || '')) ||
        !HEX64.test(String(a.carrier_grantor || '')) || !HEX64.test(String(a.source_event || '')) ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(String(a.reply_channel || '')) ||
        !carrier || !carrier.channels.includes(a.reply_channel) ||
        (grantors.length && !grantors.includes(a.carrier_grantor)) ||
        record.messages.some(message => message.event_id !== a.source_event || message.kind !== 9)) {
      throw new Error('invalid channel-carried authority')
    }
  }
  return { trustedInstruction: true, authority: a }
}
