// Validation shared by every keyless admitted-task transport boundary. Authority is produced
// only by the keyed broker after live grant verification; legacy records without it remain
// notifications/data, while a malformed or mismatched attestation is rejected outright.

const HEX64 = /^[0-9a-f]{64}$/
const TASK_CAPS = new Set(['task', 'task+act'])

export function validateAdmittedTask(record, { instance = '', scopeSubject = '', grantors = [] } = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('admitted task must be an object')
  const allowed = ['type', 'instance', 'envelope', 'messages', 'received_at', 'authority']
  if (Object.keys(record).some(key => !allowed.includes(key)) || record.type !== 'admitted-task' ||
      (instance && record.instance !== instance) || !HEX64.test(String(record.envelope || '')) ||
      !Array.isArray(record.messages) || !record.messages.length || record.messages.length > 64) throw new Error('invalid admitted task')
  for (const message of record.messages) {
    if (!message || typeof message !== 'object' || Array.isArray(message) ||
        Object.keys(message).some(key => !['from', 'transport_from', 'at', 'content', 'event_id', 'kind', 'relay_channel'].includes(key)) ||
        !HEX64.test(String(message.from || '')) || !Number.isFinite(Number(message.at)) ||
        typeof message.content !== 'string' || Buffer.byteLength(message.content) > 256 * 1024 ||
        (message.transport_from != null && !HEX64.test(String(message.transport_from))) ||
        (message.event_id != null && !HEX64.test(String(message.event_id))) ||
        (message.kind != null && message.kind !== 9) ||
        (message.relay_channel != null && !/^[0-9a-f-]{0,128}$/i.test(String(message.relay_channel)))) throw new Error('invalid admitted message')
  }
  if (record.authority == null) return { trustedInstruction: false }
  const a = record.authority
  const authorityKeys = ['version', 'type', 'sender', 'grant_id', 'grantor', 'cap', 'scope_subject', 'policy_checked_at']
  if (!a || typeof a !== 'object' || Array.isArray(a) || Object.keys(a).some(key => !authorityKeys.includes(key)) ||
      a.version !== 1 || a.type !== 'scoped-instruction' || !HEX64.test(String(a.sender || '')) ||
      !HEX64.test(String(a.grant_id || '')) || !HEX64.test(String(a.grantor || '')) ||
      !TASK_CAPS.has(a.cap) || !HEX64.test(String(a.scope_subject || '')) ||
      !Number.isFinite(Number(a.policy_checked_at)) || Number(a.policy_checked_at) <= 0 ||
      record.messages.some(message => message.from !== a.sender) ||
      (scopeSubject && a.scope_subject !== scopeSubject) ||
      (grantors.length && !grantors.includes(a.grantor))) throw new Error('invalid admitted authority')
  return { trustedInstruction: true, authority: a }
}
