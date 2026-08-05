// Closed-schema, content-free notification carried across the keyed broker -> keyless Desktop
// boundary. It proves that a configured, separately-authorized carrier delivered a valid signed
// channel event. It deliberately carries no source text and grants no reply or task capability.

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export function validateVerifiedNotification(record, { instance = '', grantors = [], carriers = [] } = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('verified notification must be an object')
  const keys = ['type', 'instance', 'envelope', 'notification']
  if (Object.keys(record).some(key => !keys.includes(key)) || record.type !== 'verified-notification' ||
      (instance && record.instance !== instance) || !HEX64.test(String(record.envelope || ''))) throw new Error('invalid verified notification')
  const n = record.notification
  const noticeKeys = ['version', 'type', 'source_author', 'source_event', 'source_channel', 'carrier',
    'carrier_grant_id', 'carrier_grantor', 'reason', 'observed_at']
  if (!n || typeof n !== 'object' || Array.isArray(n) || Object.keys(n).some(key => !noticeKeys.includes(key)) ||
      n.version !== 1 || n.type !== 'verified-channel-activity' || !HEX64.test(String(n.source_author || '')) ||
      !HEX64.test(String(n.source_event || '')) || !UUID.test(String(n.source_channel || '')) ||
      !HEX64.test(String(n.carrier || '')) || !HEX64.test(String(n.carrier_grant_id || '')) ||
      !HEX64.test(String(n.carrier_grantor || '')) || !['mention', 'reply'].includes(n.reason) ||
      !Number.isFinite(Number(n.observed_at)) || Number(n.observed_at) <= 0) throw new Error('invalid verified notification provenance')
  const carrier = carriers.find(entry => entry.pubkey === n.carrier)
  if (!carrier || !carrier.channels.includes(n.source_channel) ||
      (grantors.length && !grantors.includes(n.carrier_grantor))) throw new Error('notification is outside the configured carrier boundary')
  return { trustedInstruction: false, notification: n }
}
