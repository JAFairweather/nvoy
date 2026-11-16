// Closed-schema, content-free notification carried across the keyed broker -> keyless Desktop
// boundary. It proves that a configured, separately-authorized carrier delivered a valid signed
// channel event. It deliberately carries no source text and grants no reply or task capability.

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

// q-198: the native broker refused a mention of this identity, and says so without its content. It rides
// in this same envelope, so every queue reader already treats it as a content-free notification that
// grants no reply. The envelope is the refused event itself.
function validateUnadmittedMention(record, n, { buzz = null } = {}) {
  const keys = ['version', 'type', 'source_author', 'source_event', 'source_channel', 'reason', 'observed_at']
  if (Object.keys(n).some(key => !keys.includes(key)) || n.version !== 1 || !HEX64.test(String(n.source_author || '')) ||
      !HEX64.test(String(n.source_event || '')) || n.source_event !== record.envelope || !UUID.test(String(n.source_channel || '')) ||
      !['no-grant', 'no-grant-suspect', 'dm-not-owner'].includes(n.reason) ||
      !Number.isFinite(Number(n.observed_at)) || Number(n.observed_at) <= 0) throw new Error('invalid unadmitted-mention notice')
  // Only a native broker refuses this way. A configured channel is where a grant was missing; a DM is never
  // a configured channel, and the broker reads which channels are DMs from the relay itself.
  const configured = Array.isArray(buzz?.channels) && buzz.channels.includes(n.source_channel)
  if (!buzz || (n.reason === 'dm-not-owner' ? configured : !configured)) throw new Error('notice is outside the native channel boundary')
  return { trustedInstruction: false, notification: n }
}

export function validateVerifiedNotification(record, { instance = '', grantors = [], carriers = [], buzz = null } = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('verified notification must be an object')
  const keys = ['type', 'instance', 'envelope', 'notification']
  if (Object.keys(record).some(key => !keys.includes(key)) || record.type !== 'verified-notification' ||
      (instance && record.instance !== instance) || !HEX64.test(String(record.envelope || ''))) throw new Error('invalid verified notification')
  const n = record.notification
  if (n && typeof n === 'object' && !Array.isArray(n) && n.type === 'unadmitted-mention') return validateUnadmittedMention(record, n, { buzz })
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
