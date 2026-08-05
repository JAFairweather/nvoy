// Trust partition for the human-readable inbox. A configured transport carrier is never a
// direct instructor: a valid typed carry is verified data from its signed source, while any
// rejected/malformed carrier payload stays quarantined even if an operator accidentally also
// listed that carrier in trusted-senders.json.

export function partitionInboxMessages(messages, { trusted = {}, carriers = [] } = {}) {
  const carrierSet = new Set(carriers.map(value => String(value || '').toLowerCase()))
  const verified = []
  const trustedDirect = []
  const rejectedCarrier = []
  const untrusted = []

  for (const message of messages) {
    if (message?.verifiedData) { verified.push(message); continue }
    const sender = String(message?.from || '').toLowerCase()
    if (carrierSet.has(sender)) { rejectedCarrier.push(message); continue }
    if (trusted[sender]) trustedDirect.push(message)
    else untrusted.push(message)
  }

  return { verified, trustedDirect, rejectedCarrier, untrusted }
}
