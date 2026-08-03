// consent-publish.mjs — the completion condition for a mirror-consent click-through.
//
// A relay ACK says it accepted an event, not that the event is available to read.  The participant
// is told their consent took effect only after a fresh query returns the exact signed 440 and its
// signature verifies again on the way back.

import { verifyEvent } from 'nostr-tools'

export async function publishAndReadBack(relay, signed, verify = verifyEvent) {
  const receipt = await relay.publish(signed)
  const events = await relay.query({ ids: [signed.id], limit: 1 })
  const observed = events.find(event => event?.id === signed.id)
  if (!observed) throw new Error('relay accepted the consent but it was not readable back yet; nothing is claimed as complete')
  if (!verify(observed)) throw new Error('relay returned the consent but its signature did not verify')
  if (observed.pubkey !== signed.pubkey || observed.kind !== 440) throw new Error('relay returned an event that does not match the signed consent')
  return receipt
}
