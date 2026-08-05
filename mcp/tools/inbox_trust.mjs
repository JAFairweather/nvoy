// Trust partition for the human-readable inbox. A configured transport carrier is never a
// direct instructor: a valid typed carry is verified data from its signed source, while any
// rejected/malformed carrier payload stays quarantined even if an operator accidentally also
// listed that carrier in trusted-senders.json.
//
// A carrier also sends messages that are not carries at all — a delivery receipt for something
// you sent, or a reply relayed back out of the community. Those are its OWN notices. Filing them
// as "rejected carrier" states a verdict their contents contradict: an agent checking whether its
// message landed reads REJECTED directly above `{"ok":true}`, and the two honest readings of that
// are "it failed" and "the carrier is misbehaving" — both wrong. Worse, it left the verified
// section permanently empty, so nothing ever meant "this arrived through the sanctioned lane."
//
// So carrier traffic splits three ways, and NONE of them is actionable:
//   verified        a typed carry that verified — data from its signed source
//   rejectedCarrier it CLAIMED to be a carry and failed — genuinely rejected
//   carrierNotice   it never claimed to be a carry — the carrier's own notice
// Authority is unchanged by this split. `carrierNotice` is data-only, exactly as
// `rejectedCarrier` was; the only thing that changes is that the label is now true.

import { claimsChannelCarry } from './channel_task_carry.mjs'

export function partitionInboxMessages(messages, { trusted = {}, carriers = [], claims = claimsChannelCarry } = {}) {
  const carrierSet = new Set(carriers.map(value => String(value || '').toLowerCase()))
  const verified = []
  const trustedDirect = []
  const rejectedCarrier = []
  const carrierNotice = []
  const untrusted = []

  for (const message of messages) {
    if (message?.verifiedData) { verified.push(message); continue }
    const sender = String(message?.from || '').toLowerCase()
    if (carrierSet.has(sender)) {
      // Attempted a carry and did not verify → rejected. Never attempted one → its own
      // notice. A carrier stays a non-instructor in both cases.
      if (claims(message)) rejectedCarrier.push(message)
      else carrierNotice.push(message)
      continue
    }
    if (trusted[sender]) trustedDirect.push(message)
    else untrusted.push(message)
  }

  return { verified, trustedDirect, rejectedCarrier, carrierNotice, untrusted }
}
