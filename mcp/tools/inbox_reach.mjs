// inbox_reach.mjs — decide whether an inbox read is a RESULT or merely a silence (#382).
//
// "No messages" and "I could not see whether there are messages" print identically and read
// identically, and only one of them is good news. Everything here exists to keep them apart, as
// a pure function so both directions can be asserted without a live signer or a live relay.

// A wrap that is simply not addressed to this key fails inside nip44 with a decrypt error — that
// is the normal case and says nothing. A NIP-46 signer failing is different: something was shown
// to this run and it was not permitted, or not able, to look. Those come back in exactly three
// shapes from nip46-signer.mjs — a remote refusal (`bunker: <error>`), a timeout, and a closed
// signer. Matching the shape rather than "any error" is the whole point: broadening this to catch
// everything would mark every foreign wrap as a refusal and make the tool cry wolf on every run.
export const isSignerFault = reason =>
  /^bunker: /.test(String(reason ?? '')) || /^nip46 .*(timed out|closed)$/.test(String(reason ?? ''))

// Returns { code, inconclusive[], notes[] }. code is 0 or 3; the caller owns exit 1
// (misconfiguration), which is decided long before anything here is known.
export function inboxVerdict({
  signerRefusals = [], envelopesSeen = 0, reachedWraps = [], relayCount = 0,
  unreachable = [], answered10050 = [], dmRelayLists = 0, total = 0,
} = {}) {
  const inconclusive = [], notes = []

  if (signerRefusals.length) {
    inconclusive.push(`the signer refused or failed on ${signerRefusals.length} of ${envelopesSeen} envelope(s), ` +
      `so an unknown number of messages were never opened — first: ${signerRefusals[0]}`)
  }
  if (!reachedWraps.length) {
    inconclusive.push(`no relay answered the message query, so nothing was read — ${unreachable.join('; ') || 'no relays configured'}`)
  }
  // Only when the read came back empty. A kind:10050 is where a sender is told to deliver; without
  // one, an empty inbox is not evidence of an empty inbox — it is an address nobody could reach.
  // If messages DID arrive, the absent list is a curiosity, not a doubt, so it drops to a note.
  if (!total && answered10050.length && !dmRelayLists) {
    inconclusive.push('this identity publishes no kind:10050 DM relay list, so a sender has nowhere to deliver to. ' +
      'That is not an empty inbox, it is an unreachable one')
  }
  if (reachedWraps.length && unreachable.length) {
    notes.push(`partial reach: ${reachedWraps.length}/${relayCount} relay(s) answered — ${unreachable.join('; ')}`)
  }
  if (total && answered10050.length && !dmRelayLists) {
    notes.push('no kind:10050 for this identity, yet messages arrived — senders are reaching you by some other route')
  }

  return { code: inconclusive.length ? 3 : 0, inconclusive, notes }
}
