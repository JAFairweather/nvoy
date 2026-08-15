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
  signerRefusals = [], envelopesSeen = 0, opened = 0, reachedWraps = [], relayCount = 0,
  unreachable = [], answered10050 = [], dmRelayLists = 0, total = 0,
  unopened = 0, unopenedByRank = {},
} = {}) {
  const inconclusive = [], notes = []

  if (signerRefusals.length) {
    inconclusive.push(`the signer refused or failed on ${signerRefusals.length} of ${envelopesSeen} envelope(s), ` +
      `so an unknown number of messages were never opened — first: ${signerRefusals[0]}`)
  }
  // The classifier above matches three known shapes. There is a fourth it cannot match:
  // nip46-signer.mjs rejects verbatim whatever `pool.publish` threw, and its `finalizeEvent` /
  // `nip44.encrypt` calls sit outside that try, so an arbitrary "WebSocket is not open" rejects an
  // RPC with no recognisable prefix. Every such failure was counted as somebody else's wrap and
  // the run exited 0.
  //
  // This closes it without widening the classifier, because it does not read the error text at
  // all. What makes it sound is the `#p` filter on the message query: everything counted here was
  // ADDRESSED TO THIS KEY, so "all of it was unopenable" is a statement about this run, not about
  // strangers' mail.
  //
  // Deliberate: an alarm, not a note, even though junk persistently p-tagged at the identity would
  // fire it every run. Junk and an unrecognised signer fault are indistinguishable from here by
  // construction, and that indistinguishability is precisely what exit 3 exists to report. If junk
  // becomes chronic the remedy is to stop accepting it, not to stop saying so.
  if (envelopesSeen && !opened && !signerRefusals.length) {
    inconclusive.push(`${envelopesSeen} envelope(s) addressed to this key were read and none opened, ` +
      'with no signer fault recognised — this is not an empty inbox')
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
  // #195: the decrypt budget ran out on envelopes that could be in the window. This is the
  // decisive half of that fix — ranking makes the budget go further, but no ranking can make it
  // sufficient, because within the undecidable band the only signal left is the field NIP-59
  // randomizes. If anything in rank 0 or rank 1 went unopened, some unknown subset of this
  // identity's recent mail was not read, and printing "(none)" under every heading would be a
  // claim this run cannot support. That is what exit 3 is for.
  //
  // On 2026-08-15 this was the whole failure: eleven messages, two of them 9 KB reviews, absent
  // from a read that exited 0. The operator's conclusion was "the crew did not reply".
  //
  // `presumedOld` is excluded on purpose. Those wraps cannot carry an in-window rumor unless a
  // sender fuzzed further back than the NIP allows, so counting them would fire the alarm on every
  // mailbox that has ever received mail — the always-firing alarm this repo keeps warning about.
  // They are still reported below, and still opened if the budget reaches them.
  const missed = (unopenedByRank.certain ?? 0) + (unopenedByRank.possible ?? 0)
  if (missed) {
    inconclusive.push(`--max-wraps left ${missed} envelope(s) unopened that could be inside the window ` +
      `(${unopenedByRank.certain ?? 0} certainly, ${unopenedByRank.possible ?? 0} possibly) — ` +
      'this is a partial view of the inbox, not an empty one; raise --max-wraps')
  }
  if (unopened && !missed) {
    notes.push(`${unopened} envelope(s) left unopened by --max-wraps, none of which can be inside the window`)
  }
  if (reachedWraps.length && unreachable.length) {
    notes.push(`partial reach: ${reachedWraps.length}/${relayCount} relay(s) answered — ${unreachable.join('; ')}`)
  }
  if (total && answered10050.length && !dmRelayLists) {
    notes.push('no kind:10050 for this identity, yet messages arrived — senders are reaching you by some other route')
  }
  // `answered10050` gates both branches above, so when nobody answers that query the whole
  // reachability question was skipped — and said nothing, which is pass-by-silence one level up.
  // A note rather than exit 3: the doubt is about the check, not about the inbox.
  if (reachedWraps.length && !answered10050.length) {
    notes.push('no relay answered the kind:10050 query, so DM reachability was not checked')
  }

  return { code: inconclusive.length ? 3 : 0, inconclusive, notes }
}
