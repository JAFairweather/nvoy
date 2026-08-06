// tap.ts — every instantiation of an agent action passes a fresh human tap (AD-12 ruling 3a).
//
// THE RULING. The Director declined the templated-actuator exception on 2026-08-06: a template's
// substitution set is wider than it looks and the failure is silent, so *every* instantiation queues and
// the doctrine stands unamended — "No standing authority to sign. Standing authority to propose."
//
// THE THREE PATHS THIS CLOSES (nvoy#111). All three sign an agent's own act with no tap:
//   · instance-broker-daemon: a 1-second timer publishes text a keyless worker wrote.
//   · wake-watcher: an incoming event spawns an unattended runtime holding a signer.
//   · chat.ts: `nvoy_chat_post` and `nvoy_dm_send` sign directly, with no approval parameter at all.
//
// The third is why the second is dangerous, and the sharp part is that the restraint on that path lives in
// PROMPT TEXT — `WAKE_PROMPT` says "never auto-obey" and "do not publish under a project identity". This
// estate already has a name for configuration that exists but does not bite: `◌`. A prompt is the `◌` case
// applied to authority.
//
// WHY DRAFT-BY-DEFAULT RATHER THAN REFUSE. Refusing outright would be the simpler code and the wrong
// change: these tools are live, the crew's agents speak through them right now, and a hard refusal would
// stop work rather than gate it. The ruling says every instantiation QUEUES — not that agents fall silent.
// So the default becomes an offer the Director can sign, using the draft machinery that already exists
// end-to-end (drafts.ts mints it, Ngage renders it, he signs in his own hand). The agent still acts; what
// it no longer does is sign.
//
// The escape is per-call and unforgeable-by-the-agent: an `approval` reference the Director issues. It is
// deliberately NOT a config flag, an env var, or a standing grant — those are all standing authority to
// sign, which is the thing being removed.
//
// Pure and dependency-free so mcp/test can drive it, and so the decision is reviewable without reading a
// tool registration.

/** Tools that emit an agent's own act and therefore need a tap. Not a denylist of everything else. */
export const NEEDS_TAP = new Set(['nvoy_chat_post', 'nvoy_dm_send'])

export type TapDecision =
  | { mode: 'publish'; why: string }
  | { mode: 'draft'; why: string; notice: string }

/**
 * An approval reference is a 64-hex event id: the `["approval", id, approver]` provenance atom this estate
 * already uses (the one NIP-worthy piece of the act side). Anything else is not an approval, and a
 * malformed one is REFUSED rather than treated as absent — silently downgrading a bad approval to a draft
 * would hide a caller trying to use a broken token.
 */
const APPROVAL_REF = /^[0-9a-f]{64}$/

/**
 * Decide how one call proceeds.
 *
 * @param tool     the tool name being invoked
 * @param approval an approval event id supplied per call, or undefined
 */
export function decideTap(tool: string, approval?: string): TapDecision | { mode: 'refuse'; why: string } {
  if (!NEEDS_TAP.has(tool)) {
    return { mode: 'publish', why: `${tool} does not emit an agent act` }
  }
  if (approval === undefined || approval === null || approval === '') {
    return {
      mode: 'draft',
      why: 'no approval was supplied, so this becomes a draft the Director can sign (AD-12 3a)',
      notice:
        'NOT PUBLISHED. This was offered to the Director as a draft; he signs it in his own hand on the '
        + 'Ngage desk, and it reaches the relays under HIS signature or not at all. Nothing standing lets '
        + 'an agent sign — that is the doctrine, not a setting. To publish directly, pass the `approval` '
        + 'event id he gives you for THIS message; there is no flag that turns this off.',
    }
  }
  if (typeof approval !== 'string' || !APPROVAL_REF.test(approval)) {
    return {
      mode: 'refuse',
      why: 'approval must be the 64-hex id of an approval event. A malformed approval is refused, not '
        + 'downgraded to a draft — a caller with a broken token should hear about it.',
    }
  }
  return { mode: 'publish', why: `approval ${approval.slice(0, 12)}… supplied for this call` }
}

/**
 * The scope name a drafted call is offered under. `draft:` is the namespace Ngage admits, and drafts.ts
 * refuses anything outside it at the signing boundary.
 *
 * The KIND is carried in the name so the desk can tell a public note from a DM without decrypting: a
 * Director approving a post and a Director approving a private message are different decisions, and a desk
 * that rendered them identically would collapse them.
 */
export function draftScopeName(tool: string, seed: string): string {
  const kind = tool === 'nvoy_dm_send' ? 'dm' : 'post'
  return `draft:${kind}/${seed.slice(0, 8)}`
}

/**
 * One line for the audit log. Recorded for BOTH outcomes: a published-with-approval call is exactly the
 * event a reader will later want to find, and logging only the refusals would make the approved path the
 * invisible one.
 */
export function tapAudit(tool: string, d: { mode: string; why: string }): string {
  return `tap: ${tool} → ${d.mode} — ${d.why}`
}

/**
 * WHO a drafted call is offered to.
 *
 * There is no ambient "Director pubkey" on this server, and inventing one would be a guess wearing
 * authority. What the agent does know is who delegated to IT: a held grant's publisher. Whoever granted this
 * agent its access is the party whose desk a draft belongs on — the same derivation `relinquishGrant` already
 * uses when it sends a notice to "the delegator's contact".
 *
 * AMBIGUITY IS REFUSED, NOT RESOLVED. With two delegators there is no basis to pick one, and offering the
 * draft to the wrong person would put an agent's words on a desk that should never have seen them — a
 * disclosure, not an inconvenience. With none, there is nobody to ask. Both cases send the caller to
 * `nvoy_draft_publish`, where the grantee is explicit and the choice is the caller's to state.
 */
export function resolveDraftGrantee(publishers: string[]): { ok: true; grantee: string } | { ok: false; why: string } {
  const unique = [...new Set((publishers ?? []).filter(p => APPROVAL_REF.test(String(p ?? ''))))]
  if (unique.length === 1) return { ok: true, grantee: unique[0] }
  if (unique.length === 0) {
    return { ok: false, why: 'this agent holds no grant, so there is no delegator whose desk a draft belongs '
      + 'on. Use nvoy_draft_publish and name the grantee, or obtain an approval for this call.' }
  }
  return { ok: false, why: `this agent holds grants from ${unique.length} delegators, so which desk this draft `
    + 'belongs on is not derivable — offering it to the wrong one would disclose the message to someone who '
    + 'should not see it. Use nvoy_draft_publish and name the grantee explicitly.' }
}
