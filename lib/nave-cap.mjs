// vendored: components/nave-cap.mjs @ sha256:5d52d75c72a52377 — nave.pub@refs/heads/m
// DO NOT EDIT. Change it in nave.pub and re-run: npm run sync-vendor
// Source of truth: nave.pub/components/nave-cap.mjs — copy in, do not edit.
//
// One capability, one wording, fleet-wide. `da-cap` values are meaningful inside
// NIP-DA and meaningless to a person deciding whether to click Revoke, so every
// surface that shows a capability translates it — and before this module, each one
// translated it differently, or not at all.
//
// The wording is waggle's, promoted (AD-11: promote the best implementation, never
// level down). The gaps this closes: `task-relay` had no label anywhere, and
// `admit+read` had none either, though the bridge honours both.
//
// The enum is CLOSED (AD-12 ruling 4). New capabilities are new `capability:*`
// scope names carrying their own terms — not new `da-cap` values. So an unknown cap
// here is either a typo or a protocol change, and in both cases the honest thing is
// to render it legibly rather than silently drop the row.

/** The closed `da-cap` enum (AD-12). Order is roughly least → most authority. */
export const CAPS = ['mirror', 'admit', 'admit+read', 'task-relay', 'task', 'task+act']

/** Plain-English label. waggle's wording for the three it had; ours for the rest. */
const LABEL = {
  'mirror':      'Mirror their public posts',
  'admit':       'Post into the channel',
  'admit+read':  'Post into the channel, and read it',
  'task-relay':  'Carry signed instructions',
  'task':        'Take tasks from you',
  'task+act':    'Take tasks, and act on them',
}

/** One line on what the capability does NOT convey — the part people get wrong. */
const LIMIT = {
  'mirror':      'A consent record signed by them, not a delegation by you.',
  'admit':       'Does not convey any ability to read the channel.',
  'admit+read':  'Conveys channel key material. Revoking requires a rotation, not just a 441.',
  'task-relay':  'Transport only — never the original author of an instruction.',
  'task':        'May be woken and may reply. May not take authorized action.',
  'task+act':    'May act. Every action still passes its own approval path.',
}

/**
 * Human label for a `da-cap` value.
 * An unrecognised cap renders legibly rather than as a blank or a drop — dropping
 * an unknown grant would make a surface lie by omission.
 */
export function capLabel(cap) {
  const key = String(cap ?? '').trim()
  if (!key) return 'Unnamed capability'
  return LABEL[key] ?? `Capability: ${key}`
}

/** The one-line limit, or null when we have nothing honest to add. */
export function capLimit(cap) {
  return LIMIT[String(cap ?? '').trim()] ?? null
}

/** True when this cap is one the estate has ruled on. Unknown ≠ invalid. */
export function isKnownCap(cap) {
  return CAPS.includes(String(cap ?? '').trim())
}

/**
 * True when a cap conveys encrypted content and therefore makes the issuing UI
 * key-touching — the S2 distinction. `admit+read` references a 30440; `admit`
 * MUST NOT. A revoke path for one of these is a rotation client, not merely an
 * event signer, so a surface offering it needs to say so.
 */
export function capCarriesContent(cap) {
  return String(cap ?? '').trim() === 'admit+read'
}
