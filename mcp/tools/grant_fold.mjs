// grant_fold.mjs — the one reading of kind 440/441 that the broker (attention.mjs), the wake watcher
// and the status page all apply, so who may task an agent cannot differ between the code that admits,
// the code that wakes and the page that shows it.
//
// Order is created_at; only verified events by a grantor count; a 441 drops the grant it names, and
// a NIP-40 expiry drops a grant exactly as a 441 would. A grant is kept per capability, so one key may
// hold `task` and the carrier-only `task-relay` side by side.
//
// A `shadow` grant makes a key a grantor's voice. It is a 440 by grantor G with `p` = the voice and a
// da-scope whose subject is G itself, so a grantor can shadow only its own key. On this broker the
// voice holds whatever live task grants G itself holds here, under the shadow's grant id: one 441
// against the shadow silences the voice on every broker, and G's own grants are untouched. A voice
// inherits only G's own grants, never another voice's, so shadows do not chain; and since only a
// grantor's events are read, nothing a voice signs is ever a grant. A voice is not a grantor: it stays
// under the hourly per-sender brake, and a Buzz DM still admits only the owner (nativeGrant).

import { createHash } from 'node:crypto'
import { foldGrantsWith } from './admission.mjs'

export { TASK_CAPS } from './admission.mjs'

// The scope is a salted hash of the AGENT a grant is about (for a shadow, of the grantor itself), so
// a grant for one agent cannot be replayed against another and the agent id does not ride in clear.
export const scopeHash = (agentHex, saltHex) => createHash('sha256').update(Buffer.concat([
  Buffer.from('waggle/da-scope/v1'), Buffer.from([0]), Buffer.from(String(agentHex)), Buffer.from(saltHex || '', 'hex'),
])).digest('hex')

// Returns live: grantee -> Map(cap -> { grantId, grantor, cap, shadow? }), ended: grantee -> 'revoked' |
// 'expired' for a key whose every grant ended, and rejected: how many grantor events failed to verify.
export const foldGrants = (events, { me, grantors }) => foldGrantsWith(events, { me, grantors, scopeHash })
