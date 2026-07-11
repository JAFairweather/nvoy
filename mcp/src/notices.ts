// notices.ts — agent → delegator messages: access requests (spec §6.2
// nvoy_request_access) and relinquish notices (spec §6.6 phase 2).
//
// Both are app-level rumors delivered inside NIP-59 gift wraps, exactly like
// grants and 441 revocation notices: the relay sees an ephemeral pubkey
// handing an opaque blob to the recipient — never who asked whom for what,
// never what was handed back. The rumor kind (KIND_NVOY_MSG) is deliberately
// app-level: it exists ONLY inside gift wraps, is never published naked, and
// therefore claims nothing from the NIP kind registry (decision recorded in
// CLAUDE.md). Vanilla NIP-DA clients that unwrap it see an unknown rumor
// kind and skip it — same degradation contract as the §4 terms.
//
// Wire shapes (content JSON, discriminated by `type`):
//   access_request  { type: 'access_request', purpose }            tags: []
//   relinquish      { type: 'relinquish', d, reason?, destroyed_at }
//                                            tags: [['a', 30440:pub:d]]

import { wrapEvent } from 'nostr-tools/nip59'
import { KIND_DATA_SET, type RelayLike } from '../lib/nipxx.mjs'

/** App-level rumor kind for Nvoy notices — only ever inside 1059 gift wraps. */
export const KIND_NVOY_MSG = 24440

async function sendWrapped(
  relay: RelayLike,
  secretKey: Uint8Array,
  recipientPub: string,
  tags: string[][],
  content: Record<string, unknown>,
) {
  const rumor = {
    kind: KIND_NVOY_MSG,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: JSON.stringify(content),
  }
  // nostr-tools nip59.wrapEvent: sign-side construction is the standard one
  // (the lib avoids it only for UNwrapping, where it skips seal verification).
  const wrap = wrapEvent(rumor, secretKey, recipientPub)
  return relay.publish(wrap)
}

/** §6.2: "this agent would like a delegation for this purpose". */
export async function sendAccessRequest(
  relay: RelayLike,
  secretKey: Uint8Array,
  delegatorPub: string,
  purpose: string,
) {
  return sendWrapped(relay, secretKey, delegatorPub, [], { type: 'access_request', purpose })
}

/** §6.6 phase 2: the finalization request after local key destruction. */
export async function sendRelinquishNotice(
  relay: RelayLike,
  secretKey: Uint8Array,
  recipientPub: string,
  { publisher, scopeId, reason, destroyed_at }: { publisher: string; scopeId: string; reason?: string; destroyed_at: number },
) {
  return sendWrapped(
    relay,
    secretKey,
    recipientPub,
    [['a', `${KIND_DATA_SET}:${publisher}:${scopeId}`]],
    { type: 'relinquish', d: scopeId, ...(reason ? { reason } : {}), destroyed_at },
  )
}
