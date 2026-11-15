// broker_done.mjs — what the broker daemon reads, in its own process, before it spawns a keyed child
// for a queued post or reply: has that request already finished, by the child's own durable record?
//
// Why (q-108, 15 Nov 2026): the daemon's done sets lived in memory, and only refusals were written
// down. After every broker restart (every nvoy merge redeploys every broker) it spawned one child per
// id ever queued, serially, inside one tick, so each child could find its own record and exit as a
// replay. A seat with 486 queued posts paid 486 node starts per restart, plus an attention policy
// child for each off-list mention, before it reached the replay exit, while its inbound drain waited.
//
// Each check mirrors the replay exit the child itself takes, and only that one:
// - a post is done when posts/<id>.json is a regular file bound to this exact queue row (version,
//   request id, request digest), whose frozen unsigned event hashes to its fingerprint, whose signed
//   event, if any, is that event with a valid signature, and which says published: every condition
//   the child checks before its own replay exit (instance-broker-post.mjs; My Dude, PR 410 review);
// - a reply is done when its one-use receipt has been renamed to <receipt>.<id>.used, which the reply
//   actuator does only after publishing (instance-broker-reply.mjs).
// Anything else, including an unreadable or unbound record, answers false: the child runs, as before,
// and decides. A false "done" can only withhold a send, never cause one; these never open the signer.

import { lstatSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { getEventHash, verifyEvent } from 'nostr-tools/pure'
import { replyRequestDigest } from './outbound_record.mjs'

const REQUEST = /^[0-9a-f]{32}$/, RECEIPT = /^[0-9a-f]{64}$/
const MAX_RECORD_BYTES = 1024 * 1024

function regularFile(path) {
  try { const st = lstatSync(path); return st.isFile() && !st.isSymbolicLink() ? st : null } catch { return null }
}

// The first row for each well-formed id, as each child takes the first matching line of its queue.
export function firstRows(text) {
  const rows = new Map()
  for (const line of String(text || '').split('\n')) {
    let x; try { x = JSON.parse(line) } catch { continue }
    const id = x?.id
    if (typeof id === 'string' && REQUEST.test(id) && !rows.has(id)) rows.set(id, x)
  }
  return rows
}

export function postPublished(stateDir, row) {
  const id = row?.id
  if (typeof id !== 'string' || !REQUEST.test(id)) return false
  const path = resolve(stateDir, 'posts', `${id}.json`), st = regularFile(path)
  if (!st || st.size > MAX_RECORD_BYTES) return false
  let record; try { record = JSON.parse(readFileSync(path, 'utf8')) } catch { return false }
  if (record?.version !== 1 || record.request_id !== id || record.request_digest !== replyRequestDigest(row) || record.published !== true) return false
  const ev = record.unsigned_event
  try {
    if (!ev || getEventHash(ev) !== record.fingerprint) return false
    // Through JSON, as the child does, so no cached verification mark on the object is trusted.
    if (record.event && (record.event.id !== record.fingerprint || !verifyEvent(JSON.parse(JSON.stringify(record.event))))) return false
  } catch { return false }
  return true
}

export function replyFinished(stateDir, row) {
  // The receipt exactly as queued, as the child builds its path: an id it would spell differently is not done.
  const id = row?.id, receipt = typeof row?.receipt === 'string' ? row.receipt : ''
  if (typeof id !== 'string' || !REQUEST.test(id) || !RECEIPT.test(receipt)) return false
  return Boolean(regularFile(resolve(stateDir, 'receipts', `${receipt}.${id}.used`)))
}
