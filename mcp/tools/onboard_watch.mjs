// onboard_watch.mjs — phase B (#323): one tick of the fleet running adds itself (docs/ONBOARD_PHASE_B.md).
//
// A tick reads every trusted owner's add_agent requests, and runs each name whose newest request is
// neither finished nor refused, oldest first, through the same steps as `run`. The pairing link and
// every step's state reach the owner only inside a receipt sealed to them and signed by the runner key.

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { MAX_AGE_S, OnboardRefusal, RETRY_CODES, SETUP_KIND, SETUP_PREFIX } from './onboard_request.mjs'
import { installed, onboard } from './onboard_run.mjs'
import { delegateReceiptD, latestSteps, makeSealer, receiptBody, terminalEvent } from './onboard_receipt.mjs'
import { delegateAuthors } from './onboard_delegate.mjs'

const ADD = new RegExp(`^${SETUP_PREFIX.replace(/[/]/g, '\\/')}([a-z0-9][a-z0-9._-]{1,63})\\/add_agent$`, 'i')
// An unchanged receipt is still republished this often, so the page can tell a live runner from one
// that stopped.
export const HEARTBEAT_MS = 10 * 60 * 1000

// Every event one relay holds for a filter, newest page first, walking `until` back until a short page.
// A relay that stops answering part way keeps what it gave; the caller sees answered as on the first page.
// `complete` says whether the walk reached the end of what the relay holds. It is false when the relay
// stopped answering part way, when more events share one second than a page holds (a relay cannot be
// asked for the rest of a second), and when the page cap ended the walk, so a caller never mistakes a
// partial read for the whole window.
export const PAGE = 100
export async function readPages(query, url, filter, { page = PAGE, pages = 1000 } = {}) {
  const seen = new Map()
  let until = filter.until, answered = false, complete = false, skipped = false
  for (let n = 0; n < pages; n++) {
    const read = await query(url, { ...filter, limit: page, ...(until === undefined ? {} : { until }) })
    if (!read.answered) break
    answered = true
    let fresh = 0, oldest = Infinity
    for (const event of read.events) {
      if (!seen.has(event?.id)) { seen.set(event?.id, event); fresh++ }
      if (Number.isInteger(event?.created_at)) oldest = Math.min(oldest, event.created_at)
    }
    if (read.events.length < page || oldest === Infinity) { complete = true; break }
    // `until` is inclusive, so siblings in the oldest second come back; once a page brings nothing
    // new, step past that second, so the walk always moves back. Events left in that second are out of
    // reach, so the read is no longer complete.
    if (fresh) until = oldest
    else { until = oldest - 1; skipped = true }
  }
  return { answered, complete: complete && !skipped, events: [...seen.values()] }
}

const rows = path => existsSync(path) ? readFileSync(path, 'utf8').split('\n').filter(Boolean).flatMap(line => {
  try { return [JSON.parse(line)] } catch { return [] }
}) : []

// The newest verified add_agent per name, oldest first, leaving out those already finished or refused.
export function pendingRequests(events, { verify, finished, refused }) {
  const newest = new Map()
  for (const event of Array.isArray(events) ? events : []) {
    if (event?.kind !== SETUP_KIND) continue
    const name = (event.tags || []).find(tag => tag[0] === 'd')?.[1]?.match(ADD)?.[1]
    if (!name || !verify(event)) continue
    const held = newest.get(name)
    if (!held || event.created_at > held.created_at || (event.created_at === held.created_at && String(event.id).localeCompare(String(held.id)) > 0)) newest.set(name, event)
  }
  return [...newest].filter(([, event]) => !finished.has(event.id) && !refused.has(event.id))
    .sort(([, a], [, b]) => a.created_at - b.created_at || String(a.id).localeCompare(String(b.id)))
    .map(([name, event]) => ({ name, id: event.id }))
}

// A request stops at its first refused step; a newer request for the name starts again.
const refusedIds = stateDir => {
  const ids = new Set(rows(join(stateDir, 'watch-refused.jsonl')).map(row => row.id))
  for (const row of rows(join(stateDir, 'requests.jsonl')))
    if (row.op === 'add_agent' && latestSteps(rows(join(stateDir, `${row.id}.jsonl`))).some(step => step.state === 'refused')) ids.add(row.id)
  return ids
}

export async function watchTick({ root, out, stateDir, runner, fetchAll, fetchEvents, runTool, joinWith, pair, readWriters,
  publish, signer, verify, installFor, readDelegates = null, readTermsFor = null, readEvent = null, now = () => Date.now(), log = console.log }) {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 })
  const manifests = installed(root)
  const owners = [...new Set([...manifests.values()].flatMap(manifest => manifest.grantors))]
  const relays = [...new Set([...manifests.values()].flatMap(manifest => manifest.relays))]
  if (!owners.length) { log('no installed agent names a grantor, so no owner is trusted yet'); return { ran: [], incomplete: [] } }
  const finished = new Set(rows(join(stateDir, 'requests.jsonl')).filter(row => row.finished).map(row => row.id))
  // fetchAll hands back the events, or { events, incomplete } naming the relays whose read did not reach
  // the end of the window. Say so: a request on such a relay may be missing from the queue.
  // Delegate discovery (DESIGN_ONBOARDING_DELEGATE): the owners' live `onboard` grants, read cold each
  // tick. Their grantees' requests are fetched too; an unknown grant state adds no one, and says so.
  const delegates = readDelegates ? await readDelegates({ relays, owners }) : null
  if (delegates && !delegates.known) log(`warning  grant state unknown (${delegates.reason}); no delegate request is read this tick`)
  const read = await fetchAll({ relays, owners, delegates: delegateAuthors(delegates) })
  const incomplete = Array.isArray(read) ? [] : read.incomplete || []
  for (const url of incomplete) log(`warning  ${url} gave an incomplete read of the owner's events (more in one second than a page, or it stopped answering); an unfinished request may not be listed`)
  const refused = refusedIds(stateDir)
  const seal = makeSealer(signer, { now: () => Math.floor(now() / 1000) })
  // The public terminal marker: published, then read back from a relay, once per request, before the request is
  // recorded as finished or set aside. Without a reader (an older caller) no marker goes out and nothing waits on it.
  const markTerminal = readEvent ? async id => {
    const done = join(stateDir, `${id}.terminal.json`)
    if (existsSync(done)) return true
    try {
      const event = await signer.signEvent(terminalEvent(id, Math.floor(now() / 1000)))
      if (event.pubkey !== runner.pubkey) throw new Error('the runner connection signs as another key')
      const took = (await publish(event)).filter(result => result.accepted).map(result => result.relay)
      if (!took.length) throw new Error('no relay took it')
      const back = await readEvent(event, took)
      if (!back || back.id !== event.id || !verify(back)) throw new Error('it did not read back')
      writeFileSync(done, JSON.stringify({ id: event.id, at: now(), relays: took }) + '\n', { mode: 0o600 })
      return true
    } catch (error) { log(`warning  terminal marker for ${id.slice(0, 12)} not out: ${error.message}; the next tick tries again`); return false }
  } : null
  // A request refused in an earlier tick whose marker did not go out tries again, while its request could still count.
  if (markTerminal) {
    const cutoff = now() - (MAX_AGE_S + 600) * 1000
    const recent = new Map([...rows(join(stateDir, 'requests.jsonl')), ...rows(join(stateDir, 'watch-refused.jsonl'))]
      .filter(row => row?.id && Number(row.at) > cutoff).map(row => [row.id, row]))
    for (const id of refused) if (recent.has(id) && !existsSync(join(stateDir, `${id}.terminal.json`))) await markTerminal(id)
  }
  const queue = pendingRequests(Array.isArray(read) ? read : read.events, { verify, finished, refused })
  if (!queue.length) return { ran: [], incomplete }

  const ran = []
  for (const { name, id } of queue) {
    log(`watch: ${name}, request ${id.slice(0, 12)}`)
    const sentPath = join(stateDir, `${id}.receipt.json`)
    let install = null
    const report = async ({ request, rows: all, pairing = null }) => {
      if (!install && latestSteps(all).some(row => row.step === 'staged' && row.state === 'done')) {
        try { install = installFor(name) } catch (error) { log(`warning  no install details in the receipt: ${error.message}`) }
      }
      const body = receiptBody({ name, request: request.id, instance: name, rows: all, pairing, install })
      // Each copy is tracked on its own: stamps aside, an unchanged copy goes out only on the heartbeat (each link is
      // new, so it differs). A copy no relay takes throws, so the run does not count the request as reported, and
      // never marks it finished; the next tick sends that copy again even when the other one is up to date.
      const send = async ({ path, to, content, d, what }) => {
        const digest = createHash('sha256').update(JSON.stringify({ ...content, steps: content.steps.map(({ at, ...step }) => step) })).digest('hex')
        const last = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null
        if (last?.digest === digest && now() - last.at < HEARTBEAT_MS) return
        const event = await seal({ owner: to, request: request.id, body: content, ...(d ? { d } : {}) })
        if (event.pubkey !== runner.pubkey) throw new Error('the runner connection signs as another key; nothing published')
        const results = await publish(event)
        const took = results.filter(result => result.accepted).map(result => result.relay)
        for (const result of results.filter(result => !result.accepted)) log(`warning  ${result.relay} did not take the ${what}: ${result.message}`)
        if (!took.length) throw new Error(`no relay took the ${what}`)
        writeFileSync(path, JSON.stringify({ digest, at: now(), id: event.id, relays: took }) + '\n', { mode: 0o600 })
      }
      await send({ path: sentPath, to: request.owner, content: body, what: 'receipt' })
      // A delegate's request: a second copy, sealed to the delegate, without the pairing link, which is the owner's
      // Bunker approval and only theirs to see.
      if (request.delegated) {
        const { pairing: _owners, ...own } = body
        await send({ path: join(stateDir, `${id}.delegate-receipt.json`), to: request.signer, content: own, d: delegateReceiptD(request.id), what: "delegate's receipt copy" })
      }
    }
    try {
      const result = await onboard({ command: 'run', name, root, out, stateDir, keysPath: runner.authorizedKeys, giversRedeploy: false,
        fetchEvents, runTool, joinWith, now, log, pair, report, readWriters, verify, readDelegates, readTermsFor, delegateTemplates: runner.onboardTemplates || [], markTerminal })
      if (markTerminal && result.receipts.some(row => row.state === 'refused')) await markTerminal(id)
      ran.push({ name, id, receipts: result.receipts })
    } catch (error) {
      // A crash, or no relay answering, leaves everything as it was for the next tick.
      if (!(error instanceof OnboardRefusal) || RETRY_CODES.includes(error.code)) {
        log(`error    ${name}: ${error.message}; the next tick tries again`)
        ran.push({ name, id, error: error.message })
        continue
      }
      // A request that does not qualify is set aside by id, so the next tick does not retry it; a
      // newer request for the name is a new id. Its terminal marker goes out first; if it does not, it is
      // not set aside, and the next tick refuses it again and retries the marker.
      if (markTerminal && !(await markTerminal(id))) { ran.push({ name, id, refused: error.code || 'ERROR', marker: 'pending' }); continue }
      appendFileSync(join(stateDir, 'watch-refused.jsonl'), JSON.stringify({ id, name, at: now(), code: error.code || 'ERROR', detail: error.message }) + '\n')
      log(`refused  ${name}: ${error.code ? `${error.code}: ` : ''}${error.message}`)
      ran.push({ name, id, refused: error.code || 'ERROR' })
    }
  }
  return { ran, incomplete }
}
