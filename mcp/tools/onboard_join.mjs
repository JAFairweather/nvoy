// onboard_join.mjs — the hive and rooms steps of nvoy-onboard (#291, build item 6 of waggle #649).
//
// The owner's page seals a single-use hive invite to the new agent's key (NIP-44) inside the signed
// add_agent request. Only the agent's own connection can open it, so it is opened here, on the fleet.
// The code lives in memory for the claim and is never written to a receipt, a file or a log.
//
// Agreeing to the hive's terms and confirming the age requirement are the owner's acts. They arrive
// in the signed request exactly as ticked, are passed only when the relay serves the same terms
// version, and are never derived from each other or from what the terms ask for.

import { createHash, randomUUID } from 'node:crypto'
import { readRoster, rosterFilter } from './room_roster.mjs'

export const JOIN_KIND = 9021
export { MEMBERS_KIND } from './room_roster.mjs'

const httpBase = relay => relay.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:')
const refusedLogin = error => /AUTH refused/.test(error?.message || '')
const result = (state, detail, extra = {}) => ({ state, detail, ...extra })

// The relay's own words, without the code in them should it ever echo one back.
// Redacted before it is cut, so a code that straddles the cut cannot leave its prefix behind.
const scrub = (text, code) => {
  const said = String(text || '(no reason)')
  return (code ? said.split(code).join('[invite]') : said).slice(0, 200)
}

// Every HTTP exchange with the hive, the body read included, is bounded: a stalled answer becomes a
// step that waits, never a command that hangs. The signal aborts a real fetch; the race bounds any other.
export const HTTP_TIMEOUT_MS = 15000
async function exchange(fetchImpl, url, init, ms) {
  let timer
  const stalled = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`no answer in ${ms / 1000}s`)), ms) })
  const run = (async () => {
    const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(ms) })
    let json
    try { json = await res.json() } catch { json = undefined }
    return { status: res.status, json }
  })()
  try { return await Promise.race([run, stalled]) } finally { clearTimeout(timer) }
}

async function post(relay, path, payload, { signer, fetchImpl, signed, ms }) {
  const url = `${httpBase(relay)}${path}`, body = JSON.stringify(payload), headers = { 'content-type': 'application/json' }
  if (signed) {
    const auth = await signer.signEvent({ kind: 27235, created_at: Math.floor(Date.now() / 1000), content: '', tags: [
      ['u', url], ['method', 'POST'], ['payload', createHash('sha256').update(body).digest('hex')], ['nonce', randomUUID()]] })
    headers.authorization = `Nostr ${Buffer.from(JSON.stringify(auth)).toString('base64')}`
  }
  try {
    const { status, json } = await exchange(fetchImpl, url, { method: 'POST', headers, body }, ms)
    return { status, json: json || {} }
  } catch (error) { return { status: 0, json: {}, unanswered: error.message } }
}

// The hive's join terms. Unreadable is "can't tell", never "none". The one no-terms answer is a 200
// of exactly {}, which is what the relay sends, or exactly {policy: null}. The owner's page
// (waggle console/hive-invite.mjs termsFromRead) reads by the same rules, so the version it signs is
// the version checked here.
export async function readTerms(relay, { fetchImpl = globalThis.fetch, ms = HTTP_TIMEOUT_MS } = {}) {
  let res
  try { res = await exchange(fetchImpl, `${httpBase(relay)}/api/join-policy`, { method: 'GET', headers: { accept: 'application/json' } }, ms) }
  catch (error) { return { ok: false, reason: error.message } }
  if (res.status !== 200) return { ok: false, reason: `HTTP ${res.status}` }
  const json = res.json
  if (json === undefined) return { ok: false, reason: 'not JSON' }
  if (!json || typeof json !== 'object' || Array.isArray(json)) return { ok: false, reason: 'not a JSON object' }
  const keys = Object.keys(json)
  if (!keys.length || (keys.length === 1 && json.policy === null)) return { ok: true, version: 'none', age: false }
  // Any other object without a policy ({error: ...}) is the relay saying something else.
  const policy = json.policy
  if (policy === undefined) return { ok: false, reason: 'no policy field' }
  if (policy === null) return { ok: false, reason: 'a null policy beside other fields' }
  if (typeof policy !== 'object' || Array.isArray(policy)) return { ok: false, reason: 'the policy is not an object' }
  if (policy.version == null) return { ok: false, reason: 'the terms carry no version' }
  return { ok: true, version: String(policy.version), age: policy.age_attestation_required === true }
}

// Step "hive": the agent is a member when the relay accepts its login. Otherwise open the sealed
// invite (or take an explicit plaintext add.inviteCode) and claim it, then log in again as the proof.
export async function joinHive({ add, relay, signer, open, fetchImpl = globalThis.fetch, ms = HTTP_TIMEOUT_MS }) {
  try { return result('done', 'a member of the hive already', { session: await open() }) }
  catch (error) { if (!refusedLogin(error)) return result('pending', `the hive relay did not answer: ${error.message}`) }
  const hasPlainCode = typeof add.inviteCode === 'string'
  if (!add.invite && !hasPlainCode) return result('pending', 'not a member, and the request carries no invite; the owner signs again from the page')

  let code = ''
  if (hasPlainCode) {
    code = add.inviteCode.trim()
  } else {
    try { code = await signer.nip44Decrypt(add.owner, add.invite) } catch { code = '' }
    code = typeof code === 'string' ? code.trim() : ''
  }
  if (!code) return result('refused', hasPlainCode ? 'the invite code is empty' : 'the invite was not sealed to this agent')

  const terms = await readTerms(relay, { fetchImpl, ms })
  if (!terms.ok) return result('pending', `can't read the hive's terms (${terms.reason}); run again`)
  if (terms.version !== add.policy) return result('pending', `the terms changed since the owner signed (the hive serves ${terms.version}, the request agreed ${add.policy || 'nothing'}); the owner signs again`)
  if (terms.age && !add.ageConfirmed) return result('pending', 'the terms ask for the age confirmation and the request does not carry it; the owner signs again')

  let receipt = null
  if (terms.version !== 'none') {
    const accepted = await post(relay, '/api/invites/accept-policy', { code, policy_version: terms.version, age_confirmed: add.ageConfirmed }, { signer, fetchImpl, signed: false, ms })
    if (accepted.unanswered) return result('pending', `the hive did not answer the terms acceptance (${accepted.unanswered}); run again`)
    if (accepted.status !== 200 || typeof accepted.json.receipt !== 'string')
      return result('refused', `the hive refused the terms acceptance: ${scrub(accepted.json.error, code)}`)
    receipt = accepted.json.receipt
  }
  const claimed = await post(relay, '/api/invites/claim', { code, ...(receipt ? { policy_receipt: receipt } : {}) }, { signer, fetchImpl, signed: true, ms })
  // A claim with no answer may still have landed, so the next run starts from the login check.
  if (claimed.unanswered) return result('pending', `the hive did not answer the claim (${claimed.unanswered}); the next run checks whether it took`)
  if (claimed.status !== 200) return result('refused', `the hive refused the invite: ${scrub(claimed.json.error, code)}`)
  try { return result('done', 'claimed the invite, and the hive lets it log in', { session: await open() }) }
  catch (error) { return result('pending', `claimed, but the hive does not let it log in yet: ${error.message}`) }
}

// With the relay's signing key pinned in the template (#321), only a list it signed counts.
const inRoom = async (session, room, pubkey, relaySigner) => {
  if (relaySigner) return !!(await readRoster(session, room, relaySigner))?.includes(pubkey)
  const lists = await session.fetch(rosterFilter(room))
  const newest = lists.sort((a, b) => b.created_at - a.created_at)[0]
  return !!newest?.tags?.some(tag => tag[0] === 'p' && tag[1] === pubkey)
}

// Step "rooms": each room asked for, joined by the agent itself, proven by the room's member list.
export async function joinRooms({ add, session, now = () => Date.now(), relaySigner = null }) {
  if (!add.rooms.length) return result('done', 'no rooms asked for')
  const joined = [], waiting = []
  for (const room of add.rooms) {
    if (await inRoom(session, room, add.pubkey, relaySigner)) { joined.push(room); continue }
    const sent = await session.publish({ kind: JOIN_KIND, created_at: Math.floor(now() / 1000), tags: [['h', room]], content: '' })
    if (!sent.accepted) { waiting.push(`${room.slice(0, 8)} refused the join (${scrub(sent.message)}); if it is private, the owner adds it from the page`); continue }
    if (await inRoom(session, room, add.pubkey, relaySigner)) joined.push(room)
    else waiting.push(`${room.slice(0, 8)} took the join but its member list does not show it yet; run again`)
  }
  const head = `${joined.length} of ${add.rooms.length} rooms joined`
  return waiting.length ? result('pending', `${head}; ${waiting.join('; ')}`) : result('done', head)
}
