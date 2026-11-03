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

export const JOIN_KIND = 9021
export const MEMBERS_KIND = 39002

const httpBase = relay => relay.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:')
const refusedLogin = error => /AUTH refused/.test(error?.message || '')
const result = (state, detail, extra = {}) => ({ state, detail, ...extra })

// The relay's own words, without the code in them should it ever echo one back.
const scrub = (text, code) => {
  const said = String(text || '(no reason)').slice(0, 200)
  return code ? said.split(code).join('[invite]') : said
}

async function post(relay, path, payload, { signer, fetchImpl, signed }) {
  const url = `${httpBase(relay)}${path}`, body = JSON.stringify(payload), headers = { 'content-type': 'application/json' }
  if (signed) {
    const auth = await signer.signEvent({ kind: 27235, created_at: Math.floor(Date.now() / 1000), content: '', tags: [
      ['u', url], ['method', 'POST'], ['payload', createHash('sha256').update(body).digest('hex')], ['nonce', randomUUID()]] })
    headers.authorization = `Nostr ${Buffer.from(JSON.stringify(auth)).toString('base64')}`
  }
  const res = await fetchImpl(url, { method: 'POST', headers, body })
  let json = {}
  try { json = await res.json() } catch { /* judged by status */ }
  return { status: res.status, json: json || {} }
}

// The hive's join terms. Unreadable is "can't tell", never "none".
export async function readTerms(relay, { fetchImpl = globalThis.fetch } = {}) {
  let res, json
  try { res = await fetchImpl(`${httpBase(relay)}/api/join-policy`, { method: 'GET', headers: { accept: 'application/json' } }) }
  catch (error) { return { ok: false, reason: error.message } }
  if (res.status !== 200) return { ok: false, reason: `HTTP ${res.status}` }
  try { json = await res.json() } catch { return { ok: false, reason: 'not JSON' } }
  if (!json || !('policy' in json)) return { ok: false, reason: 'no policy field' }
  if (json.policy == null) return { ok: true, version: 'none', age: false }
  return { ok: true, version: String(json.policy.version), age: json.policy.age_attestation_required === true }
}

// Step "hive": the agent is a member when the relay accepts its login. Otherwise open the sealed
// invite and claim it, then log in again as the proof.
export async function joinHive({ add, relay, signer, open, fetchImpl = globalThis.fetch }) {
  try { return result('done', 'a member of the hive already', { session: await open() }) }
  catch (error) { if (!refusedLogin(error)) return result('pending', `the hive relay did not answer: ${error.message}`) }
  if (!add.invite) return result('pending', 'not a member, and the request carries no invite; the owner signs again from the page')

  let code = ''
  try { code = await signer.nip44Decrypt(add.owner, add.invite) } catch { code = '' }
  code = typeof code === 'string' ? code.trim() : ''
  if (!code) return result('refused', 'the invite was not sealed to this agent')

  const terms = await readTerms(relay, { fetchImpl })
  if (!terms.ok) return result('pending', `can't read the hive's terms (${terms.reason}); run again`)
  if (terms.version !== add.policy) return result('pending', `the terms changed since the owner signed (the hive serves ${terms.version}, the request agreed ${add.policy || 'nothing'}); the owner signs again`)
  if (terms.age && !add.ageConfirmed) return result('pending', 'the terms ask for the age confirmation and the request does not carry it; the owner signs again')

  let receipt = null
  if (terms.version !== 'none') {
    const accepted = await post(relay, '/api/invites/accept-policy', { code, policy_version: terms.version, age_confirmed: add.ageConfirmed }, { signer, fetchImpl, signed: false })
    if (accepted.status !== 200 || typeof accepted.json.receipt !== 'string')
      return result('refused', `the hive refused the terms acceptance: ${scrub(accepted.json.error, code)}`)
    receipt = accepted.json.receipt
  }
  const claimed = await post(relay, '/api/invites/claim', { code, ...(receipt ? { policy_receipt: receipt } : {}) }, { signer, fetchImpl, signed: true })
  if (claimed.status !== 200) return result('refused', `the hive refused the invite: ${scrub(claimed.json.error, code)}`)
  try { return result('done', 'claimed the invite, and the hive lets it log in', { session: await open() }) }
  catch (error) { return result('pending', `claimed, but the hive does not let it log in yet: ${error.message}`) }
}

const inRoom = async (session, room, pubkey) => {
  const lists = await session.fetch({ kinds: [MEMBERS_KIND], '#d': [room], '#h': [room], limit: 5 })
  const newest = lists.sort((a, b) => b.created_at - a.created_at)[0]
  return !!newest?.tags?.some(tag => tag[0] === 'p' && tag[1] === pubkey)
}

// Step "rooms": each room asked for, joined by the agent itself, proven by the room's member list.
export async function joinRooms({ add, session, now = () => Date.now() }) {
  if (!add.rooms.length) return result('done', 'no rooms asked for')
  const joined = [], waiting = []
  for (const room of add.rooms) {
    if (await inRoom(session, room, add.pubkey)) { joined.push(room); continue }
    const sent = await session.publish({ kind: JOIN_KIND, created_at: Math.floor(now() / 1000), tags: [['h', room]], content: '' })
    if (!sent.accepted) { waiting.push(`${room.slice(0, 8)} refused the join (${scrub(sent.message)}); if it is private, the owner adds it from the page`); continue }
    if (await inRoom(session, room, add.pubkey)) joined.push(room)
    else waiting.push(`${room.slice(0, 8)} took the join but its member list does not show it yet; run again`)
  }
  const head = `${joined.length} of ${add.rooms.length} rooms joined`
  return waiting.length ? result('pending', `${head}; ${waiting.join('; ')}`) : result('done', head)
}
