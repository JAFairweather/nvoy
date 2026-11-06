// room_roster.mjs — who is in each Buzz room, read from the relay's own member list (#321).
//
// The relay publishes each room's members as a kind 39002 it signs itself. Only a list signed by the
// key pinned in the manifest (buzz.relay_signer) counts: never one learned from the relay, whose NIP-11
// is no independent pin. The broker reads it through its NIP-42 session and leaves what it read in
// mention-rooms.json for the keyless channel MCPs. That file is for discovery only: before the broker
// signs or publishes a mention that only a room allows, it reads the roster again (confirmMembers).

import { closeSync, constants, fstatSync, ftruncateSync, lstatSync, openSync, readFileSync, writeSync } from 'node:fs'
import { resolve } from 'node:path'
import { verifyEvent } from 'nostr-tools/pure'
import { MENTION_NAME } from './admission.mjs'

export const MEMBERS_KIND = 39002
const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const PROFILE_BATCH = 100
const tagValues = (ev, name) => (Array.isArray(ev?.tags) ? ev.tags : []).filter(t => Array.isArray(t) && t[0] === name).map(t => t[1])
// A clean copy, so a verification nostr-tools cached on a tampered object is not reused.
const verified = (ev, verify) => {
  const { id, pubkey, created_at, kind, tags, content, sig } = ev || {}
  try { return verify({ id, pubkey, created_at, kind, tags, content, sig }) === true } catch { return false }
}
const fold = s => String(s).toLowerCase().replace(/[^a-z0-9]/g, '')

export const rosterFilter = room => ({ kinds: [MEMBERS_KIND], '#d': [room], '#h': [room], limit: 5 })

// The members of `room` from the newest list that passes every check, or null when none does.
// Null is "no roster", never "nobody": a reader that needs authority holds rather than refuses.
export function rosterFrom(events, { room, relaySigner, verify = verifyEvent }) {
  if (!UUID.test(String(room || '')) || !HEX64.test(String(relaySigner || ''))) return null
  const passing = (Array.isArray(events) ? events : []).filter(ev => ev?.kind === MEMBERS_KIND && ev.pubkey === relaySigner &&
    Number.isSafeInteger(ev.created_at) && tagValues(ev, 'd').length === 1 && tagValues(ev, 'd')[0] === room &&
    tagValues(ev, 'h').every(h => h === room) && verified(ev, verify))
  const newest = passing.sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1))[0]
  return newest ? [...new Set(tagValues(newest, 'p').filter(p => HEX64.test(String(p))))] : null
}
export const readRoster = async (session, room, relaySigner) => rosterFrom(await session.fetch(rosterFilter(room)), { room, relaySigner })

// The broker's check before it signs or publishes a mention only a room allows. Resolves to the first
// key not in the fresh roster, or undefined when every key is. Throws when the roster cannot be read
// or no list passes, so the caller holds the message rather than refusing it.
export async function confirmMembers({ session, room, keys, relaySigner }) {
  const roster = await readRoster(session, room, relaySigner)
  if (!roster) throw new Error(`no member list for room ${room} passes the pinned relay signer`)
  return keys.find(key => !roster.includes(key))
}

// A display name an agent can type: `name`, else `display_name`, lowercased, spaces to dashes, and
// anything outside the manifest's name pattern dropped. Null when nothing usable is left.
export function mentionName(content) {
  let profile; try { profile = JSON.parse(content) } catch { return null }
  const raw = [profile?.name, profile?.display_name].find(v => typeof v === 'string' && v.trim())
  if (!raw) return null
  const name = raw.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9._-]/g, '').replace(/^[^a-z0-9]+/, '').slice(0, 32)
  return MENTION_NAME.test(name) ? name : null
}
export const profileFilter = authors => ({ kinds: [0], authors })
// Newest verified kind 0 per wanted key, reduced to a mention name.
export function namesFrom(events, wanted, verify = verifyEvent) {
  const newest = new Map()
  for (const ev of Array.isArray(events) ? events : []) {
    if (ev?.kind !== 0 || !wanted.includes(ev.pubkey) || !Number.isSafeInteger(ev.created_at) || !verified(ev, verify)) continue
    const held = newest.get(ev.pubkey)
    if (!held || ev.created_at > held.created_at) newest.set(ev.pubkey, ev)
  }
  return new Map([...newest].map(([pubkey, ev]) => [pubkey, mentionName(ev.content)]))
}

// Every room's roster, the broker itself left out, and a name for each member where one is usable.
// A name two keys reduce to is kept by neither: they stay mentionable by key. A room that could not
// be read is listed in `failed`, so the caller keeps what it last had for it.
export async function readRooms({ session, rooms, relaySigner, me }) {
  const read = {}, failed = []
  for (const room of rooms) {
    try { read[room] = (await readRoster(session, room, relaySigner) || []).filter(p => p !== me) }
    catch (e) { failed.push({ room, reason: e.message }) }
  }
  const everyone = [...new Set(Object.values(read).flat())]
  let names = new Map()
  try {
    for (let i = 0; i < everyone.length; i += PROFILE_BATCH) {
      const batch = everyone.slice(i, i + PROFILE_BATCH)
      for (const [k, v] of namesFrom(await session.fetch(profileFilter(batch)), batch)) names.set(k, v)
    }
  } catch (e) { failed.push({ room: null, reason: `profiles: ${e.message}` }); names = new Map() }
  const holders = new Map()
  for (const [pubkey, name] of names) if (name) holders.set(fold(name), [...(holders.get(fold(name)) || []), pubkey])
  const nameOf = pubkey => { const n = names.get(pubkey); return n && holders.get(fold(n)).length === 1 ? n : null }
  return { rooms: Object.fromEntries(Object.entries(read).map(([room, keys]) => [room, keys.map(pubkey => ({ pubkey, name: nameOf(pubkey) }))])), failed }
}

// --- The discovery file: broker-owned, worker-group readable, provisioned beside mention-grants.json. ---
export const mentionRoomsPath = manifest => resolve(manifest.runtimeDir, 'mention-rooms.json')
const entryOk = e => e && HEX64.test(String(e.pubkey || '')) && (e.name === null || MENTION_NAME.test(String(e.name || '')))
// Only the identity's own may_post rooms, and only well-formed entries; null when the file cannot be read whole.
export function readMentionRooms(manifest) {
  const channels = manifest.mayPost?.channels || []
  try {
    const path = mentionRoomsPath(manifest), st = lstatSync(path)
    if (!st.isFile() || st.size > 4 * 1024 * 1024) return null
    const x = JSON.parse(readFileSync(path, 'utf8'))
    if (x?.version !== 1 || x.instance !== manifest.id || !x.rooms || typeof x.rooms !== 'object' || Array.isArray(x.rooms)) return null
    return Object.fromEntries(channels.filter(c => Array.isArray(x.rooms[c])).map(c => [c, x.rooms[c].filter(entryOk).map(({ pubkey, name }) => ({ pubkey, name }))]))
  } catch { return null }
}
// A room not read this time (one that failed, or one a single-room refresh skipped) keeps its last
// good list. True only when the file now holds exactly this body.
// When the profiles could not be read, a member keeps the name it last had: a subset of a list that
// was clash-free when written, so no clash comes back.
export function recordMentionRooms(manifest, { rooms, failed = [] }, now = Date.now()) {
  if (!manifest.mayPost?.mentionRooms) return false
  const last = readMentionRooms(manifest) || {}
  const lastName = new Map(Object.values(last).flat().filter(e => e.name).map(e => [e.pubkey, e.name]))
  const noProfiles = failed.some(f => f.room === null)
  const fresh = list => noProfiles ? list.map(e => ({ pubkey: e.pubkey, name: e.name ?? lastName.get(e.pubkey) ?? null })) : list
  const merged = Object.fromEntries(manifest.mayPost.channels.filter(c => rooms[c] || last[c]).map(c => [c, rooms[c] ? fresh(rooms[c]) : last[c]]))
  const body = JSON.stringify({ version: 1, instance: manifest.id, read_at: Math.floor(now / 1000), rooms: merged }) + '\n'
  let fd
  try {
    fd = openSync(mentionRoomsPath(manifest), constants.O_RDWR | constants.O_NOFOLLOW)
    if (!fstatSync(fd).isFile()) throw new Error('is not a regular file')
    if (readFileSync(fd, 'utf8') !== body) { ftruncateSync(fd, 0); writeSync(fd, body, 0) }
  } catch (e) { if (e.code !== 'ENOENT') console.error(`nvoy-mention: cannot record room members: ${e.message}`); return false }
  finally { if (fd !== undefined) closeSync(fd) }
  try { return readFileSync(mentionRoomsPath(manifest), 'utf8') === body } catch { return false }
}
