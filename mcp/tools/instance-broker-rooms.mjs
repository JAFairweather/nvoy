#!/usr/bin/env node
// instance-broker-rooms.mjs — refresh mention-rooms.json, who is in each may_post room (#321).
//
// Run by the broker daemon at start and every five minutes for a mention_rooms manifest. Reads each
// room's relay-signed member list through the broker's NIP-42 session and the members' profiles for
// their names. The file is discovery for the keyless channel MCPs only: the post and reply actuators
// read the roster again before they sign a mention that only a room allows.

import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { openBuzzSession } from './buzz_native.mjs'
import { readRooms, recordMentionRooms } from './room_roster.mjs'

let signer, session
const exit = code => { try { session?.close() } catch { /* best effort */ } try { signer?.close?.() } catch { /* best effort */ } process.exit(code) }
const die = m => { console.error(`instance-broker-rooms: ${m}`); exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (!manifest.mayPost?.mentionRooms) die('mention_rooms is off for this identity')
;({ signer } = brokerSigner(die, { idleMs: 30000 }))
try { session = await openBuzzSession({ relay: manifest.buzz.relay, signer }) } catch (e) { die(`Buzz relay unavailable: ${e.message}; the last member lists stay`) }
const read = await readRooms({ session, rooms: manifest.mayPost.channels, relaySigner: manifest.buzz.relaySigner, me: manifest.pubkey })
for (const f of read.failed) console.error(`instance-broker-rooms: ${f.room ? `room ${f.room}` : 'member names'} unread (${f.reason}); the last good copy stays`)
if (!recordMentionRooms(manifest, read)) die('the room member snapshot could not be written')
// The audit line: how many members per room, never who.
console.log(`instance-broker-rooms: ${Object.entries(read.rooms).map(([room, list]) => `${room.slice(0, 8)} ${list.length}`).join(', ') || 'no room read'}`)
exit(0)
