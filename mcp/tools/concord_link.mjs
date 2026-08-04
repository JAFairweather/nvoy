#!/usr/bin/env node
// concord_link.mjs — Bunker-signed CORD-05 dry-run / join for one isolated identity.
// The invite MUST arrive in a mode-0600 file.  Fragments are never accepted on argv or env.

import { readFileSync, lstatSync } from 'node:fs'
import WebSocket from 'ws'
import { makeBunkerSigner } from './nip46-signer.mjs'
import { buildJoin, latestCoordinateEvent, openBundle, parseInviteLink, verifyColdJoin } from './concord_link_lib.mjs'

const die = m => { console.error(`concord-link: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const mode = process.argv[2], invitePath = flag('--invite-file')
if (!['inspect', 'join'].includes(mode) || !invitePath) die('usage: inspect|join --invite-file <mode-0600 file> [--confirm]')
if (process.argv.includes('--invite') || process.env.CONCORD_INVITE) die('invite values are accepted only through --invite-file, never argv or environment')
let st, inviteText
try { st = lstatSync(invitePath); if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077)) die('invite file must be a regular mode-0600 file'); inviteText = readFileSync(invitePath, 'utf8').trim() } catch (e) { die(e.message || 'cannot read invite file') }
const invite = parseInviteLink(inviteText)

const query = (url, filter, timeout = 10000) => new Promise(resolve => {
  const out = []; let done = false; const finish = () => { if (done) return; done = true; try { ws?.close() } catch {}; resolve(out) }; let ws
  try { ws = new WebSocket(url) } catch { return finish() }
  const timer = setTimeout(finish, timeout)
  ws.on('open', () => ws.send(JSON.stringify(['REQ', 'cord05', filter])))
  ws.on('message', raw => { try { const m = JSON.parse(raw.toString()); if (m[0] === 'EVENT' && m[1] === 'cord05') out.push(m[2]); if ((m[0] === 'EOSE' || m[0] === 'CLOSED') && m[1] === 'cord05') { clearTimeout(timer); finish() } } catch {} })
  ws.on('error', () => { clearTimeout(timer); finish() })
})
const publish = (url, event, timeout = 10000) => new Promise(resolve => {
  let done = false; const finish = ok => { if (done) return; done = true; try { ws?.close() } catch {}; resolve(ok) }; let ws
  try { ws = new WebSocket(url) } catch { return finish(false) }
  const timer = setTimeout(() => finish(false), timeout)
  ws.on('open', () => ws.send(JSON.stringify(['EVENT', event])))
  ws.on('message', raw => { try { const m = JSON.parse(raw.toString()); if (m[0] === 'OK' && m[1] === event.id) { clearTimeout(timer); finish(!!m[2]) } } catch {} })
  ws.on('error', () => { clearTimeout(timer); finish(false) })
})

const bundles = (await Promise.all(invite.bootstrapRelays.map(url => query(url, { kinds: [33301], authors: [invite.linkSigner], '#d': [''], limit: 8 })))).flat()
const bundle = openBundle(latestCoordinateEvent(bundles, invite), invite)
console.log(JSON.stringify({ verified: true, community_id: bundle.community_id, name: bundle.name, root_epoch: bundle.root_epoch, channels: bundle.channels.map(c => ({ id: c.id, name: c.name })), relays: bundle.relays, invite_attribution: bundle.creator_npub || null }, null, 2))
if (mode === 'inspect') process.exit(0)
if (!process.argv.includes('--confirm')) { console.error('concord-link: DRY RUN — bundle verified; add --confirm to publish Codex\'s guestbook join'); process.exit(0) }

const credential = (path, label) => { try { return readFileSync(path, 'utf8').trim() } catch { die(`cannot read ${label}`) } }
const uri = credential(process.env.NVOY_BUNKER_URI_FILE, 'Bunker URI credential')
const client = credential(process.env.NVOY_NIP46_CLIENT_FILE, 'Bunker client credential')
const signer = makeBunkerSigner(uri, client)
const { wrap, rumor, group } = await buildJoin(bundle, signer)
const accepted = (await Promise.all(bundle.relays.map(url => publish(url, wrap)))).filter(Boolean).length
signer.close()
if (!accepted) die('no community relay accepted the locally verified join')
// A new query after the publishes is the proof that the relay has stored the exact wrap.  We
// open both encryption layers again rather than trusting an EVENT acknowledgement.
const cold = (await Promise.all(bundle.relays.map(url => query(url, { kinds: [1059], authors: [group.pub], ids: [wrap.id], limit: 1 })))).flat()
if (!verifyColdJoin(cold, group, rumor)) die('join was accepted but did not survive a cold, cryptographically verified guestbook read')
console.error(`concord-link: join ${rumor.id.slice(0, 12)}… accepted by ${accepted}/${bundle.relays.length} relay(s) and cold-verified.`)
