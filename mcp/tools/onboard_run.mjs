// onboard_run.mjs — the steps nvoy-onboard runs for one setup request, phase A (#289).
//
// Each step is an existing tool. A step is done when the state it makes is there, not because a
// receipt says so, so a second run does each thing once and carries on where the first stopped:
// after the owner approves the pairing, after the box's bind_runtime arrives, or after the operator
// agrees to redeploy the givers. Receipts record what each run found; they never hold a secret.

import { appendFileSync, constants, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync, chownSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { readManifest } from './runtime_manifest.mjs'
import { newestRequest, OnboardRefusal, parseSetupRequest } from './onboard_request.mjs'
import { joinHive, joinRooms } from './onboard_join.mjs'
import { profileRequestIdsPath, profileResultsPath, profileStatus, queueProfile } from './agent_profile.mjs'

export const WRITERS_KIND = 30000, WRITERS_D = 'nave-relay-writers'

// The newest owner writer list (nave.pub #157) decides whether the relay takes the agent's writes: by
// NIP-01 order, a later created_at, then the lower id. Only a list that verifies counts.
export function writerVerdict(read, { owners, pubkey, verify }) {
  if (!read?.answered) return ['pending', 'the relay did not answer; trying again next run']
  const lists = (read.events || []).filter(event => event?.kind === WRITERS_KIND && owners.includes(event.pubkey) &&
    (event.tags || []).some(tag => tag[0] === 'd' && tag[1] === WRITERS_D) && verify(event))
  const newest = lists.sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1))[0]
  if (newest && newest.tags.some(tag => tag[0] === 'p' && tag[1] === pubkey))
    return ['done', `on the owner's writer list (${newest.id.slice(0, 12)}), so the relay takes its writes`]
  return ['pending', newest ? 'not on the owner\'s newest writer list yet: sign it on the page (step 3)' : 'no owner writer list on the relay yet: sign it on the page (step 3)']
}

export function installed(root) {
  const manifests = new Map()
  for (const file of readdirSync(root).filter(name => name.endsWith('.json')).sort()) {
    const id = file.slice(0, -5)
    manifests.set(id, readManifest(root, id))
  }
  return manifests
}

const lines = path => existsSync(path) ? readFileSync(path, 'utf8').split('\n').filter(Boolean).flatMap(line => {
  try { return [JSON.parse(line)] } catch { return [] }
}) : []

const mentions = (raw, pubkey) => (raw?.may_post?.mention || []).some(entry => (entry?.pubkey || entry) === pubkey)

// Writes a manifest in place the way an operator would: a dated backup first, never over an earlier
// one, then a same-owner, same-mode temporary renamed over it, then read back through readManifest.
export function rewrite(root, id, change, { backupRoot, now }) {
  const path = join(root, `${id}.json`), raw = JSON.parse(readFileSync(path, 'utf8'))
  const stamp = new Date(now()).toISOString().slice(0, 19).replace(/[-:T]/g, '')
  const dir = join(backupRoot, `${id}-backups-${stamp.slice(0, 8)}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  for (let n = 0; ; n++) {
    try { copyFileSync(path, join(dir, `${id}.json.pre-onboard-${stamp.slice(8)}${n ? `-${n}` : ''}`), constants.COPYFILE_EXCL); break } catch (error) {
      if (error.code !== 'EEXIST') throw error
    }
  }
  const st = statSync(path), temporary = `${path}.onboard.tmp`
  writeFileSync(temporary, JSON.stringify(change(raw), null, 2) + '\n', { mode: st.mode & 0o777 })
  try { chownSync(temporary, st.uid, st.gid) } catch {}
  renameSync(temporary, path)
  readManifest(root, id)
}

export async function onboard({ command, name, root, out, stateDir, keysPath = '', giversRedeploy = false,
  backupRoot = '/root', fetchEvents, runTool, joinWith, now = () => Date.now(), log = console.log,
  pair = null, report = null, readWriters = null, verify = () => false }) {
  if (!['show', 'run'].includes(command)) throw new OnboardRefusal('ONBOARD_USAGE', 'command is show or run')
  const ledger = join(stateDir, 'requests.jsonl')
  const rows = lines(ledger), seen = new Set(rows.filter(row => row.finished).map(row => row.id))
  const inProgress = new Set(rows.map(row => row.id))
  let manifests = installed(root)
  const owners = [...new Set([...manifests.values()].flatMap(manifest => manifest.grantors))]
  const relays = [...new Set([...manifests.values()].flatMap(manifest => manifest.relays))]
  const events = await fetchEvents({ relays, owners, name })
  const earlier = rows.filter(row => row.op === 'add_agent' && row.name === name && row.pubkey)
  const add = parseSetupRequest(newestRequest(events, name, 'add_agent'), { name, manifests, seen, inProgress, earlier, now: now() })
  let bind = null
  const bindEvent = newestRequest(events, name, 'bind_runtime')
  if (bindEvent) {
    bind = parseSetupRequest(bindEvent, { name, manifests, seen, now: now() })
    if (bind.pubkey !== add.pubkey || bind.owner !== add.owner) throw new OnboardRefusal('ONBOARD_BIND_MISMATCH', 'bind_runtime names a different key or owner than add_agent')
  }

  log(`request ${add.id.slice(0, 12)} from ${add.owner.slice(0, 8)}: add ${name} (${add.harness}) like ${add.like}`)
  for (const giver of add.givers)
    log(`  giver ${giver.pubkey.slice(0, 8)}: ${giver.seat ? `seat ${giver.seat}` : giver.owner ? 'the owner' : 'outside the fleet'}`)
  if (add.rooms.length) log(`  rooms ${add.rooms.join(', ')}`)
  log(`  bind_runtime: ${bind ? `${bind.channelKey.keyType} key, ${bind.id.slice(0, 12)}` : 'not yet'}`)
  if (command === 'show') return { request: add, bind, receipts: [] }

  mkdirSync(stateDir, { recursive: true, mode: 0o700 })
  if (!inProgress.has(add.id)) appendFileSync(ledger, JSON.stringify({ id: add.id, name, op: 'add_agent', at: now(),
    pubkey: add.pubkey, owner: add.owner, harness: add.harness, like: add.like }) + '\n')
  const receiptPath = join(stateDir, `${add.id}.jsonl`), receipts = []
  const receipt = (step, state, detail) => {
    const row = { step, state, at: now(), detail }
    receipts.push(row); appendFileSync(receiptPath, JSON.stringify(row) + '\n'); log(`${state.padEnd(8)} ${step}: ${detail}`)
    return state === 'done'
  }
  // Phase B: every row so far, this run's and earlier runs', goes to the owner after each step.
  // A receipt that no relay takes is logged; it never changes a step's state, but the request is not
  // marked finished until the receipt that shows it finished is out.
  let reported = !report
  const publish = async (extra = {}) => {
    if (!report) return
    try { await report({ request: add, rows: lines(receiptPath), ...extra }); reported = true }
    catch (error) { reported = false; log(`warning  receipt not published: ${error.message}`) }
  }
  const isInstalled = () => manifests.has(name)
  const stagedPath = join(out, `${name}.json`), stagedFor = join(out, `${name}.request`)

  const steps = [
    ['staged', () => {
      if (isInstalled()) return receipt('staged', 'done', 'installed already')
      // A staged manifest belongs to the request that made it. A newer signed request for this name is
      // staged afresh, so its template, not the earlier one's, is what gets installed.
      const owner = existsSync(stagedFor) ? readFileSync(stagedFor, 'utf8').trim() : ''
      if (existsSync(stagedPath) && owner !== add.id) renameSync(stagedPath, `${stagedPath}.superseded-${(owner || 'unknown').slice(0, 12)}`)
      if (!existsSync(stagedPath)) {
        const code = runTool('instance-identity.mjs', ['allocate', '--id', name, '--pubkey', add.pubkey, '--like', add.like, '--out', out, '--instance-root', root])
        if (code !== 0) return receipt('staged', 'refused', `allocate exited ${code}`)
        writeFileSync(stagedFor, `${add.id}\n`)
      }
      const raw = JSON.parse(readFileSync(stagedPath, 'utf8'))
      if (raw.pubkey !== add.pubkey) return receipt('staged', 'refused', 'a staged manifest for another key is in the way')
      if (!raw.may_set_profile) {
        const template = JSON.parse(readFileSync(join(root, `${add.like}.json`), 'utf8'))
        raw.may_set_profile = { kind: 0, pubkey: add.pubkey, grant_id: randomBytes(32).toString('hex'), per_day: 1,
          picture_hosts: template.may_set_profile?.picture_hosts || ['nave.pub'] }
        writeFileSync(stagedPath, JSON.stringify(raw, null, 2) + '\n')
      }
      try { readManifest(out, name) } catch (error) { return receipt('staged', 'refused', error.message) }
      return receipt('staged', 'done', `staged like ${add.like} with its profile grant, for request ${add.id.slice(0, 12)}`)
    }],
    ['paired', async () => {
      if (isInstalled()) return receipt('paired', 'done', 'installed already')
      const staged = readManifest(out, name), seated = [staged.bunkerUriRef, staged.bunkerClientRef].filter(path => path && existsSync(path))
      if (seated.length === 2) return receipt('paired', 'done', 'both credential files are seated')
      if (seated.length) return receipt('paired', 'refused', 'only one credential file is seated; remove it and run again')
      // In watch mode the link goes only into a receipt sealed to the owner, while pairing waits.
      let sent = null
      const code = pair ? await pair({ name, out, onUri: (uri, expiresAt) => { sent = publish({ pairing: { uri, made_at: Math.floor(now() / 1000), expires_at: expiresAt } }) } })
        : runTool('instance-pair.mjs', ['--id', name, '--out', out])
      await sent
      return code === 0 ? receipt('paired', 'done', 'the Bunker signs as this agent') :
        receipt('paired', 'pending', 'not approved in the Bunker yet; run again to make a new link')
    }],
    ['checked', () => {
      if (isInstalled()) return receipt('checked', 'done', 'installed already')
      const code = runTool('instance-identity.mjs', ['check', '--id', name, '--out', out, '--instance-root', root])
      return code === 0 ? receipt('checked', 'done', 'clear of every identity and block') : receipt('checked', 'refused', `check exited ${code}`)
    }],
    ['started', () => {
      if (isInstalled()) return receipt('started', 'done', 'installed')
      if (!bind) return receipt('started', 'pending', 'waiting for bind_runtime: the install line on the agent\'s box')
      if (!keysPath) return receipt('started', 'pending', 'give --authorized-keys for the channel account')
      const pub = join(stateDir, `${add.id}.channel.pub`)
      writeFileSync(pub, `${bind.channelKey.keyType} ${bind.channelKey.keyBody} nvoy-onboard-${name}\n`, { mode: 0o644 })
      const code = runTool('instance-identity.mjs', ['apply', '--id', name, '--public-key-file', pub, '--authorized-keys', keysPath, '--out', out, '--instance-root', root])
      manifests = installed(root)
      return code === 0 && isInstalled() ? receipt('started', 'done', 'applied, principal seated, channel baselined') :
        receipt('started', code === 3 ? 'pending' : 'refused', `apply exited ${code}`)
    }],
    // The name the owner gave, queued for the agent's own broker to sign and publish as its first
    // kind 0 (waggle #717). The request id comes from the name and the fields, so a run again, or the
    // same request signed again, queues nothing new; a changed name is a new request.
    ['profile', () => {
      if (!add.profile) return receipt('profile', 'done', 'no name in the request; the agent sets its own profile')
      if (!isInstalled()) return receipt('profile', 'pending', 'waiting for the agent to start')
      const manifest = manifests.get(name)
      const request = createHash('sha256').update(JSON.stringify([name, add.profile])).digest('hex').slice(0, 32)
      if (!manifest.maySetProfile) return receipt('profile', 'refused', `${name} has no may_set_profile grant`)
      const queued = queueProfile(manifest, { fields: { ...add.profile }, request })
      if (queued.error) {
        const waiting = queued.error.code === 'NVOY_PROFILE_QUEUE_FAILED' && /not provisioned/.test(queued.error.message || '')
        return receipt('profile', waiting ? 'pending' : 'refused', waiting ? 'waiting for the agent to start: its profile queue is not there yet' : `${queued.error.code}${queued.error.message ? `: ${queued.error.message}` : ''}`)
      }
      // Run as root, the reservation is made root's; give it to the agent's worker, like its own.
      if (process.getuid?.() === 0) chownSync(join(profileRequestIdsPath(manifest), request), manifest.workerUid, manifest.workerUid)
      const queuedLine = `"${add.profile.name}" queued for ${name}'s broker to sign and publish`
      // Only a results log that is not there yet is waiting: the broker writes it on its first answer.
      // A log that is there but cannot be read (a link, not a file, unreadable) is a fault to surface.
      let absent = false
      try { lstatSync(profileResultsPath(manifest)) } catch (error) { absent = error?.code === 'ENOENT' }
      if (absent) return receipt('profile', 'pending', queuedLine)
      const status = profileStatus(manifest, request)
      if (status.error?.code === 'NVOY_PROFILE_STATUS_FAILED') return receipt('profile', 'refused', `cannot read ${name}'s profile results: ${status.error.message || 'unknown error'}`)
      if (status.error) return receipt('profile', 'refused', `the broker refused it: ${status.error.code || 'error'}`)
      if (status.ok.pending) return receipt('profile', 'pending', queuedLine)
      // Done only when Buzz read the signed profile back field for field and every public relay took
      // it. A partial row is still retrying; a relay that refused, or that the broker gave up on, fails.
      const row = status.ok, legs = Array.isArray(row.public_relays) ? row.public_relays : []
      const failed = legs.filter(leg => leg?.state === 'refused' || leg?.state === 'gave_up').map(leg => leg.relay)
      if (failed.length) return receipt('profile', 'refused', `${name}'s profile did not reach ${failed.join(', ')}`)
      const waiting = legs.filter(leg => leg?.state === 'pending').map(leg => leg.relay)
      if (row.partial || waiting.length) return receipt('profile', 'pending', `"${add.profile.name}" is on Buzz; ${name}'s broker is still retrying ${waiting.join(', ') || 'the public relays'}`)
      const fields = row.readback && typeof row.readback === 'object' ? Object.values(row.readback) : []
      if (!fields.length || !fields.every(field => field?.match === true)) return receipt('profile', 'refused', `${name}'s broker could not read "${add.profile.name}" back from Buzz`)
      return receipt('profile', 'done', `${name}'s broker published "${add.profile.name}", read back from Buzz and accepted by ${legs.length} public relay${legs.length === 1 ? '' : 's'}`)
    }],
    ['givers', () => {
      const seats = add.givers.filter(giver => giver.seat)
      // A giver with mention_rooms on that shares a room with the new agent needs no rewrite (#321):
      // the rooms step proves the join, and its roster makes the agent mentionable there.
      const viaRoom = new Map()
      const missing = seats.filter(giver => {
        const raw = JSON.parse(readFileSync(join(root, `${giver.seat}.json`), 'utf8'))
        if (mentions(raw, add.pubkey)) return false
        const shared = raw?.may_post?.mention_rooms === true && (raw.may_post.channels || []).find(c => add.rooms.includes(String(c).toLowerCase()))
        if (shared) { viaRoom.set(giver.seat, String(shared).toLowerCase()); return false }
        return true
      })
      const rooms = [...viaRoom].map(([seat, room]) => `; ${seat} can mention ${name} through room ${room}`).join('')
      const outside = add.givers.filter(giver => giver.outside).map(giver => giver.pubkey.slice(0, 8))
      const tail = outside.length ? `; outside the fleet, nothing run: ${outside.join(', ')}` : ''
      if (!missing.length) return receipt('givers', outside.length ? 'pending' : 'done', `every seat giver can mention ${name}${rooms}${tail}`)
      if (!giversRedeploy) return receipt('givers', 'pending', `run again with --givers-redeploy: it redeploys ${missing.map(giver => giver.seat).join(', ')}${tail}`)
      for (const giver of missing) rewrite(root, giver.seat, raw => {
        if (!raw.may_post) throw new OnboardRefusal('ONBOARD_GIVER_NO_POST', `${giver.seat} has no may_post block`)
        raw.may_post.mention = [...(raw.may_post.mention || []), { name, pubkey: add.pubkey }]
        return raw
      }, { backupRoot, now })
      manifests = installed(root)
      return receipt('givers', outside.length ? 'pending' : 'done', `added ${name} to ${missing.map(giver => giver.seat).join(', ')}${tail}`)
    }],
    ['relay writer', async () => {
      if (!readWriters) return receipt('relay writer', 'pending', 'not read: this run has no relay to read the owner\'s writer list from')
      const [state, detail] = writerVerdict(await readWriters({ owners: [add.owner] }), { owners: [add.owner], pubkey: add.pubkey, verify })
      return receipt('relay writer', state, detail)
    }],
    ['hive', async () => {
      if (!isInstalled()) return receipt('hive', 'pending', 'waiting for the agent to start')
      const manifest = manifests.get(name)
      if (!manifest.buzz) return receipt('hive', 'refused', `${add.like} has no Buzz relay to copy, so there is no hive to join`)
      agentLink = await joinWith(manifest)
      const joined = await joinHive({ add, relay: manifest.buzz.relay, signer: agentLink.signer, open: agentLink.open, fetchImpl: agentLink.fetchImpl })
      session = joined.session || null
      return receipt('hive', joined.state, joined.detail)
    }],
    ['rooms', async () => {
      if (!session) return receipt('rooms', 'pending', 'waiting for the hive')
      const rooms = await joinRooms({ add, session, now, relaySigner: manifests.get(name)?.buzz?.relaySigner || null })
      return receipt('rooms', rooms.state, rooms.detail)
    }],
  ]
  // Stop at the first step that is not done. After those four, givers, the relay writer and the hive
  // do not depend on each other; rooms waits for the hive's login.
  let agentLink = null, session = null
  try {
    for (const [index, [, step]] of steps.entries()) {
      const done = await step()
      await publish()
      if (!done && index < 4) break
    }
  } finally { session?.close?.(); agentLink?.close?.() }
  if (receipts.every(row => row.state === 'done')) {
    if (reported) appendFileSync(ledger, JSON.stringify({ id: add.id, name, op: 'add_agent', at: now(), finished: true }) + '\n')
    else log('pending  finished: every step is done, but the owner has not been told; the next run sends the receipt again')
  }
  return { request: add, bind, receipts }
}
