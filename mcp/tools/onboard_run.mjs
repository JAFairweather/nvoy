// onboard_run.mjs — the steps nvoy-onboard runs for one setup request, phase A (#289).
//
// Each step is an existing tool. A step is done when the state it makes is there, not because a
// receipt says so, so a second run does each thing once and carries on where the first stopped:
// after the owner approves the pairing, after the box's bind_runtime arrives, or after the operator
// agrees to redeploy the givers. Receipts record what each run found; they never hold a secret.

import { appendFileSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync, chownSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { readManifest } from './runtime_manifest.mjs'
import { newestRequest, OnboardRefusal, parseSetupRequest } from './onboard_request.mjs'

const PENDING_RELAY = 'the relay writer list is nave.pub #157; until it lands, add the key to deploy/relay/allowlist.json by PR'
const PENDING_HIVE = 'the sealed invite is not built; until it is, the owner sends the invite and the agent claims it'

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

// Writes a manifest in place the way an operator would: a dated backup first, then a same-owner,
// same-mode temporary renamed over it, then read back through readManifest.
function rewrite(root, id, change, { backupRoot, now }) {
  const path = join(root, `${id}.json`), raw = JSON.parse(readFileSync(path, 'utf8'))
  const stamp = new Date(now()).toISOString().slice(0, 16).replace(/[-:T]/g, '')
  const dir = join(backupRoot, `${id}-backups-${stamp.slice(0, 8)}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  copyFileSync(path, join(dir, `${id}.json.pre-onboard-${stamp.slice(8)}`))
  const st = statSync(path), temporary = `${path}.onboard.tmp`
  writeFileSync(temporary, JSON.stringify(change(raw), null, 2) + '\n', { mode: st.mode & 0o777 })
  try { chownSync(temporary, st.uid, st.gid) } catch {}
  renameSync(temporary, path)
  readManifest(root, id)
}

export async function onboard({ command, name, root, out, stateDir, keysPath = '', giversRedeploy = false,
  backupRoot = '/root', fetchEvents, runTool, now = () => Date.now(), log = console.log }) {
  if (!['show', 'run'].includes(command)) throw new OnboardRefusal('ONBOARD_USAGE', 'command is show or run')
  mkdirSync(stateDir, { recursive: true, mode: 0o700 })
  const ledger = join(stateDir, 'requests.jsonl')
  const rows = lines(ledger), seen = new Set(rows.filter(row => row.finished).map(row => row.id))
  const inProgress = new Set(rows.map(row => row.id))
  let manifests = installed(root)
  const owners = [...new Set([...manifests.values()].flatMap(manifest => manifest.grantors))]
  const relays = [...new Set([...manifests.values()].flatMap(manifest => manifest.relays))]
  const events = await fetchEvents({ relays, owners, name })
  const add = parseSetupRequest(newestRequest(events, name, 'add_agent'), { name, manifests, seen, inProgress, now: now() })
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

  if (!inProgress.has(add.id)) appendFileSync(ledger, JSON.stringify({ id: add.id, name, op: 'add_agent', at: now() }) + '\n')
  const receiptPath = join(stateDir, `${add.id}.jsonl`), receipts = []
  const receipt = (step, state, detail) => {
    const row = { step, state, at: now(), detail }
    receipts.push(row); appendFileSync(receiptPath, JSON.stringify(row) + '\n'); log(`${state.padEnd(8)} ${step}: ${detail}`)
    return state === 'done'
  }
  const isInstalled = () => manifests.has(name)
  const stagedPath = join(out, `${name}.json`)

  const steps = [
    ['staged', () => {
      if (isInstalled()) return receipt('staged', 'done', 'installed already')
      if (!existsSync(stagedPath)) {
        const code = runTool('instance-identity.mjs', ['allocate', '--id', name, '--pubkey', add.pubkey, '--like', add.like, '--out', out, '--instance-root', root])
        if (code !== 0) return receipt('staged', 'refused', `allocate exited ${code}`)
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
      return receipt('staged', 'done', `staged with its profile grant`)
    }],
    ['paired', () => {
      if (isInstalled()) return receipt('paired', 'done', 'installed already')
      const staged = readManifest(out, name), seated = [staged.bunkerUriRef, staged.bunkerClientRef].filter(path => path && existsSync(path))
      if (seated.length === 2) return receipt('paired', 'done', 'both credential files are seated')
      if (seated.length) return receipt('paired', 'refused', 'only one credential file is seated; remove it and run again')
      const code = runTool('instance-pair.mjs', ['--id', name, '--out', out])
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
    ['givers', () => {
      const seats = add.givers.filter(giver => giver.seat)
      const missing = seats.filter(giver => !mentions(JSON.parse(readFileSync(join(root, `${giver.seat}.json`), 'utf8')), add.pubkey))
      const outside = add.givers.filter(giver => giver.outside).map(giver => giver.pubkey.slice(0, 8))
      const tail = outside.length ? `; outside the fleet, nothing run: ${outside.join(', ')}` : ''
      if (!missing.length) return receipt('givers', outside.length ? 'pending' : 'done', `every seat giver can mention ${name}${tail}`)
      if (!giversRedeploy) return receipt('givers', 'pending', `run again with --givers-redeploy: it redeploys ${missing.map(giver => giver.seat).join(', ')}${tail}`)
      for (const giver of missing) rewrite(root, giver.seat, raw => {
        if (!raw.may_post) throw new OnboardRefusal('ONBOARD_GIVER_NO_POST', `${giver.seat} has no may_post block`)
        raw.may_post.mention = [...(raw.may_post.mention || []), { name, pubkey: add.pubkey }]
        return raw
      }, { backupRoot, now })
      manifests = installed(root)
      return receipt('givers', outside.length ? 'pending' : 'done', `added ${name} to ${missing.map(giver => giver.seat).join(', ')}${tail}`)
    }],
    ['relay writer', () => receipt('relay writer', 'pending', PENDING_RELAY)],
    ['hive and rooms', () => receipt('hive and rooms', 'pending', PENDING_HIVE)],
  ]
  // Stop at the first step that is not done, except the last three, which do not depend on each other.
  for (const [index, [, step]] of steps.entries()) {
    const done = step()
    if (!done && index < 4) break
  }
  if (receipts.every(row => row.state === 'done')) appendFileSync(ledger, JSON.stringify({ id: add.id, name, op: 'add_agent', at: now(), finished: true }) + '\n')
  return { request: add, bind, receipts }
}
