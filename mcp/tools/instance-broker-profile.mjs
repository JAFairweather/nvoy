#!/usr/bin/env node
import { appendFileSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import { getEventHash, verifyEvent } from 'nostr-tools/pure'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { validateProfileRequest, profileQueuePath, profileResultsPath } from './agent_profile.mjs'
import { mergedProfile, ProfileRefusal, readbackProfile } from './profile_policy.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { openBuzzSession } from './buzz_native.mjs'
import { countInWindow } from './agent_limits.mjs'

const flag = name => { const index = process.argv.indexOf(name); return index < 0 ? '' : process.argv[index + 1] || '' }
const id = flag('--instance'), requestId = flag('--request').toLowerCase()
if (!id || !/^[0-9a-f]{32}$/.test(requestId)) throw new Error('usage: --instance <id> --request <32-hex-id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
const manifest = readManifest(root, instanceId(id))
assertNoCollisions(root, manifest)
const grant = manifest.maySetProfile
const resultsPath = profileResultsPath(manifest)
const auditPath = resolve(manifest.stateDir, 'profile-audit.jsonl')
const recordDir = resolve(manifest.stateDir, 'profiles')
let signer, session, request, record, changedForAudit = {}

function appendResult(result) {
  appendFileSync(resultsPath, JSON.stringify({ version: 1, type: 'profile-result', instance: manifest.id,
    request: requestId, ...result }) + '\n')
}
function audit(result) {
  appendFileSync(auditPath, JSON.stringify({ version: 1, at: Date.now(), seat: manifest.pubkey,
    grant_id: grant?.grantId || null, request: requestId, dry_run: request?.dry_run ?? null,
    changed: record?.changed || changedForAudit, event_id: record?.event?.id || null,
    outcome: result?.code || (result?.dry_run ? 'dry_run' : 'accepted') }) + '\n', { mode: 0o600 })
}
function finish(result) {
  audit(result)
  appendResult(result)
  console.log(JSON.stringify({ request: requestId, code: result.code || 'ok', event_id: result.event_id || null }))
  process.exitCode = 0
}
function persist() {
  mkdirSync(recordDir, { recursive: true, mode: 0o700 })
  const path = resolve(recordDir, `${requestId}.json`), temporary = `${path}.${process.pid}.tmp`
  writeFileSync(temporary, JSON.stringify(record), { mode: 0o600 })
  renameSync(temporary, path)
}
function latestProfile(events) {
  const latest = (Array.isArray(events) ? events : []).filter(event => event?.kind === 0 && event.pubkey === manifest.pubkey &&
    verifyEvent(JSON.parse(JSON.stringify(event)))).sort((left, right) => right.created_at - left.created_at || right.id.localeCompare(left.id))[0]
  if (!latest) throw new ProfileRefusal('NVOY_PROFILE_INVALID_CURRENT',
    events.length ? 'relay returned an invalid kind-0 event' : 'relay returned no current kind-0 event')
  try { return JSON.parse(latest.content) }
  catch { throw new ProfileRefusal('NVOY_PROFILE_INVALID_CURRENT', 'current kind-0 content is invalid JSON') }
}

try {
  const queue = profileQueuePath(manifest), stat = lstatSync(queue)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024 * 1024) throw new ProfileRefusal('NVOY_PROFILE_BAD_REQUEST', 'profile queue is invalid')
  for (const line of readFileSync(queue, 'utf8').split('\n')) {
    try { const candidate = JSON.parse(line); if (candidate?.id === requestId) { request = candidate; break } } catch {}
  }
  if (!request) throw new ProfileRefusal('NVOY_PROFILE_BAD_REQUEST', 'profile request is missing')
  validateProfileRequest(request, manifest)
  const digest = createHash('sha256').update(JSON.stringify({ fields: request.fields, dry_run: request.dry_run })).digest('hex')
  const path = resolve(recordDir, `${requestId}.json`)
  if (existsSync(path)) {
    const saved = lstatSync(path)
    if (!saved.isFile() || saved.isSymbolicLink()) throw new ProfileRefusal('NVOY_PROFILE_RECORD_INVALID', 'profile record is invalid')
    record = JSON.parse(readFileSync(path, 'utf8'))
    if (record?.version !== 1 || record.request_digest !== digest || record.grant_id !== grant.grantId ||
        record.pubkey !== manifest.pubkey || !record.unsigned_event || getEventHash(record.unsigned_event) !== record.fingerprint ||
        (record.event && (record.event.id !== record.fingerprint || !verifyEvent(JSON.parse(JSON.stringify(record.event))))))
      throw new ProfileRefusal('NVOY_PROFILE_RECORD_INVALID', 'profile record does not bind this request and grant')
  }

  if (!record) {
    ;({ signer } = brokerSigner(message => { throw new Error(message) }, { idleMs: 30000 }))
    const signerPubkey = String(await signer.getPublicKey()).toLowerCase()
    if (signerPubkey !== manifest.pubkey) throw new ProfileRefusal('NVOY_PROFILE_SIGNER_MISMATCH', 'signer does not match manifest pubkey')
    session = await openBuzzSession({ relay: manifest.buzz.relay, signer })
    const current = latestProfile(await session.fetch({ kinds: [0], authors: [manifest.pubkey], limit: 1 }))
    const { profile, changed } = await mergedProfile(current, request.fields, { pubkey: manifest.pubkey, pictureHosts: grant.pictureHosts })
    changedForAudit = changed
    if (request.dry_run) {
      finish({ dry_run: true, candidate: profile, changed, event_id: null, relay: null })
    } else {
      const verdict = countInWindow(resolve(manifest.stateDir, 'agent-limits', 'profiles.json'),
        { key: 'profile', id: requestId, limit: grant.perDay, windowMs: 24 * 60 * 60 * 1000 })
      if (!verdict.allowed) throw new ProfileRefusal('NVOY_PROFILE_RATE_LIMITED', `profile budget ${verdict.count}/${grant.perDay} in the last day`)
      const unsignedEvent = { pubkey: manifest.pubkey, kind: 0, created_at: Math.floor(Date.now() / 1000),
        tags: [], content: JSON.stringify(profile) }
      record = { version: 1, request_digest: digest, grant_id: grant.grantId, pubkey: manifest.pubkey,
        fingerprint: getEventHash(unsignedEvent), unsigned_event: unsignedEvent, profile, changed, event: null }
      persist()
    }
  }

  if (record) {
    if (!signer) {
      ;({ signer } = brokerSigner(message => { throw new Error(message) }, { idleMs: 30000 }))
      const signerPubkey = String(await signer.getPublicKey()).toLowerCase()
      if (signerPubkey !== manifest.pubkey) throw new ProfileRefusal('NVOY_PROFILE_SIGNER_MISMATCH', 'signer does not match manifest pubkey')
    }
    if (!record.event) {
      const event = await signer.signEvent(record.unsigned_event)
      if (event?.id !== record.fingerprint || event.pubkey !== manifest.pubkey || event.kind !== 0 ||
          !verifyEvent(JSON.parse(JSON.stringify(event))))
        throw new ProfileRefusal('NVOY_PROFILE_SIGNER_MISMATCH', 'signer changed or invalidly signed the frozen profile')
      record.event = event
      persist()
    }
    if (!session) session = await openBuzzSession({ relay: manifest.buzz.relay, signer })
    const published = await session.publishSigned(record.event)
    if (!published.accepted) throw new ProfileRefusal('NVOY_PROFILE_RELAY_REFUSED', published.message || 'Buzz relay refused profile')
    const events = await session.fetch({ kinds: [0], authors: [manifest.pubkey], limit: 1 })
    const readback = readbackProfile(events, record.event, record.profile)
    finish({ event_id: record.event.id, relay: { accepted: true, message: published.message },
      changed: record.changed, readback })
  }
} catch (error) {
  const code = error instanceof ProfileRefusal ? error.code :
    error.message?.startsWith('NVOY_PROFILE_') || error.message === 'NVOY_WITHHELD_CREDENTIAL' ? error.message : 'NVOY_PROFILE_RETRYABLE'
  if (code === 'NVOY_PROFILE_RETRYABLE') {
    console.error(`instance-broker-profile: retryable ${requestId}: ${error.message}`)
    process.exitCode = 1
  } else {
    finish({ error: true, code, message: error.message, event_id: record?.event?.id || null,
      ...(code === 'NVOY_PROFILE_RELAY_REFUSED' ? { relay: { accepted: false, message: error.message } } : {}) })
  }
} finally {
  session?.close()
  try { signer?.close?.() } catch {}
}
