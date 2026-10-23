import { appendFileSync, existsSync, lstatSync, readFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { resolve } from 'node:path'
import { credentialIn } from './outbound_secrets.mjs'

const HEX32 = /^[0-9a-f]{32}$/
export const PROFILE_FIELDS = Object.freeze(['name', 'display_name', 'about', 'picture', 'website', 'nip05'])
export const profileQueuePath = manifest => resolve(manifest.runtimeDir, 'profile-requests.jsonl')
export const profileResultsPath = manifest => resolve(manifest.runtimeDir, 'profile-results.jsonl')

export function profileToolSpec(manifest) {
  const grant = manifest.maySetProfile
  return {
    name: 'nvoy_profile_set',
    description: grant
      ? `Propose changes to this seat's kind-0 profile. The broker merges and validates the fields, then signs and publishes under manifest grant ${grant.grantId}. Dry run validates without signing kind 0. Rolling 24-hour limit: ${grant.perDay}. Allowed picture hosts: ${grant.pictureHosts.join(', ')}.`
      : 'Profile changes are refused because this seat has no may_set_profile grant.',
    inputSchema: { type: 'object', properties: {
      fields: { type: 'object', properties: Object.fromEntries(PROFILE_FIELDS.map(field => [field, { type: 'string' }])),
        minProperties: 1, additionalProperties: false },
      dry_run: { type: 'boolean' },
      request: { type: 'string', pattern: HEX32.source },
    }, required: ['fields'], additionalProperties: false },
  }
}

export const profileStatusToolSpec = () => ({ name: 'nvoy_profile_status',
  description: 'Read the broker result for one exact profile request ID.',
  inputSchema: { type: 'object', properties: { request: { type: 'string', pattern: HEX32.source } },
    required: ['request'], additionalProperties: false } })

export function validateProfileRequest(row, manifest) {
  if (!row || typeof row !== 'object' || Array.isArray(row) ||
      Object.keys(row).some(key => !['version', 'type', 'id', 'instance', 'fields', 'dry_run', 'requested_at'].includes(key)) ||
      row.version !== 1 || row.type !== 'profile-request' || row.instance !== manifest.id ||
      !HEX32.test(String(row.id || '')) || typeof row.dry_run !== 'boolean' ||
      !Number.isFinite(row.requested_at)) throw new Error('NVOY_PROFILE_BAD_REQUEST')
  if (!manifest.maySetProfile || manifest.maySetProfile.kind !== 0 ||
      manifest.maySetProfile.pubkey !== manifest.pubkey) throw new Error('NVOY_PROFILE_NOT_PERMITTED')
  const fields = row.fields
  if (!fields || typeof fields !== 'object' || Array.isArray(fields) || !Object.keys(fields).length ||
      Object.keys(fields).some(key => !PROFILE_FIELDS.includes(key) || typeof fields[key] !== 'string') ||
      Buffer.byteLength(JSON.stringify(fields)) > 8192) throw new Error('NVOY_PROFILE_BAD_FIELDS')
  if (credentialIn(JSON.stringify(fields))) throw new Error('NVOY_WITHHELD_CREDENTIAL')
  return row
}

export function queueProfile(manifest, args = {}, now = Date.now()) {
  const row = { version: 1, type: 'profile-request', id: args.request || randomBytes(16).toString('hex'),
    instance: manifest.id, fields: args.fields, dry_run: args.dry_run ?? false, requested_at: now }
  try { validateProfileRequest(row, manifest) }
  catch (error) { return { error: { code: error.message,
    ...(error.message === 'NVOY_WITHHELD_CREDENTIAL' ? { message: 'profile contains a credential; nothing was published' } : {}) } } }
  const path = profileQueuePath(manifest)
  if (!existsSync(path)) return { error: { code: 'NVOY_PROFILE_QUEUE_FAILED', message: 'profile request queue is not provisioned' } }
  try {
    const stat = lstatSync(path)
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024 * 1024) throw new Error('profile request queue is invalid')
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      let existing
      try { existing = JSON.parse(line) } catch { continue }
      if (existing?.id !== row.id) continue
      if (existing.instance !== row.instance || existing.dry_run !== row.dry_run ||
          JSON.stringify(existing.fields) !== JSON.stringify(row.fields))
        return { error: { code: 'NVOY_PROFILE_REQUEST_CONFLICT', message: 'request ID belongs to different profile fields' } }
      return { ok: { queued: true, request: row.id, repeat: true } }
    }
    appendFileSync(path, JSON.stringify(row) + '\n')
    return { ok: { queued: true, request: row.id } }
  } catch (error) { return { error: { code: 'NVOY_PROFILE_QUEUE_FAILED', message: error.message } } }
}

export function profileStatus(manifest, request) {
  if (!HEX32.test(String(request || ''))) return { error: { code: 'NVOY_PROFILE_BAD_REQUEST' } }
  if (!manifest.maySetProfile) return { error: { code: 'NVOY_PROFILE_NOT_PERMITTED' } }
  try {
    const path = profileResultsPath(manifest)
    const stat = lstatSync(path)
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024 * 1024) throw new Error('profile result log is invalid')
    const rows = readFileSync(path, 'utf8').split('\n')
    for (let index = rows.length - 1; index >= 0; index--) {
      let row
      try { row = JSON.parse(rows[index]) } catch { continue }
      if (row?.version === 1 && row.type === 'profile-result' && row.instance === manifest.id && row.request === request)
        return row.error ? { error: row } : { ok: row }
    }
    return { ok: { pending: true, request } }
  } catch (error) { return { error: { code: 'NVOY_PROFILE_STATUS_FAILED', message: error.message } } }
}

export async function waitProfile(manifest, request, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const status = profileStatus(manifest, request)
    if (status.error || !status.ok.pending) return status
    await new Promise(resolve => setTimeout(resolve, 250))
  }
  return { ok: { pending: true, request } }
}
