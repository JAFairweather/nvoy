import { isDeepStrictEqual } from 'node:util'
import { verifyEvent } from 'nostr-tools/pure'
import { PROFILE_FIELDS } from './agent_profile.mjs'
import { credentialIn } from './outbound_secrets.mjs'

const MAX_LENGTH = Object.freeze({ name: 64, display_name: 128, about: 1024, picture: 2048, website: 2048, nip05: 128 })
const HEX64 = /^[0-9a-f]{64}$/

export class ProfileRefusal extends Error {
  constructor(code, message) { super(message); this.code = code }
}

function profileObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ProfileRefusal('NVOY_PROFILE_INVALID_CURRENT', 'current profile is not a JSON object')
  if (Buffer.byteLength(JSON.stringify(value)) > 16384) throw new ProfileRefusal('NVOY_PROFILE_INVALID_CURRENT', 'current profile exceeds 16 KiB')
  return value
}

function httpsUrl(value, field, hosts) {
  let url
  try { url = new URL(value) } catch { throw new ProfileRefusal(`NVOY_PROFILE_BAD_${field.toUpperCase()}`, `${field} must be an HTTPS URL`) }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname || (hosts && url.port) ||
      (hosts && !hosts.includes(url.hostname.toLowerCase())))
    throw new ProfileRefusal(`NVOY_PROFILE_BAD_${field.toUpperCase()}`, `${field} must be HTTPS on an allowed host`)
}

export async function mergedProfile(current, fields, { pubkey, pictureHosts, fetchJson = async url => {
  const response = await fetch(url, { signal: AbortSignal.timeout(10000) })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json()
} }) {
  profileObject(current)
  if (!HEX64.test(String(pubkey || '')) || !Array.isArray(pictureHosts)) throw new ProfileRefusal('NVOY_PROFILE_SCOPE_INVALID', 'profile grant scope is invalid')
  if (!fields || typeof fields !== 'object' || Array.isArray(fields) || !Object.keys(fields).length ||
      Object.keys(fields).some(field => !PROFILE_FIELDS.includes(field) || typeof fields[field] !== 'string'))
    throw new ProfileRefusal('NVOY_PROFILE_BAD_FIELDS', 'only the six allowed string fields may be changed')
  const profile = { ...current, ...fields, bot: true }
  if (Buffer.byteLength(JSON.stringify(profile)) > 16384) throw new ProfileRefusal('NVOY_PROFILE_TOO_LARGE', 'merged profile exceeds 16 KiB')
  if (credentialIn(JSON.stringify(profile))) throw new ProfileRefusal('NVOY_WITHHELD_CREDENTIAL', 'merged profile contains a credential')
  for (const field of PROFILE_FIELDS.filter(key => Object.hasOwn(profile, key))) {
    const value = profile[field]
    if (typeof value !== 'string') throw new ProfileRefusal('NVOY_PROFILE_BAD_FIELDS', `${field} must be a string`)
    if (Buffer.byteLength(value) > MAX_LENGTH[field]) throw new ProfileRefusal('NVOY_PROFILE_FIELD_TOO_LONG', `${field} exceeds ${MAX_LENGTH[field]} bytes`)
    if (field === 'name' && !value.trim()) throw new ProfileRefusal('NVOY_PROFILE_BAD_NAME', 'name cannot be blank')
    if (field === 'picture' && value) httpsUrl(value, field, pictureHosts)
    if (field === 'nip05' && value) {
      const match = value.toLowerCase().match(/^([a-z0-9._-]+)@nave\.pub$/)
      if (!match) throw new ProfileRefusal('NVOY_PROFILE_BAD_NIP05', 'nip05 must be a nave.pub name')
      let directory
      try { directory = await fetchJson(`https://nave.pub/.well-known/nostr.json?name=${encodeURIComponent(match[1])}`) }
      catch (error) { throw new ProfileRefusal('NVOY_PROFILE_NIP05_UNAVAILABLE', `nip05 lookup failed: ${error.message}`) }
      if (String(directory?.names?.[match[1]] || '').toLowerCase() !== pubkey)
        throw new ProfileRefusal('NVOY_PROFILE_NIP05_MISMATCH', 'nip05 does not resolve to this seat')
    }
  }
  const changed = Object.fromEntries([...Object.keys(fields), 'bot'].filter(field => !isDeepStrictEqual(current[field], profile[field]))
    .map(field => [field, { old: current[field] ?? null, new: profile[field] }]))
  return { profile, changed }
}

export function readbackProfile(events, signedEvent, profile) {
  const matching = (Array.isArray(events) ? events : []).find(event => event?.id === signedEvent.id)
  if (!matching || matching.pubkey !== signedEvent.pubkey || matching.kind !== 0 ||
      !verifyEvent(JSON.parse(JSON.stringify(matching))))
    throw new ProfileRefusal('NVOY_PROFILE_READBACK_MISMATCH', 'relay did not return the signed kind-0 event')
  let actual
  try { actual = profileObject(JSON.parse(matching.content)) }
  catch { throw new ProfileRefusal('NVOY_PROFILE_READBACK_MISMATCH', 'relay returned invalid profile content') }
  if (!isDeepStrictEqual(actual, profile)) throw new ProfileRefusal('NVOY_PROFILE_READBACK_MISMATCH', 'relay profile fields differ from the signed event')
  return Object.fromEntries(Object.keys(profile).sort().map(field => [field, { expected: profile[field], actual: actual[field], match: true }]))
}
