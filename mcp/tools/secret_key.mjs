// Decodes a secret key read from a credential, and on failure names the credential, never the
// value. The bech32 decoder puts its whole input in its errors (@scure/base: "Invalid checksum in
// <input>"), so on 10-23 a broker that died on a malformed transport key logged the key itself.
// `source` is the env var or file path the value came from.

import { decode } from 'nostr-tools/nip19'

const HEX64 = /^[0-9a-f]{64}$/i

export function secretKey(raw, source, { hex = true } = {}) {
  const text = String(raw ?? '').trim()
  if (hex && HEX64.test(text)) return Uint8Array.from(Buffer.from(text, 'hex'))
  let decoded
  try { decoded = decode(text) } catch { decoded = null }
  if (decoded?.type !== 'nsec' || decoded.data?.length !== 32) throw new Error(`${source} is not a valid ${hex ? 'nsec or 64-char hex key' : 'nsec'}`)
  return decoded.data
}
