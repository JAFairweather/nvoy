// The operator's wake-webhook credentials: one file holding the URL, one holding the auth headers in
// `curl -H @file` form. Both are secrets, so no error here ever repeats a value, a header name, or
// the URL; a refusal names only the file's label and, for headers, the line number.

import { lstatSync, readFileSync } from 'node:fs'

export const MAX_URL_FILE = 2048, MAX_HEADERS_FILE = 8192, MAX_HEADERS = 16
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const VALUE = /^[\x20-\x7e\t]+$/
// The notifier sets these itself, or they would let a header file reshape the request's framing.
const RESERVED = new Set(['host', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'upgrade', 'te', 'trailer',
  'keep-alive', 'expect', 'proxy-connection'])

export function readCredential(path, label, max) {
  let st
  try { st = lstatSync(path) } catch { throw new Error(`${label} is missing`) }
  if (!st.isFile() || st.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`)
  if (st.mode & 0o077) throw new Error(`${label} must be owner-only`)
  if (st.size > max) throw new Error(`${label} exceeds its ${max}-byte bound`)
  const text = readFileSync(path, 'utf8')
  if (Buffer.byteLength(text) > max) throw new Error(`${label} exceeds its ${max}-byte bound`)
  return text
}

export function parseWebhookUrl(text) {
  const line = String(text).replace(/\n$/, '')
  if (/[\r\n]/.test(line)) throw new Error('wake webhook URL file must hold exactly one line')
  if (!line || /[\s\x00-\x1f\x7f]/.test(line)) throw new Error('wake webhook URL must be one URL with no whitespace or control characters')
  let url
  try { url = new URL(line) } catch { throw new Error('wake webhook URL is not a valid URL') }
  if (url.protocol !== 'https:') throw new Error('wake webhook URL must use https')
  if (url.username || url.password) throw new Error('wake webhook URL must not carry user info; put credentials in the headers file')
  if (url.hash || !url.hostname) throw new Error('wake webhook URL must name a host and carry no fragment')
  return url.href
}

export function parseWebhookHeaders(text) {
  const source = String(text)
  if (source.includes('\r')) throw new Error('wake webhook headers must not contain a carriage return')
  const headers = [], seen = new Set()
  source.split('\n').forEach((line, index) => {
    if (!line.trim()) return
    const at = line.indexOf(':'), where = `wake webhook headers line ${index + 1}`
    if (at <= 0) throw new Error(`${where} is not "Name: value"`)
    const name = line.slice(0, at), value = line.slice(at + 1).trim()
    if (!TOKEN.test(name)) throw new Error(`${where}: the name is not an RFC 7230 token`)
    if (!value || !VALUE.test(value)) throw new Error(`${where}: the value must be non-empty printable ASCII`)
    if (RESERVED.has(name.toLowerCase())) throw new Error(`${where} names a header the notifier sets itself`)
    if (seen.has(name.toLowerCase())) throw new Error(`${where} repeats an earlier header`)
    seen.add(name.toLowerCase())
    headers.push([name, value])
  })
  if (!headers.length) throw new Error('wake webhook headers file must hold at least one "Name: value" line')
  if (headers.length > MAX_HEADERS) throw new Error(`wake webhook headers file holds more than ${MAX_HEADERS} headers`)
  return headers
}

// The only thing that crosses the wire: four fields, built fresh from queue metadata.
export function wakeBody(instance, row) {
  return JSON.stringify({ instance, envelope: row.envelope, type: row.type, at: row.at ?? null })
}

// An error class, never an error message: a fetch message can carry the host or the URL.
export function errorClass(error) {
  if (error?.name === 'TimeoutError' || error?.name === 'AbortError') return 'timeout'
  const code = String(error?.cause?.code || error?.code || '')
  return /^[A-Z][A-Z0-9_]{1,40}$/.test(code) ? code : 'network-error'
}
