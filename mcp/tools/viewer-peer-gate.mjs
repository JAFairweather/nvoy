// viewer-peer-gate.mjs — who may open the Hive memory viewer (Frontier A4: "viewer refuses an
// unauthenticated request").
//
// The viewer listens only on herd-cloud's tailnet address, so every caller is a tailnet device. The gate asks the
// local tailscaled who the caller is (LocalAPI `whois`, over its Unix socket: no key, no token, nothing for the
// owner to type on a phone) and admits it only when that device is on a short allowlist: a Tailscale stable node
// ID (`n…CNTRL`) or an ACL tag (`tag:name`). Owner login is deliberately not an allowlist form: on this tailnet the
// owner's login also owns agent hosts, so "James's account" would admit them.
//
// `tailnet:any`, alone in the file, admits every device of this tailnet (James, 14 Nov 2026: "Any device on
// Tailscale"), except two: the viewer's own host (every agent seat on it could otherwise read the whole viewer over its
// own tailnet address) and a node shared in from another tailnet (whois names a Sharer; it is not James's device).
//
// It fails closed. A caller tailscaled does not know, a lookup error, a timeout, or a malformed answer is a refusal;
// the viewer serves nothing before the gate has said yes.

import { request as httpRequest } from 'node:http'

export const DEFAULT_TAILSCALE_SOCKET = '/var/run/tailscale/tailscaled.sock'
const STABLE_ID = /^n[A-Za-z0-9]{4,40}CNTRL$/
const TAG = /^tag:[a-z0-9][a-z0-9-]{0,62}$/
export const ANY_TAILNET = 'tailnet:any'
const MAX_ALLOW = 64
const MAX_BODY = 256 * 1024

// One entry per line; `#` starts a comment. Anything that is not a stable node ID or a tag is refused, so a typo
// cannot quietly widen or empty the list.
export function parseAllowedNodes(text) {
  const out = []
  for (const [i, raw] of String(text ?? '').split('\n').entries()) {
    const line = raw.replace(/#.*$/, '').trim()
    if (!line) continue
    if (!STABLE_ID.test(line) && !TAG.test(line) && line !== ANY_TAILNET) {
      throw new Error(`allowed-nodes line ${i + 1} is not a Tailscale stable node ID (n…CNTRL), tag:name or ${ANY_TAILNET}`)
    }
    if (!out.includes(line)) out.push(line)
  }
  if (!out.length) throw new Error('allowed-nodes lists no device, so the viewer would admit no one')
  if (out.includes(ANY_TAILNET) && out.length > 1) throw new Error(`${ANY_TAILNET} must be the only allowed-nodes entry`)
  if (out.length > MAX_ALLOW) throw new Error(`allowed-nodes lists more than ${MAX_ALLOW} entries`)
  return out
}

// GET one tailscaled LocalAPI path over its Unix socket; resolves { status, body } with body parsed as JSON (or
// undefined when it is not JSON). Bounded in size and time.
function localApi(socketPath, path, timeoutMs) {
  return new Promise((resolveApi, rejectApi) => {
    const req = httpRequest(
      { socketPath, method: 'GET', path, headers: { Host: 'local-tailscaled.sock' }, timeout: timeoutMs },
      res => {
        let size = 0
        const chunks = []
        res.on('data', c => {
          size += c.length
          if (size > MAX_BODY) {
            req.destroy(new Error('tailscaled answer too large'))
            return
          }
          chunks.push(c)
        })
        res.on('end', () => {
          let body
          try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { body = undefined }
          resolveApi({ status: res.statusCode, body })
        })
        res.on('error', rejectApi)
      }
    )
    req.on('timeout', () => req.destroy(new Error('tailscaled timed out')))
    req.on('error', rejectApi)
    req.end()
  })
}

// The viewer host's own stable node ID, from tailscaled's status (LocalAPI `status?peers=false`, field Self.ID).
// Asked once; a failure is not remembered, so the next request asks again.
export function createTailscaleSelf({ socketPath = DEFAULT_TAILSCALE_SOCKET, timeoutMs = 3000 } = {}) {
  let known
  return async function selfId() {
    if (known) return known
    const { status, body } = await localApi(socketPath, '/localapi/v0/status?peers=false', timeoutMs)
    if (status !== 200) throw new Error(`tailscaled status answered ${status}`)
    const id = body && body.Self && typeof body.Self.ID === 'string' ? body.Self.ID : ''
    if (!id) throw new Error('tailscaled status names no self node')
    known = id
    return id
  }
}

// tailscaled's whois for one caller address. Resolves { stableId, tags, name, shared } for a known tailnet device, null
// when tailscaled has no such peer (404), and rejects on anything else.
export function createTailscaleWhois({ socketPath = DEFAULT_TAILSCALE_SOCKET, timeoutMs = 3000 } = {}) {
  return async function whois(addr) {
    const { status, body } = await localApi(socketPath, `/localapi/v0/whois?addr=${encodeURIComponent(addr)}`, timeoutMs)
    if (status === 404) return null
    if (status !== 200) throw new Error(`tailscaled whois answered ${status}`)
    if (body === undefined) throw new Error('tailscaled whois answer is not JSON')
    const node = body && typeof body === 'object' ? body.Node : null
    const stableId = node && typeof node.StableID === 'string' ? node.StableID : ''
    if (!stableId) throw new Error('tailscaled whois answer names no node')
    const tags = Array.isArray(node.Tags) ? node.Tags.filter(t => typeof t === 'string') : []
    // Sharer is set (a non-zero user ID) on a node shared in from another tailnet.
    const shared = Boolean(node.Sharer)
    return { stableId, tags, name: typeof node.Name === 'string' ? node.Name : '', shared }
  }
}

// The caller's address as tailscaled's whois takes it.
export function whoisAddr(remoteAddress, remotePort) {
  let ip = String(remoteAddress || '')
  if (ip.startsWith('::ffff:') && ip.includes('.')) ip = ip.slice(7)
  if (!ip) return ''
  const port = Number.isInteger(remotePort) && remotePort > 0 ? remotePort : 0
  if (!port) return ip
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`
}

// check(remoteAddress, remotePort) → { ok: true, node } | { ok: false, status: 403|503, reason }.
// Verdicts are cached per caller IP for cacheMs (a page load opens several requests and an event stream).
export function createPeerGate({ allowed, whois, selfId, cacheMs = 30_000, now = () => Date.now() } = {}) {
  const allow = new Set(Array.isArray(allowed) ? allowed : [])
  if (!allow.size) throw new Error('the viewer peer gate needs at least one allowed device')
  if (typeof whois !== 'function') throw new Error('the viewer peer gate needs a whois lookup')
  const anyTailnet = allow.has(ANY_TAILNET)
  if (anyTailnet && allow.size > 1) throw new Error(`${ANY_TAILNET} must be the only allowed entry`)
  if (anyTailnet && typeof selfId !== 'function') throw new Error(`${ANY_TAILNET} needs the host's own node ID lookup`)
  const cache = new Map()

  return async function check(remoteAddress, remotePort) {
    const ip = whoisAddr(remoteAddress, 0)
    if (!ip) return { ok: false, status: 403, reason: 'no caller address' }
    const hit = cache.get(ip)
    if (hit && hit.until > now()) return hit.verdict
    let verdict
    try {
      const node = await whois(whoisAddr(remoteAddress, remotePort))
      if (!node) verdict = { ok: false, status: 403, reason: 'not a known tailnet device' }
      else if (anyTailnet) {
        if (node.shared) verdict = { ok: false, status: 403, reason: 'device is shared in from another tailnet' }
        else if (node.stableId === (await selfId())) verdict = { ok: false, status: 403, reason: 'the viewer host itself is not admitted' }
        else verdict = { ok: true, node }
      } else if (allow.has(node.stableId) || node.tags.some(t => allow.has(t))) verdict = { ok: true, node }
      else verdict = { ok: false, status: 403, reason: 'device not on the viewer allowlist' }
    } catch (err) {
      // Not cached: the next request asks tailscaled again.
      return { ok: false, status: 503, reason: `device check unavailable (${err?.message || err})` }
    }
    if (cache.size > 1024) cache.clear()
    cache.set(ip, { until: now() + cacheMs, verdict })
    return verdict
  }
}
