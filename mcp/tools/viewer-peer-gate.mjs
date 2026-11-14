// viewer-peer-gate.mjs — who may open the Hive memory viewer (Frontier A4: "viewer refuses an
// unauthenticated request").
//
// The viewer listens only on herd-cloud's tailnet address, so every caller is a tailnet device. The gate asks the
// local tailscaled who the caller is (LocalAPI `whois`, over its Unix socket: no key, no token, nothing for the
// owner to type on a phone) and admits it only when that device is on a short allowlist: a Tailscale stable node
// ID (`n…CNTRL`) or an ACL tag (`tag:name`). Owner login is deliberately not an allowlist form: on this tailnet the
// owner's login also owns agent hosts, so "James's account" would admit them.
//
// It fails closed. A caller tailscaled does not know, a lookup error, a timeout, or a malformed answer is a refusal;
// the viewer serves nothing before the gate has said yes.

import { request as httpRequest } from 'node:http'

export const DEFAULT_TAILSCALE_SOCKET = '/var/run/tailscale/tailscaled.sock'
const STABLE_ID = /^n[A-Za-z0-9]{4,40}CNTRL$/
const TAG = /^tag:[a-z0-9][a-z0-9-]{0,62}$/
const MAX_ALLOW = 64
const MAX_BODY = 256 * 1024

// One entry per line; `#` starts a comment. Anything that is not a stable node ID or a tag is refused, so a typo
// cannot quietly widen or empty the list.
export function parseAllowedNodes(text) {
  const out = []
  for (const [i, raw] of String(text ?? '').split('\n').entries()) {
    const line = raw.replace(/#.*$/, '').trim()
    if (!line) continue
    if (!STABLE_ID.test(line) && !TAG.test(line)) {
      throw new Error(`allowed-nodes line ${i + 1} is not a Tailscale stable node ID (n…CNTRL) or tag:name`)
    }
    if (!out.includes(line)) out.push(line)
  }
  if (!out.length) throw new Error('allowed-nodes lists no device, so the viewer would admit no one')
  if (out.length > MAX_ALLOW) throw new Error(`allowed-nodes lists more than ${MAX_ALLOW} entries`)
  return out
}

// tailscaled's whois for one caller address. Resolves { stableId, tags, name } for a known tailnet device, null
// when tailscaled has no such peer (404), and rejects on anything else.
export function createTailscaleWhois({ socketPath = DEFAULT_TAILSCALE_SOCKET, timeoutMs = 3000 } = {}) {
  return function whois(addr) {
    return new Promise((resolveWhois, rejectWhois) => {
      const req = httpRequest(
        {
          socketPath,
          method: 'GET',
          path: `/localapi/v0/whois?addr=${encodeURIComponent(addr)}`,
          headers: { Host: 'local-tailscaled.sock' },
          timeout: timeoutMs,
        },
        res => {
          let size = 0
          const chunks = []
          res.on('data', c => {
            size += c.length
            if (size > MAX_BODY) {
              req.destroy(new Error('tailscaled whois answer too large'))
              return
            }
            chunks.push(c)
          })
          res.on('end', () => {
            if (res.statusCode === 404) return resolveWhois(null)
            if (res.statusCode !== 200) return rejectWhois(new Error(`tailscaled whois answered ${res.statusCode}`))
            let body
            try {
              body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
            } catch {
              return rejectWhois(new Error('tailscaled whois answer is not JSON'))
            }
            const node = body && typeof body === 'object' ? body.Node : null
            const stableId = node && typeof node.StableID === 'string' ? node.StableID : ''
            if (!stableId) return rejectWhois(new Error('tailscaled whois answer names no node'))
            const tags = Array.isArray(node.Tags) ? node.Tags.filter(t => typeof t === 'string') : []
            resolveWhois({ stableId, tags, name: typeof node.Name === 'string' ? node.Name : '' })
          })
          res.on('error', rejectWhois)
        }
      )
      req.on('timeout', () => req.destroy(new Error('tailscaled whois timed out')))
      req.on('error', rejectWhois)
      req.end()
    })
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
export function createPeerGate({ allowed, whois, cacheMs = 30_000, now = () => Date.now() } = {}) {
  const allow = new Set(Array.isArray(allowed) ? allowed : [])
  if (!allow.size) throw new Error('the viewer peer gate needs at least one allowed device')
  if (typeof whois !== 'function') throw new Error('the viewer peer gate needs a whois lookup')
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
      else if (allow.has(node.stableId) || node.tags.some(t => allow.has(t))) verdict = { ok: true, node }
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
