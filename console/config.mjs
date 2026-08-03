// config.mjs — per-device relay configuration (Nvelope shared/config.mjs
// pattern, relays only — Nvoy has no blob servers until the M4 outbox).
// Stored in localStorage (non-secret — endpoints, not keys); defaults are
// the shipped public relays. ws:// is deliberately allowed alongside wss://
// so a local test relay (test/wsrelay.mjs) can drive the console offline.
//
// DOM-free: storage is injectable so Node tests exercise the sanitize path.

export const DEFAULT_RELAYS = ['wss://nos.lol', 'wss://relay.primal.net']
export const CONFIG_KEY = 'nvoy-config'

export const defaultConfig = () => ({ relays: [...DEFAULT_RELAYS] })

const validRelay = (u) => { try { return /^wss?:$/.test(new URL(u).protocol) } catch { return false } }
const strip = (u) => u.trim().replace(/\/+$/, '')

/** Coerce anything into a usable config; empty/invalid lists fall back to
 *  the defaults — a broken config must never brick the console. */
export function sanitizeConfig(raw) {
  const cfg = defaultConfig()
  const relays = [...new Set((Array.isArray(raw?.relays) ? raw.relays : [])
    .filter(r => typeof r === 'string').map(strip).filter(validRelay))]
  if (relays.length) cfg.relays = relays
  return cfg
}

export function loadConfig(storage = globalThis.localStorage) {
  try { return sanitizeConfig(JSON.parse(storage?.getItem(CONFIG_KEY))) }
  catch { return defaultConfig() }
}

export function saveConfig(cfg, storage = globalThis.localStorage) {
  const clean = sanitizeConfig(cfg)
  storage?.setItem(CONFIG_KEY, JSON.stringify(clean))
  return clean
}

export function resetConfig(storage = globalThis.localStorage) {
  storage?.removeItem(CONFIG_KEY)
  return defaultConfig()
}
