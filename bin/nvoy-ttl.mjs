#!/usr/bin/env node
// nvoy-ttl.mjs — the OPTIONAL operator daemon for hard expiry (spec §6.4.3,
// decision 2): the console's TTL scheduler only runs while the console is
// open; this closes the gap for delegators who need deadlines enforced
// around the clock without a hosted scheduler.
//
// SAY IT PLAINLY: this process holds your delegator nsec (via env) and can
// therefore rotate every scope you publish. Run it only on a machine you
// trust as much as your browser profile, or don't run it at all — expiry
// stays soft (compliant runtimes stop serving; auto_relinquish agents
// destroy their keys) and the sweep completes on your next console visit.
//
//   NVOY_TTL_NSEC=nsec1… [NVOY_RELAYS=wss://…,wss://…] node bin/nvoy-ttl.mjs
//   optional: NVOY_TTL_INTERVAL_S (default 60) — sweep period in seconds
//
// Each sweep: load the Grant Index, rotate any scope holding a delegation
// past its expires_at (drop the lapsed, re-grant survivors under original
// terms, ledger 'expired-rotated'), save. Exactly what the console does on
// load — same modules, no forked logic.

import { nip19 } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import { localSigner, loadGrantIndex } from '../lib/nipxx.mjs'
import { expiryRotationPlan, runExpiryRotation, nextExpiry } from '../console/ttl.mjs'

const log = (...a) => console.error(`[nvoy-ttl ${new Date().toISOString().slice(0, 19)}]`, ...a)

const raw = process.env.NVOY_TTL_NSEC
if (!raw) {
  console.error('usage: NVOY_TTL_NSEC=nsec1… [NVOY_RELAYS=wss://…,…] node bin/nvoy-ttl.mjs')
  console.error('This daemon holds your delegator nsec. Read the header before running it.')
  process.exit(1)
}
let sk
if (/^[0-9a-f]{64}$/i.test(raw.trim())) sk = Uint8Array.from(raw.trim().match(/../g), h => parseInt(h, 16))
else {
  const { type, data } = nip19.decode(raw.trim())
  if (type !== 'nsec') { console.error('NVOY_TTL_NSEC: expected nsec1… or 64-char hex'); process.exit(1) }
  sk = data
}

const relays = (process.env.NVOY_RELAYS ?? 'wss://nos.lol,wss://relay.primal.net')
  .split(',').map(s => s.trim()).filter(Boolean)
const intervalMs = Math.max(5, Number(process.env.NVOY_TTL_INTERVAL_S) || 60) * 1000
const relay = new LiveRelay(relays)
const signer = localSigner(sk)

log(`delegator ${nip19.npubEncode(await signer.getPublicKey())} · relays ${relays.join(', ')}`)
log(`sweeping every ${intervalMs / 1000}s — ctrl-c to stop (expiry falls back to soft + next console visit)`)

async function sweep() {
  try {
    const index = await loadGrantIndex(relay, signer)
    const plan = expiryRotationPlan(index)
    for (const item of plan) {
      try {
        const r = await runExpiryRotation(relay, signer, index, item, { relayHint: relays[0] })
        log(`rotated ${item.scope} v${r.from_v} → v${r.to_v}: ${item.expired.length} lapsed dropped, ${r.survivors.length} re-granted`)
      } catch (err) {
        log(`skipped ${item.scope}: ${err.message}`)
      }
    }
    const next = nextExpiry(index)
    if (!plan.length) log(`nothing due${next ? `; next deadline ${new Date(next * 1000).toISOString().slice(0, 16)}` : ''}`)
  } catch (err) {
    log(`sweep failed (will retry): ${err.message}`)
  }
}

await sweep()
setInterval(sweep, intervalMs)
