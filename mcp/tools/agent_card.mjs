// agent_card.mjs — what this manifest allows, as the agent's own signed statement (waggle#613 C1).
//
// The hive manager has to show, for every agent, who can give it work, where it can post and what it
// holds. The manifest is the source of truth for most of that, and it lives on the fleet, out of the
// browser's reach. So the broker publishes one replaceable event, kind 30078 with d=nvoy-agent-card,
// signed by the agent's key through its Bunker client: the agent attests to its own configuration,
// and the page needs no new server to trust.
//
// The card is an allowlist by construction, like console/runtime-facts.mjs: every field is named
// here, and a manifest field added upstream stays off the card until someone admits it. Holdings
// are named, never located: no credential path, uid, directory or host leaves the fleet.

import { createHash } from 'node:crypto'
import { capabilitySummary, releaseSha } from './agent_post.mjs'
import { grantReadRelays } from './grant_relays.mjs'

export const CARD_KIND = 30078
export const CARD_D = 'nvoy-agent-card'
// A card that has not changed is still republished this often, so a reader can tell a live broker
// from one whose last card is old.
export const CARD_REFRESH_MS = 24 * 60 * 60 * 1000

// "has a copy": the credential is on the fleet and the runtime reads it. "signs through": the key
// stays in the Bunker and the runtime holds only a client key that asks it to sign.
function holdings(manifest) {
  return [
    manifest.bunkerUriRef ? { name: 'nostr identity', access: 'signs through its Bunker; never sees the key' }
      : manifest.keyRef ? { name: 'nostr identity', access: 'has a copy of the key' } : null,
    manifest.workerEnabled ? { name: `${manifest.workerRunner} worker login`, access: 'has a copy' } : null,
    manifest.harness ? { name: `${manifest.harness.runner} harness login`, access: 'has a copy' } : null,
    manifest.wakeWebhook ? { name: 'wake webhook', access: 'has a copy' } : null,
    manifest.channelDoor ? { name: 'channel door token', access: 'holds its hash only' } : null,
  ].filter(Boolean)
}

export function agentCard(manifest, { release = releaseSha() } = {}) {
  const m = manifest.mayPost, profile = manifest.maySetProfile
  return {
    version: 1,
    instance: manifest.id,
    pubkey: manifest.pubkey,
    release,
    grantors: [...manifest.grantors],
    carriers: manifest.carriers.map(c => ({ pubkey: c.pubkey, channels: [...c.channels] })),
    relays: [...manifest.relays],
    buzz_channels: manifest.buzz ? [...manifest.buzz.channels] : [],
    may_post: m ? { channels: [...m.channels], per_hour: m.perHour, mention: m.mention.map(e => ({ name: e.name, pubkey: e.pubkey })) } : null,
    may_set_profile: profile ? { grant_id: profile.grantId, per_day: profile.perDay } : null,
    agent_limits: { max_hops: manifest.agentLimits.maxHops, per_sender_per_hour: manifest.agentLimits.perSenderPerHour },
    delivery_mode: manifest.deliveryMode,
    harness: manifest.harness ? { runner: manifest.harness.runner, model: manifest.harness.model || null } : null,
    holdings: holdings(manifest),
    summary: capabilitySummary(manifest),
  }
}

export const cardDigest = card => createHash('sha256').update(JSON.stringify(card)).digest('hex')

export function cardTemplate(card, now = Date.now()) {
  return { kind: CARD_KIND, created_at: Math.floor(now / 1000), tags: [['d', CARD_D]], content: JSON.stringify(card) }
}

// Due when the card says something new, or when the last one is older than CARD_REFRESH_MS.
export function cardDue(card, last, now = Date.now()) {
  return !last || last.digest !== cardDigest(card) || !(now - last.at < CARD_REFRESH_MS)
}

// The card goes where the page already reads grants (grant_relays.mjs). The Buzz relay is no home
// for it: it returns nothing to a filter without channel UUIDs.
export const cardRelays = (manifest, override = process.env.NVOY_GRANT_RELAYS || '') => grantReadRelays(manifest.relays, override)
