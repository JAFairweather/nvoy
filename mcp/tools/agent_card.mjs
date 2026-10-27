// agent_card.mjs — what this manifest allows, as the agent's own signed statement (waggle#613 C1).
//
// The hive manager has to show, for every agent, what it may do, and the manifest that says so lives
// on the fleet, out of the browser's reach. So the broker publishes one replaceable event, kind 30078
// with d=nvoy-agent-card, signed by the agent's key through its Bunker client: the agent attests to
// its own configuration, and the page needs no new server to trust.
//
// The card is public, so it is the coarse projection only. Channel ids, mentionable keys, holdings,
// the model and the profile grant id draw a private map of who works with whom; they are named in
// `withheld` and stay off until a separately reviewed opt-in carries them. Every field is built here,
// so a manifest field added upstream stays off the card until someone admits it.

import { createHash } from 'node:crypto'
import { releaseSha } from './agent_post.mjs'

export const CARD_KIND = 30078
export const CARD_D = 'nvoy-agent-card'
// One relay the owner runs, until publishing cards more widely is a product decision of its own.
export const CARD_RELAYS = ['wss://relay.nave.pub']
// An unchanged card is still re-signed this often, so a reader can tell a broker that keeps its card
// current from one that stopped. It says nothing about whether the agent did any work.
export const CARD_REFRESH_MS = 24 * 60 * 60 * 1000
export const WITHHELD = ['channel ids', 'mentionable keys', 'holdings', 'harness model', 'profile grant id']
export const NOT_REPORTED = ['harness profile', 'last admitted task', 'last reply']

const plural = (n, one) => `${n} ${n === 1 ? one : `${one}s`}`

// The capability sentence without any identifier in it (agent_post.mjs's names channels and grants).
export function publicSummary(manifest) {
  const m = manifest.mayPost, limits = manifest.agentLimits
  return [
    'It replies to work it is given;',
    m ? `it may start a message in ${plural(m.channels.length, 'channel')}, at most ${m.perHour} an hour, mentioning up to ${plural(m.mention.length, 'named participant')};`
      : 'it may not start a message;',
    manifest.maySetProfile ? `it may set its own profile, at most ${manifest.maySetProfile.perDay} a day;` : 'it may not set its profile;',
    `a chain of agent messages stops at ${limits.maxHops} hops, and at most ${limits.perSenderPerHour} messages an hour from one sender are admitted.`,
  ].join(' ')
}

export function agentCard(manifest, { release = releaseSha() } = {}) {
  const m = manifest.mayPost
  return {
    version: 1,
    instance: manifest.id,
    pubkey: manifest.pubkey,
    release,
    grantors: [...manifest.grantors],
    relays: [...manifest.relays],
    may_post: m ? { channels: m.channels.length, per_hour: m.perHour, mentions: m.mention.length } : null,
    may_set_profile: manifest.maySetProfile ? { per_day: manifest.maySetProfile.perDay } : null,
    agent_limits: { max_hops: manifest.agentLimits.maxHops, per_sender_per_hour: manifest.agentLimits.perSenderPerHour },
    delivery_mode: manifest.deliveryMode,
    harness: manifest.harness ? { runner: manifest.harness.runner } : null,
    summary: publicSummary(manifest),
    withheld: WITHHELD,
    not_reported: NOT_REPORTED,
  }
}

export const cardDigest = card => createHash('sha256').update(JSON.stringify(card)).digest('hex')

export function cardTemplate(card, now = Date.now()) {
  return { kind: CARD_KIND, created_at: Math.floor(now / 1000), tags: [['d', CARD_D]], content: JSON.stringify(card) }
}

// A new signature is due when the card says something new, or the last one is CARD_REFRESH_MS old.
export function cardDue(card, last, now = Date.now()) {
  return !last?.event || last.digest !== cardDigest(card) || !(now - last.at < CARD_REFRESH_MS)
}

// The relays still owed the signed card: every card relay that has not read it back.
export function relaysOwed(relays, last) {
  const done = new Set((last?.relays || []).filter(r => r.read_back).map(r => r.relay))
  return relays.filter(url => !done.has(url))
}

export const cardRelays = (override = process.env.NVOY_CARD_RELAYS || '') =>
  override ? [...new Set(String(override).split(',').map(s => s.trim()).filter(Boolean))] : [...CARD_RELAYS]
