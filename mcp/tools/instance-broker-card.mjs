// instance-broker-card.mjs — publish this agent's card (agent_card.mjs) when it is due.
//
// The broker daemon runs it at start and then hourly. It signs through the broker's own signer,
// refuses a signature that is not the manifest's key, publishes to the card relays, and reads the card
// back from each. Only a card read back somewhere counts, and the record names every relay that
// accepted it and every relay that read it back, so a reader can see the coverage, not just "ok".

import { readFileSync, renameSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { verifyEvent } from 'nostr-tools/pure'
import WebSocket from 'ws'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { agentCard, cardDigest, cardDue, cardRelays, cardTemplate, CARD_D, CARD_KIND } from './agent_card.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { credentialIn } from './outbound_secrets.mjs'

const flag = name => { const index = process.argv.indexOf(name); return index < 0 ? '' : process.argv[index + 1] || '' }
const id = flag('--instance')
if (!id) throw new Error('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
const manifest = readManifest(root, instanceId(id))
assertNoCollisions(root, manifest)
if (!manifest.agentCard) throw new Error('agent_card is off in this manifest')
const statePath = resolve(manifest.stateDir, 'agent-card.json')
let last = null
try { last = JSON.parse(readFileSync(statePath, 'utf8')) } catch (error) { if (error.code !== 'ENOENT') console.error(`instance-broker-card: ignoring unreadable ${statePath}`) }

// One relay, one connection: publish, then ask for the card by its address and look for our id.
function publishAndReadBack(url, event) {
  return new Promise(done => {
    const result = { relay: url, accepted: false, read_back: false, message: '' }
    let settled = false
    const ws = new WebSocket(url)
    const finish = message => {
      if (settled) return
      settled = true; clearTimeout(timer)
      if (message) result.message = String(message).slice(0, 160)
      try { ws.close() } catch {}
      done(result)
    }
    const timer = setTimeout(() => finish(result.accepted ? 'read-back timed out' : 'timed out'), 10000)
    ws.on('open', () => ws.send(JSON.stringify(['EVENT', event])))
    ws.on('message', raw => {
      let frame
      try { frame = JSON.parse(raw.toString()) } catch { return }
      if (frame[0] === 'OK' && frame[1] === event.id) {
        result.accepted = !!frame[2]
        if (!result.accepted) return finish(frame[3] || 'refused')
        ws.send(JSON.stringify(['REQ', 'card', { kinds: [CARD_KIND], authors: [event.pubkey], '#d': [CARD_D], limit: 1 }]))
      }
      if (frame[0] === 'EVENT' && frame[1] === 'card' && frame[2]?.id === event.id) result.read_back = true
      if (frame[0] === 'EOSE' && frame[1] === 'card') finish(result.read_back ? '' : 'not read back')
    })
    ws.on('error', error => finish(error.message))
  })
}

const card = agentCard(manifest)
const leak = credentialIn(JSON.stringify(card))
if (leak) throw new Error(`card withheld: it looks like it holds a credential (${leak})`)
if (!cardDue(card, last)) console.log(JSON.stringify({ card: 'current', event_id: last.event_id }))
else {
  let signer
  try {
    ;({ signer } = brokerSigner(message => { throw new Error(message) }, { idleMs: 30000 }))
    const template = cardTemplate(card)
    const event = await signer.signEvent({ pubkey: manifest.pubkey, ...template })
    if (event?.pubkey !== manifest.pubkey || event.kind !== CARD_KIND || event.content !== template.content ||
        JSON.stringify(event.tags) !== JSON.stringify(template.tags) || !verifyEvent(event)) throw new Error('signer returned a different card')
    const relays = await Promise.all(cardRelays(manifest).map(url => publishAndReadBack(url, event)))
    const read = relays.filter(r => r.read_back).map(r => r.relay)
    console.log(JSON.stringify({ card: read.length ? 'published' : 'unconfirmed', event_id: event.id, read_back: read,
      missing: relays.filter(r => !r.read_back).map(r => `${r.relay}: ${r.message}`) }))
    // An unconfirmed card is not recorded, so the next run signs and tries again.
    if (!read.length) process.exitCode = 1
    else {
      const temporary = `${statePath}.${process.pid}.tmp`
      writeFileSync(temporary, JSON.stringify({ version: 1, at: Date.now(), digest: cardDigest(card), event_id: event.id, relays }), { mode: 0o600 })
      renameSync(temporary, statePath)
    }
  } finally {
    try { signer?.close?.() } catch {}
  }
}
