import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools'
import { buildTaskAuthority, taskScopeHash, signPublishTaskAuthority } from '../console/task-authority-lib.mjs'

let n = 0, pass = 0
const t = (name, ok) => { n++; if (ok) { pass++; console.log(`ok - ${name}`) } else console.error(`FAIL - ${name}`) }
const operatorSk = generateSecretKey(), operator = getPublicKey(operatorSk)
const sender = getPublicKey(generateSecretKey()), agent = getPublicKey(generateSecretKey())
const salt = 'ab'.repeat(16)
const draft = await buildTaskAuthority({ senderPub: sender, agentPub: agent, cap: 'task+act', createdAt: 1000, salt })

t('builds a public 440 task authority for the sender', draft.kind === 440 && draft.tags[0][0] === 'p' && draft.tags[0][1] === sender)
t('uses exactly the requested capability', draft.tags.find(t => t[0] === 'da-cap')?.[1] === 'task+act')
t('binds scope to the intended agent using the shared domain', draft.tags.find(t => t[0] === 'da-scope')?.[1] === await taskScopeHash(agent, salt))
t('does not expose the agent public key in the public tags', !draft.tags.flat().includes(agent))
await Promise.all(['wat', '', 'task+anything'].map(async cap => {
  try { await buildTaskAuthority({ senderPub: sender, agentPub: agent, cap }); return false } catch { return true }
})).then(v => t('rejects every capability outside task/task+act', v.every(Boolean)))

const signer = { async getPublicKey() { return operator }, async signEvent(ev) { return finalizeEvent(ev, operatorSk) } }
const events = []
const relay = { async publish(ev) { events.push(JSON.parse(JSON.stringify(ev))); return { acks: 2, of: 2 } }, async query({ ids }) { return events.filter(e => ids.includes(e.id)) } }
const { signed } = await signPublishTaskAuthority({ signer, relay, draft })
t('signs, publishes and reads back a verifiable wire event', verifyEvent(JSON.parse(JSON.stringify(signed))) && events.length === 1)
t('the signer cannot silently change the reviewed grant', await (async () => {
  const bad = { ...signer, async signEvent(ev) { return finalizeEvent({ ...ev, tags: [...ev.tags, ['x', 'changed']] }, operatorSk) } }
  try { await signPublishTaskAuthority({ signer: bad, relay, draft }); return false } catch { return true }
})())

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
