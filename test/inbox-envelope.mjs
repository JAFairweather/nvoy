import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey } from 'nostr-tools/pure'
import { verifyInboxEnvelope } from '../mcp/tools/inbox_envelope.mjs'

let pass = 0, fail = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? pass++ : fail++ }
const recipient = getPublicKey(generateSecretKey())
const carrierSk = generateSecretKey(), carrier = getPublicKey(carrierSk)
const rumor = { pubkey: carrier, created_at: 1785870000, kind: 14, tags: [], content: 'signed-source review data' }
rumor.id = getEventHash(rumor)
const seal = JSON.parse(JSON.stringify(finalizeEvent({ kind: 13, created_at: rumor.created_at, tags: [], content: 'encrypted rumor' }, carrierSk)))
const wrap = JSON.parse(JSON.stringify(finalizeEvent({ kind: 1059, created_at: rumor.created_at,
  tags: [['p', recipient]], content: 'encrypted seal' }, generateSecretKey())))
const verify = values => verifyInboxEnvelope({ wrap, seal, rumor, recipient, ...values })

const accepted = verify()
ok('a complete signed wrap, signed seal, and hash-bound rumor authenticates the carrier message',
  accepted?.from === carrier && accepted?.content === rumor.content)
ok('a forged outer wrap is refused', !verify({ wrap: { ...wrap, content: wrap.content + 'x' } }))
ok('a wrap addressed to another recipient is refused', !verify({ recipient: getPublicKey(generateSecretKey()) }))
ok('multiple recipient tags are refused', !verify({ wrap: { ...wrap, tags: [...wrap.tags, ['p', recipient]] } }))
ok('a seal whose signed ciphertext was altered is refused', !verify({ seal: { ...seal, content: seal.content + 'x' } }))
ok('a forged carrier seal is refused', !verify({ seal: { ...seal, pubkey: getPublicKey(generateSecretKey()) } }))
ok('a rumor author not bound to the signed seal is refused', !verify({ rumor: { ...rumor, pubkey: getPublicKey(generateSecretKey()) } }))
ok('a rumor whose content no longer matches its id is refused', !verify({ rumor: { ...rumor, content: rumor.content + 'x' } }))
ok('unknown event fields are refused', !verify({ rumor: { ...rumor, redirect: 'elsewhere' } }))

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
