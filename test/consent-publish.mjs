import { finalizeEvent, generateSecretKey } from 'nostr-tools'
import { publishAndReadBack } from '../console/consent-publish.mjs'

let n = 0, pass = 0
const t = (name, ok) => { n++; if (ok) { pass++; console.log(`ok - ${name}`) } else console.error(`FAIL - ${name}`) }
const signed = JSON.parse(JSON.stringify(finalizeEvent({ kind: 440, created_at: 1, tags: [], content: '' }, generateSecretKey())))

let filter
const receipt = await publishAndReadBack({
  async publish(event) { return { acks: 2, of: 3, event } },
  async query(f) { filter = f; return [signed] },
}, signed)
t('success requires a query for the exact signed event id', filter?.ids?.[0] === signed.id && filter?.limit === 1 && receipt.acks === 2)

let absent = false
try { await publishAndReadBack({ async publish() { return { acks: 1, of: 1 } }, async query() { return [] } }, signed) } catch { absent = true }
t('an ACK without a read-back is not reported as success', absent)

let invalid = false
try { await publishAndReadBack({ async publish() { return { acks: 1, of: 1 } }, async query() { return [signed] } }, signed, () => false) } catch { invalid = true }
t('a read-back with an invalid signature is refused', invalid)

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
