import { generateSecretKey, getPublicKey, nip19, verifyEvent } from 'nostr-tools'
import { testingNsecSigner } from '../console/testing-nsec-signer.mjs'

let n = 0, pass = 0
const t = (name, ok) => { n++; if (ok) { pass++; console.log(`ok - ${name}`) } else console.error(`FAIL - ${name}`) }
const sk = generateSecretKey()
const signer = testingNsecSigner(nip19.nsecEncode(sk))
t('the burner nsec resolves to its own public identity', await signer.getPublicKey() === getPublicKey(sk))
const signed = await signer.signEvent({ kind: 440, created_at: 1, tags: [], content: '' })
t('the burner signer produces a valid event signature', verifyEvent(signed))
signer.clear()
let cleared = false
try { await signer.signEvent({ kind: 440, created_at: 2, tags: [], content: '' }) } catch { cleared = true }
t('a cleared testing signer cannot sign again', cleared)
let rejected = false
try { testingNsecSigner('00'.repeat(32)) } catch { rejected = true }
t('the testing path rejects raw hex and accepts nsec1 only', rejected)
console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
