import { createHash } from 'node:crypto'
import { encodeConsentRequest, decodeConsentRequest, validateConsentRequest, consentTerms } from '../console/consent-request.mjs'

let n = 0, pass = 0
const t = (name, ok) => { n++; if (ok) { pass++; console.log(`ok - ${name}`) } else console.error(`FAIL - ${name}`) }
const hiveId = 'a'.repeat(64), bridge = 'b'.repeat(64)
const base = () => {
  const meta = { hiveId, hiveName: "JA Fairweather's hive", hiveHandle: 'jaf@dequalsf.com', termsUrl: 'https://example.test/terms' }
  const tos = createHash('sha256').update(consentTerms(meta)).digest('hex')
  return { ...meta, prefill: { kind: 440, created_at: 1000, tags: [['p', bridge], ['da-scope', 'c'.repeat(64), 'd'.repeat(32)], ['da-cap', 'mirror'], ['tos', tos]], content: '' } }
}
const request = base()
const round = validateConsentRequest(decodeConsentRequest(`#request=${encodeConsentRequest(request)}`))
t('fragment round-trip preserves a valid unsigned consent draft', round.prefill.kind === 440 && round.bridge === bridge)
t('visible terms bind the same hive identity', round.terms.includes(`community_id:${hiveId}`) && round.hive.handle === 'jaf@dequalsf.com')
for (const [name, mutate] of [
  ['rejects a signed draft', x => { x.prefill.sig = 'f'.repeat(128) }],
  ['rejects an extra tag', x => x.prefill.tags.push(['client', 'evil'])],
  ['rejects an admit capability', x => { x.prefill.tags[2][1] = 'admit' }],
  ['rejects a draft with another consent scope shape', x => { x.prefill.tags[1][2] = 'not-a-salt' }],
  ['rejects an invalid fragment', () => null],
]) {
  n++; try { if (name === 'rejects an invalid fragment') decodeConsentRequest('#request=%%%'); else { const x = base(); mutate(x); validateConsentRequest(x) }; console.error(`FAIL - ${name}`) } catch { pass++; console.log(`ok - ${name}`) }
}
console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
