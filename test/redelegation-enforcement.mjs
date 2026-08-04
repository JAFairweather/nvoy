// re-delegation enforcement: an allowed parent produces a NEW attenuated
// scope; forbidden parents produce nothing. The issuer identity deliberately
// exposes only signer primitives (no secretKey), matching a Bunker runtime.

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { LocalRelay } from '../lib/liverelay.mjs'
import { Relay } from '../lib/relay.mjs'
import { localSigner, newScopeKey, publishScope, fetchScope, loadGrantIndex } from '../lib/nipxx.mjs'
import { grantWithTerms, opaqueScopeId } from './nvoygrant.mjs'
import { receiveGrants } from '../mcp/dist/grants.js'
import { cascadeDerivedRevocation, issueDerivedGrant, RedelegationForbidden } from '../mcp/dist/subgrants.js'

let n = 0, pass = 0
const t = (name, ok) => { n++; if (ok) { pass++; console.log(`PASS ${n}. ${name}`) } else console.error(`FAIL ${n}. ${name}`) }
const relay = new LocalRelay(new Relay())
const directorSk = generateSecretKey(), director = getPublicKey(directorSk)
const centralSk = generateSecretKey(), central = getPublicKey(centralSk)
const leafSk = generateSecretKey(), leaf = getPublicKey(leafSk)
// The raw test key stays inside the signer fixture; the Identity has no
// secretKey, precisely the runtime shape selected by NVOY_SIGNER=nip46.
const centralIdentity = { signer: localSigner(centralSk), pubkey: central, npub: '', source: 'nip46' }

async function parent(terms) {
  const scopeId = opaqueScopeId(), scopeKey = newScopeKey()
  await publishScope(relay, directorSk, { scopeId, generation: 1, scopeKey, payload: { safe: 'yes', secret: 'never delegate this' } })
  await grantWithTerms(relay, directorSk, central, { scopeId, generation: 1, scopeKey, scopeName: 'parent', terms })
  return (await receiveGrants(relay, centralIdentity.signer)).find(g => g.publisher === director && g.scopeId === scopeId)
}

const forbid = async (g, terms = { purpose: 'leaf' }) => {
  try { await issueDerivedGrant(relay, centralIdentity, g, leaf, { safe: 'yes' }, 'derived:leaf', terms); return false }
  catch (e) { return e instanceof RedelegationForbidden }
}

const denied = await parent({ purpose: 'root', redelegate: false })
t('redelegate:false is mechanically refused', await forbid(denied))
t('refusal creates no leaf grant', !(await receiveGrants(relay, leafSk)).some(g => g.scopeName === 'derived:leaf'))

const noPersist = await parent({ purpose: 'root', redelegate: true, no_persist: true })
t('no_persist parent cannot be copied into a relay-stored child', await forbid(noPersist))

const expiresAt = Math.floor(Date.now() / 1000) + 600
const expiring = await parent({ purpose: 'root', redelegate: true, expires_at: expiresAt })
t('a child cannot omit its parent expiry', await forbid(expiring))
t('a child cannot outlive its parent', await forbid(expiring, { purpose: 'leaf', expires_at: expiresAt + 1 }))

const allowed = await parent({ purpose: 'root', redelegate: true })
const issued = await issueDerivedGrant(relay, centralIdentity, allowed, leaf, { safe: 'yes' }, 'derived:booking', { purpose: 'booking subset' })
const leafGrant = (await receiveGrants(relay, leafSk)).find(g => g.publisher === central && g.scopeId === issued.scopeId)
t('a signer-only (Bunker-shaped) identity can issue the child', !!leafGrant && centralIdentity.secretKey === undefined)
t('the leaf receives a NEW scope from the sub-issuer, not the parent publisher', leafGrant?.publisher === central && leafGrant.scopeId !== allowed.scopeId)
t('the child defaults to redelegate:false', leafGrant?.terms?.redelegate === false)
const data = await fetchScope(relay, leafGrant)
t('the leaf sees only the deliberately attenuated payload', data.status === 'ok' && data.data.safe === 'yes' && data.data.secret === undefined)
t('the parent key was not re-wrapped to the leaf', !(await receiveGrants(relay, leafSk)).some(g => g.publisher === director && g.scopeId === allowed.scopeId))

const beforeCascade = await loadGrantIndex(relay, centralIdentity.signer)
t('parent-to-child lineage is encrypted in the sub-issuer Grant Index before a restart',
  Array.isArray(beforeCascade.nvoy_derived_children) && beforeCascade.nvoy_derived_children.some(x => x?.parent?.scope === allowed.scopeId && x?.child?.scope === issued.scopeId && x?.state === 'active'))
const cascade = await cascadeDerivedRevocation(relay, centralIdentity, allowed)
t('revoking the parent cryptographically severs its child scope', cascade.cascaded === 1 && (await fetchScope(relay, leafGrant)).status === 'stale')
const afterCascade = await loadGrantIndex(relay, centralIdentity.signer)
t('restart recovery retains only a revoked lineage tombstone, not a usable child key',
  afterCascade.nvoy_derived_children?.some(x => x?.child?.scope === issued.scopeId && x?.state === 'revoked') && !afterCascade.issued?.some(x => x?.scope === issued.scopeId))
const replay = await cascadeDerivedRevocation(relay, centralIdentity, allowed)
t('replaying a parent revocation after restart is idempotent', replay.cascaded === 0)

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
