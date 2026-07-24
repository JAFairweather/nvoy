// nip46-signer.mjs — the remote-signer backend (nvoy#30), offline.
//
// A drafter under NVOY_SIGNER=nip46 never holds a key: every sign/encrypt/
// decrypt is a call on `identity.signer`. This proves the two paths a drafter
// uses — grant READ (credential:anthropic) and draft EMIT — work through a
// signer that exposes ONLY the async Signer interface (no raw key), byte-for-
// byte the same as the raw-key path; and that operations needing a local key
// refuse cleanly under a remote signer.

import assert from 'node:assert'
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { publishScope, grant, newScopeKey, localSigner, fetchScope } from '../lib/nipxx.mjs'
import { Relay } from '../lib/relay.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { receiveGrants } from '../mcp/dist/grants.js'
import { DraftDesk } from '../mcp/dist/drafts.js'
import { requireLocalKey } from '../mcp/dist/identity.js'

let n = 0, failed = 0
const check = (name, cond) => { n++; console.log(`${cond ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${name}`); if (!cond) failed = 1 }

// A stand-in for a NIP-46 bunker: it wraps a raw key but is handed to the code
// ONLY as the async Signer interface — the code can never see `secretKey`.
// This is exactly the surface BunkerSigner presents (getPublicKey / signEvent
// / nip44Encrypt / nip44Decrypt), so if the paths work here they work remotely.
function remoteSignerFor(sk) {
  const local = localSigner(sk)
  let calls = 0
  return {
    _calls: () => calls,
    getPublicKey: async () => { calls++; return local.getPublicKey() },
    signEvent: async (e) => { calls++; return local.signEvent(e) },
    nip44Encrypt: async (pk, pt) => { calls++; return local.nip44Encrypt(pk, pt) },
    nip44Decrypt: async (pk, ct) => { calls++; return local.nip44Decrypt(pk, ct) },
  }
}

const relay = new LocalRelay(new Relay())
const directorSk = generateSecretKey()
const directorPub = getPublicKey(directorSk)
const directorNpub = nip19.npubEncode(directorPub)

// The agent (jaf-quill) — key exists only inside the remote signer here.
const agentSk = generateSecretKey()
const agentPub = getPublicKey(agentSk)
const agentSigner = remoteSignerFor(agentSk)

// --- grant READ through the remote signer ---------------------------------
// A Director grants credential:anthropic to the agent (gift-wrapped to agentPub).
const credScope = 'cred-abc'
const credKey = newScopeKey()
await publishScope(relay, directorSk, { scopeId: credScope, generation: 1, scopeKey: credKey, payload: { value: 'sk-ant-xyz' } })
await grant(relay, directorSk, agentPub, { scopeId: credScope, generation: 1, scopeKey: credKey, scopeName: 'credential:anthropic' })

const viaRaw = await receiveGrants(relay, agentSk)
const viaSigner = await receiveGrants(relay, agentSigner)
check('grant read: the remote signer reads the same grants as the raw key',
  viaSigner.length === 1 && viaSigner[0].scopeName === 'credential:anthropic'
  && viaRaw.length === viaSigner.length && viaRaw[0].scopeId === viaSigner[0].scopeId)
check('grant read: it went through the remote signer (nip44Decrypt calls made)', agentSigner._calls() > 0)

// --- draft EMIT through the remote signer ---------------------------------
// DraftDesk is constructed with an identity whose ONLY signing capability is
// the remote signer (no secretKey) — exactly the nip46 drafter shape.
const nip46Identity = { signer: agentSigner, pubkey: agentPub, npub: nip19.npubEncode(agentPub), source: 'nip46' }
const desk = new DraftDesk(relay, nip46Identity)
const res = await desk.publish(directorPub, { kind: 'draft:post', text: 'signed by the bunker, never by this host' })
check('draft emit: fresh draft:post scope, granted to the Director',
  typeof res.scopeId === 'string' && res.generation === 1 && res.scopeName === `draft:post/${res.scopeId.slice(0, 8)}`)

// Director side: unwraps with HIS key and reads the draft the remote signer authored.
const onDesk = (await receiveGrants(relay, directorSk)).filter(g => g.scopeId === res.scopeId)
check('draft emit: the draft reaches the Director, published by the agent identity',
  onDesk.length === 1 && onDesk[0].publisher === agentPub && onDesk[0].scopeName === res.scopeName)

// Withdraw through the remote signer tombstones the SCOPE (the grant record is
// unchanged; the granted key simply no longer dereferences it).
const before = await fetchScope(relay, onDesk[0])
await desk.withdraw(res.scopeId)
const afterScope = await fetchScope(relay, onDesk[0])
check('draft withdraw: supersession through the remote signer — the granted key no longer opens it',
  before.status === 'ok' && afterScope.status !== 'ok')

// --- the guard: local-key ops refuse under a remote signer ----------------
let threw = false
try { requireLocalKey(nip46Identity, 'grant issuance') } catch (e) { threw = /remote .*signer/i.test(String(e.message)) }
check('requireLocalKey: refuses cleanly under a remote signer', threw)
const localIdentity = { signer: localSigner(agentSk), secretKey: agentSk, pubkey: agentPub, npub: '', source: 'env' }
check('requireLocalKey: returns the key for a local backend',
  requireLocalKey(localIdentity, 'x') === agentSk)

console.log(failed ? '\nNIP46-SIGNER: FAIL' : '\nNIP46-SIGNER: ALL PASS')
process.exit(failed)
