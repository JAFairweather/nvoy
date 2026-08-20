// identity-binding.mjs — a process must know which identity it holds before it acts (#338).
//
// The reported symptom was that a remote agent's nvoy_whoami returned a DIFFERENT agent's identity.
// Nothing was broken enough to fail. Two identity claims existed and nothing compared them:
//
//   1. `identity.pubkey` — for a bunker, PARSED OUT OF THE URI (identity.ts: `pubkey = m[1]`), and
//      reported verbatim by nvoy_whoami;
//   2. whatever the signer actually signs as — the bunker's own get_public_key.
//
// Point a shared server's credential env at one identity while a session believes it is another and
// whoami answers with #1 while every signature is authored by #2.
//
// Both directions matter and a green suite hides the difference: a binding check that refuses
// everything and one that refuses nothing are indistinguishable unless the legitimate case is
// asserted to still pass.

import { bindIdentity } from '../mcp/dist/identity.js'

let failed = 0
const check = (name, ok) => { console.log(ok ? '  ok' : 'FAIL', name); if (!ok) failed++ }

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)

// A signer whose reported key is set independently of the claim — which is the whole bug.
const signerSaying = (pubkey, { throws = null } = {}) => ({
  getPublicKey: async () => { if (throws) throw new Error(throws); return pubkey },
  signEvent: async (e) => e,
  nip44Encrypt: async () => '',
  nip44Decrypt: async () => '',
})
const identity = (claimed, signs, extra = {}) => ({
  pubkey: claimed, npub: `npub-${claimed.slice(0, 6)}`, source: 'nip46',
  signer: signerSaying(signs, extra),
})
const bind = async (id, env = {}) => {
  try { await bindIdentity(id, env); return { ok: true } }
  catch (error) { return { ok: false, error: String(error.message) } }
}

// ---- the legitimate case FIRST, so nothing below can be vacuous ------------------------------
check('an identity whose signer agrees with its configuration is accepted',
  (await bind(identity(A, A))).ok)
check('…and it is still accepted when a matching binding is declared',
  (await bind(identity(A, A), { NVOY_EXPECTED_PUBKEY: A })).ok)
check('…and an UPPERCASE declared binding still matches — case is not a mismatch',
  (await bind(identity(A, A), { NVOY_EXPECTED_PUBKEY: A.toUpperCase() })).ok)

// ---- #338 itself: the claim and the signer disagree -------------------------------------------
{
  const r = await bind(identity(A, B))
  check('#338 a signer that signs as someone else is REFUSED', !r.ok)
  // Assert the REASON, not just the refusal. This message is the whole diagnosis: without it an
  // operator sees a boot failure and starts looking at relays.
  check('#338 …and the refusal names both keys, so the mix-up is visible',
    /identity mismatch/.test(r.error) && r.error.includes(A.slice(0, 12)) && r.error.includes(B.slice(0, 12)))
  check('#338 …and says what would otherwise have happened — whoami one key, signatures another',
    /whoami/i.test(r.error) && /signature/i.test(r.error))
}

// ---- the declared binding: what makes a shared server safe to register per-agent ---------------
{
  const r = await bind(identity(A, A), { NVOY_EXPECTED_PUBKEY: B })
  check('a process bound to one agent refuses to run as a different one', !r.ok)
  check('…and says so as a binding failure, not as a mismatch', /refusing to act as another agent/.test(r.error))
  const bad = await bind(identity(A, A), { NVOY_EXPECTED_PUBKEY: 'not-a-key' })
  check('a malformed binding is refused rather than ignored',
    !bad.ok && /64-character hex/.test(bad.error))
  // BOTH DIRECTIONS on the optionality: no declaration is allowed (it is opt-in), but it must not
  // become a way to skip the claim-vs-signer check above.
  check('an ABSENT binding is allowed — the declaration is opt-in',
    (await bind(identity(A, A), {})).ok)
  check('…but an absent binding does not skip the mismatch check',
    !(await bind(identity(A, B), {})).ok)
}

// ---- being unable to check is not being fine ---------------------------------------------------
{
  const r = await bind(identity(A, A, { throws: 'bunker unreachable' }))
  check('a signer that cannot be asked is REFUSED, not assumed to match the claim', !r.ok)
  check('…and the message says the identity is unconfirmed rather than wrong',
    /unconfirmed identity/.test(r.error) && /bunker unreachable/.test(r.error))
  const empty = await bind(identity(A, ''))
  check('a signer that reports nothing is refused', !empty.ok && /did not report a public key/.test(empty.error))
  const junk = await bind(identity('nope', 'nope'))
  check('an identity with no usable key is refused before anything is asked',
    !junk.ok && /no usable public key/.test(junk.error))
}

// ---- the check has to run at BOOT, not merely exist ---------------------------------------------
// A helper nobody calls is the same as no helper, and that is exactly how the original defect
// survived: the information was available and nothing compared it.
{
  const { readFileSync } = await import('node:fs')
  const server = readFileSync(new URL('../mcp/src/server.ts', import.meta.url), 'utf8')
  check('server.ts binds the identity before building the context',
    /await bindIdentity\(loadIdentity\(\)\)/.test(server))
  check('…and does not also construct an unbound identity somewhere else',
    (server.match(/loadIdentity\(\)/g) || []).length === 1)
}

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed')
process.exit(failed ? 1 : 0)
