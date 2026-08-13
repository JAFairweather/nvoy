// NVOY_EXPECTED_PUBKEY — the MCP path's EXPECT_PUBKEY (#191, waggle#338).
//
// A server whose env pointed at another agent's credentials came up AS that agent: whoami answered
// with their key, and it would have signed and read their sealed inbox, silently, because a
// wrong-identity pairing works perfectly. This asserts the guard in BOTH directions — a check that
// only ever refuses cannot distinguish "catches the wrong identity" from "refuses everything".
//
//   node test/identity-expected-pubkey.mjs

import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import { loadIdentity } from '../mcp/dist/identity.js'

let passed = 0, failed = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passed++ : failed++ }

const sk = generateSecretKey()
const pk = getPublicKey(sk)
const nsec = nip19.nsecEncode(sk)
const other = getPublicKey(generateSecretKey())

const load = expected => loadIdentity([], { NVOY_NSEC: nsec, ...(expected === undefined ? {} : { NVOY_EXPECTED_PUBKEY: expected }) })
const refusal = expected => { try { load(expected); return null } catch (error) { return error.message } }
// A guard that wrongly refuses makes these throw. Returning null instead of propagating keeps the
// verdict printed — an aborted run reports nothing for the very assertion that just caught the bug.
const loaded = expected => { try { return load(expected).pubkey } catch { return null } }

// --- the guard is opt-in, exactly like EXPECT_PUBKEY -------------------------------------------
ok('with no expectation set, the identity loads unchanged', loaded(undefined) === pk)

// --- POSITIVE: the matching key must still start. Without this the suite cannot tell a working
// guard from one that refuses everything, which is the failure mode that shipped here before.
ok('a matching hex pubkey still starts', loaded(pk) === pk)
ok('a matching npub still starts', loaded(nip19.npubEncode(pk)) === pk)
ok('an UPPERCASE hex expectation still matches (case is not identity)', loaded(pk.toUpperCase()) === pk)
ok('surrounding whitespace does not break a legitimate match', loaded(`  ${pk}  `) === pk)

// --- NEGATIVE: the wrong key must be refused, and the refusal must NAME BOTH keys. Asserting only
// that it threw cannot distinguish a correct refusal from a correct refusal that sends the reader
// hunting the wrong credential.
const mismatch = refusal(other)
ok('a different pubkey is refused', mismatch !== null)
ok('the refusal names the resolved identity', !!mismatch && mismatch.includes(nip19.npubEncode(pk)))
ok('the refusal names the expected identity', !!mismatch && mismatch.includes(nip19.npubEncode(other)))
const mismatchNpub = refusal(nip19.npubEncode(other))
ok('a different npub is refused too', mismatchNpub !== null)

// --- malformed must be an ERROR, not a silent "no expectation". A typo'd guard that disables
// itself is worse than no guard, because it reads as protection.
for (const [label, value] of [
  ['a truncated hex string', pk.slice(0, 32)],
  ['a non-hex string', 'not-a-pubkey'],
  ['an npub that does not decode', 'npub1zzzzzzzzzzzz'],
  ['an nsec where a pubkey belongs', nsec],
]) {
  const message = refusal(value)
  ok(`${label} is rejected as malformed rather than ignored`,
    message !== null && /must be an npub or a 64-character hex pubkey/.test(message))
}
// An nsec must never be accepted here, and must not be echoed back in the error either.
ok('a rejected nsec is not echoed into the error message', !String(refusal(nsec)).includes(nsec))

// An empty/whitespace value is "unset", not "malformed" — otherwise an exported-but-empty variable
// would hard-stop every server that never opted in.
ok('an empty expectation is treated as unset, not malformed', loaded('') === pk)
ok('a whitespace-only expectation is treated as unset', loaded('   ') === pk)

console.log(`\n${passed}/${passed + failed} passed`)
process.exit(failed ? 1 : 0)
