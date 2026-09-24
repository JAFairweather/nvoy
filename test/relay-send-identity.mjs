import { spawnSync } from 'node:child_process'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'

let pass = 0, fail = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? pass++ : fail++ }
const sk = generateSecretKey(), pk = getPublicKey(sk), nsec = nip19.nsecEncode(sk)
const bridge = getPublicKey(generateSecretKey())
const run = (expected, extra = { WAGGLE_BRIDGE_PUBKEY: bridge }) => spawnSync(process.execPath, ['mcp/tools/relay-send.mjs'], {
  encoding: 'utf8', input: 'identity-bound dry run', env: { ...process.env, WAGGLE_BRIDGE_PUBKEY: '', NVOY_NSEC: nsec, EXPECT_PUBKEY: expected, DRY_RUN: '1', ...extra },
})
const match = run(nip19.npubEncode(pk))
ok('relay send accepts the explicitly expected signer identity', match.status === 0 && /DRY_RUN/.test(match.stderr))
const mismatch = run('f'.repeat(64))
ok('relay send refuses a valid credential that resolves to another identity', mismatch.status !== 0 && /signer identity mismatch/.test(mismatch.stderr) && !/sealed wrap/.test(mismatch.stderr))
const malformed = run('npub1not-valid')
ok('relay send fails closed on a malformed expected identity', malformed.status !== 0 && /EXPECT_PUBKEY must/.test(malformed.stderr))
const noBridge = run(nip19.npubEncode(pk), {})
ok('relay send has no default recipient', noBridge.status !== 0 && /WAGGLE_BRIDGE_PUBKEY/.test(noBridge.stderr) && !/sealed wrap/.test(noBridge.stderr))

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
