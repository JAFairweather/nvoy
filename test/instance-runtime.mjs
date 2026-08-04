// Multi-instance runtime contract (#44): a public manifest names exactly one identity and
// isolated state. This drives the real CLI, rather than duplicating its validation in a unit.
import { mkdtempSync, writeFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-instance-'))
const key = generateSecretKey(), pubkey = getPublicKey(key)
const keyFile = join(root, 'identity.nsec')
writeFileSync(keyFile, nip19.nsecEncode(key), { mode: 0o600 })
const manifestFile = join(root, 'codex.json')
const manifest = { version: 1, id: 'codex-test', keyFile, recipient: nip19.npubEncode(pubkey),
  stateDir: join(root, 'state-codex'), grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'],
  relays: ['wss://nos.lol', 'wss://relay.primal.net'] }
writeFileSync(manifestFile, JSON.stringify(manifest))
const cli = (...args) => spawnSync(process.execPath, ['mcp/tools/instance-runtime.mjs', ...args], { cwd: resolve('.'), encoding: 'utf8' })

const good = cli('describe', '--manifest', manifestFile)
const described = JSON.parse(good.stdout || '{}')
ok('a valid instance manifest describes its public identity', good.status === 0 && described.recipient === pubkey)
ok('the description does not disclose the key path', !good.stdout.includes(keyFile))
ok('the instance receives its own state directory', described.stateDir === manifest.stateDir)

chmodSync(keyFile, 0o644)
const loose = cli('describe', '--manifest', manifestFile)
ok('a group/world-readable identity file is refused', loose.status !== 0 && /mode 0600/.test(loose.stderr))
chmodSync(keyFile, 0o600)

writeFileSync(manifestFile, JSON.stringify({ ...manifest, recipient: 'f'.repeat(64) }))
const mismatch = cli('attention', '--manifest', manifestFile)
ok('a manifest/key identity mismatch is refused before attention can decrypt', mismatch.status !== 0 && /does not match/.test(mismatch.stderr))

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
