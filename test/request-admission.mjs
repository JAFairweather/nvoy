import { mkdtempSync, writeFileSync, chmodSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'

const ROOT = resolve(import.meta.dirname, '..')
const TOOL = join(ROOT, 'mcp', 'tools', 'request-admission.mjs')
const dir = mkdtempSync(join(tmpdir(), 'nvoy-request-admission-'))
const sk = generateSecretKey()
const key = join(dir, 'identity.nsec')
writeFileSync(key, `${nip19.nsecEncode(sk)}\n`, { mode: 0o600 })

const run = (...args) => spawnSync(process.execPath, [TOOL, ...args], {
  cwd: ROOT,
  env: { ...process.env, DRY_RUN: '1' },
  encoding: 'utf8',
})

let fails = 0
const ok = (label, condition) => {
  console.log(`${condition ? 'ok  ' : 'FAIL'} — ${label}`)
  if (!condition) fails++
}

const persistent = run('--key', key, '--purpose', 'persistent participant test')
const npub = nip19.npubEncode(getPublicKey(sk))
ok('a mode-0600 existing nsec is accepted', persistent.status === 0)
ok('the request uses that exact participant identity', persistent.stderr.includes(`existing participant npub ${npub}`))
ok('stdout exposes only the key path', persistent.stdout.trim() === key)
ok('a persistent identity is never told to burn its key', !persistent.stderr.includes('shred -u'))
ok('the nsec is never printed', !`${persistent.stdout}${persistent.stderr}`.includes(nip19.nsecEncode(sk)))

chmodSync(key, 0o644)
const exposed = run('--key', key)
ok('a group/world-readable key fails closed', exposed.status !== 0 && /mode 0600/.test(exposed.stderr))

const malformed = join(dir, 'malformed.nsec')
writeFileSync(malformed, `${'x'.repeat(64)}\n`, { mode: 0o600 })
const bad = run('--key', malformed)
ok('a malformed key fails closed', bad.status !== 0 && /valid nsec/.test(bad.stderr))

const linked = join(dir, 'linked.nsec')
symlinkSync(malformed, linked)
const symlinked = run('--key', linked)
ok('a symlinked key fails closed', symlinked.status !== 0 && /non-symlink/.test(symlinked.stderr))

console.log(fails ? `\nrequest-admission: ${fails} failed` : '\nrequest-admission: all checks passed')
process.exit(fails ? 1 : 0)
