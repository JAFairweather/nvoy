// A NIP-46 pairing URI carries a bearer secret. Nvoy may read it from a private
// file, but it must never force callers to embed it in an MCP config/env literal.
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { loadBunkerUri } from '../mcp/dist/identity.js'

let failed = 0
const check = (name, ok) => { console.log(ok ? '  ok' : 'FAIL', name); if (!ok) failed++ }
const dir = mkdtempSync(join(tmpdir(), 'nvoy-nip46-uri-'))
const file = join(dir, 'bunker-uri')
const uri = `bunker://${'a'.repeat(64)}?relay=wss%3A%2F%2Frelay.example&secret=pairing-secret`
const read = (env) => { try { return { value: loadBunkerUri(env) } } catch (error) { return { error: String(error.message) } } }

try {
  writeFileSync(file, `${uri}\n`, { mode: 0o600 })
  check('mode-0600 URI file is accepted', read({ NVOY_BUNKER_URI_FILE: file }).value === uri)
  chmodSync(file, 0o644)
  check('group/world-readable URI file is refused', /chmod 600/.test(read({ NVOY_BUNKER_URI_FILE: file }).error || ''))
  chmodSync(file, 0o600)
  const link = join(dir, 'link')
  symlinkSync(file, link)
  check('symlink URI file is refused', /non-symlink/.test(read({ NVOY_BUNKER_URI_FILE: link }).error || ''))
  // A symlink swap after an open must not change what gets read. We cannot reliably race the
  // scheduler in a test, so assert the implementation uses the descriptor-safe primitives; the
  // production code's open(O_NOFOLLOW) + fstat(fd) + read(fd) is the property being protected.
  const identitySource = readFileSync(new URL('../mcp/src/identity.ts', import.meta.url), 'utf8')
  check('credential file reads pin a no-follow opened descriptor (no pathname re-open race)', /openSync\(path, fsConstants\.O_RDONLY \| fsConstants\.O_NOFOLLOW\)/.test(identitySource) && /fstatSync\(fd\)/.test(identitySource) && /readFileSync\(fd, 'utf8'\)/.test(identitySource) && !/readFileSync\(path, 'utf8'\)/.test(identitySource))
  check('ambiguous direct and file URI is refused', /only one/.test(read({ NVOY_BUNKER_URI: uri, NVOY_BUNKER_URI_FILE: file }).error || ''))
} finally { rmSync(dir, { recursive: true, force: true }) }

if (failed) process.exit(1)
console.log('nip46-uri-file: all checks passed')
