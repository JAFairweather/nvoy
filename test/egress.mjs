// egress.mjs — the zero-egress guarantee for BOTH halves of Nvoy, enforced
// at the strongest level feasible without a headless browser. Nvoy has no
// server of its own: the console is a pure browser client, and the MCP
// server talks only to relays and its local MCP transport.
//
//   A. CONSOLE (browser client)
//      1. STATIC SCAN: every absolute URL in shipped code (root redirect,
//         console/*.mjs, console/index.html) resolves to an allowed origin.
//         Network origins are exactly the configured relays and esm.sh (the
//         pinned module CDN). Nvoy ships NO Blossom hosts — outbox payloads
//         stay JSON; Blossom artifact pointers are deferred post-v1.
//         github.com is allowed ONLY as an <a href>/banner link in HTML
//         (user navigation, not egress); w3.org ONLY as an SVG namespace in
//         the favicon (never fetched); localhost / URL-parse bases ONLY in
//         the dev server; *.example ONLY as reserved placeholder copy.
//      2. CONSISTENCY: the allowlist is cross-checked against the live
//         config module (config.mjs DEFAULT_RELAYS + defaultConfig) and the
//         import map, so it cannot drift.
//      3. IMPORT-TIME INTERCEPTION: fetch / WebSocket / XMLHttpRequest are
//         replaced with recording traps, then every DOM-free module is
//         imported; zero network calls may occur at module load.
//      4. AT-REST DISCIPLINE: the only key material reaching localStorage
//         goes through nip49.encrypt (the NIP-49 ncryptsec); the raw key
//         lives only in the tab-session slot; everything else persisted is
//         non-secret (relays, dismissed-request ids).
//
//   B. MCP SERVER (agent runtime, Node/TS)
//      5. STATIC SCAN of mcp/src AND the built mcp/dist: only the relay set
//         and the LOCAL MCP HTTP transport (a `http://${host}` template
//         binding 127.0.0.1 by default). No Blossom, no telemetry origin.
//      6. CONSISTENCY: identity.js DEFAULT_RELAYS + loadRelays() default ⊆
//         allowlist.
//      7. IMPORT-TIME INTERCEPTION: the built leaf modules import cleanly
//         under the network traps — nothing dials out at load.
//      8. AT-REST DISCIPLINE: the server writes NO key material to disk —
//         identity.ts only READS an ncryptsec file; the sole fs write is the
//         stderr shutdown line (fd 2). Asserted against src.
//
// What this does NOT cover (documented, not hidden): runtime sockets in a
// real browser / live server (nostr-tools opens sockets only to the relay
// URLs we pass it — the static scan pins those), and a tampered CDN serving
// different code than audited (see SECURITY.md, "code delivery path").
//
//   node test/egress.mjs        (run `npm run build` first — scans mcp/dist)

import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

// The one and only egress allowlist. Relays + the pinned module CDN. No
// Blossom hosts ship in v1 (outbox payloads are JSON; artifact pointers are
// deferred — CLAUDE.md decision 26).
const NETWORK = new Set([
  'wss://nos.lol', 'wss://relay.primal.net', // relays
  'https://esm.sh',                                                  // pinned modules (console)
])
const LINK_ONLY = new Set(['https://github.com'])   // <a href> / alpha banner in HTML only
// The family-nav footer: first-party links to the hub + sibling apps. Link-only
// and HTML-only, same discipline as LINK_ONLY — one of these origins showing up
// in a .mjs or as a fetch target must still fail the scan (#26).
const FIRST_PARTY = (host) => host === 'nave.pub' || host.endsWith('.nave.pub')
const NAMESPACE = new Set(['http://www.w3.org'])    // svg xmlns in the favicon, never fetched
const DEV_ONLY = new Set(['http://localhost:4443', 'http://x'])  // console/serve.mjs
const RESERVED = (host) => host === 'example.com' || host.endsWith('.example')
// A `http://${...}` template literal is the LOCAL MCP HTTP transport binding
// (127.0.0.1 by default; NVOY_HTTP_HOST is the operator's explicit act). It
// is not a shipped destination — the host is interpolated at runtime.
const TEMPLATE = (raw) => raw.includes('$')

const urlRx = /\b(?:https?|wss?):\/\/[^\s"'`<>\\)\]{},]*/g

/** Scan a set of files; every URL must land in the allowlist or an
 *  explicitly-justified exception. Returns [scanned, found, offenders]. */
function scan(files, { allowServerTemplates = false } = {}) {
  const offenders = []
  let scanned = 0, found = 0
  for (const file of files) {
    const src = readFileSync(file, 'utf8')
    scanned++
    const rel = file.slice(root.length + 1)
    for (const raw of src.match(urlRx) ?? []) {
      if (allowServerTemplates && TEMPLATE(raw)) continue  // local MCP transport binding
      let origin, host
      try { ({ origin, host } = new URL(raw)) } catch { origin = raw; host = '' }
      if (!host || host === '$') continue                  // bare "wss://" in prose, not a destination
      found++
      if (NETWORK.has(origin)) continue
      if (RESERVED(host)) continue
      if (LINK_ONLY.has(origin) && rel.endsWith('.html') && src.includes(`href="${origin}`)) continue
      if (FIRST_PARTY(host) && rel.endsWith('.html') && src.includes(`href="${origin}`)) continue
      if (NAMESPACE.has(origin) && src.includes(`xmlns='${origin}`)) continue
      if (DEV_ONLY.has(origin) && rel.endsWith('serve.mjs')) continue
      offenders.push(`${rel}: ${raw}`)
    }
  }
  return [scanned, found, offenders]
}

// ==========================================================================
console.log('\nA. CONSOLE (browser client)')
// ==========================================================================

console.log('\n1. Static scan: every URL in shipped console code resolves to an allowed origin')
const consoleFiles = [
  join(root, 'index.html'),                                // root redirect page
  join(root, 'consent.html'),                              // public consent signer
  join(root, 'console', 'index.html'),
  ...readdirSync(join(root, 'console')).filter(f => f.endsWith('.mjs')).map(f => join(root, 'console', f)),
]
{
  const [scanned, found, offenders] = scan(consoleFiles)
  check(`no unexpected origins in ${scanned} console files (${found} URLs found)`,
    offenders.length === 0, offenders.join(' | '))
  check('the scan itself sees the expected surface', found >= 6,
    'regex or file list broke if this number collapses')
}

console.log('\n2. Consistency: the allowlist matches the live console config')
const cfgSrc = readFileSync(join(root, 'console', 'config.mjs'), 'utf8')
const cfgRelays = cfgSrc.match(/wss:\/\/[a-z0-9.-]+/g) ?? []
check('every default console relay is allowlisted',
  cfgRelays.length >= 2 && cfgRelays.every(r => NETWORK.has(r)), cfgRelays.join(', '))
const htmlSrc = readFileSync(join(root, 'console', 'index.html'), 'utf8')
const importMap = htmlSrc.match(/<script type="importmap">([\s\S]*?)<\/script>/)?.[1] ?? ''
const imports = Object.values(JSON.parse(importMap).imports).map(u => new URL(u).origin)
check('import map points only at esm.sh',
  imports.length >= 3 && imports.every(o => o === 'https://esm.sh'), [...new Set(imports)].join(', '))
check('no Blossom / third-party host in the import map or config',
  !/nostr\.download|cdn\.hzrd149|blossom/i.test(cfgSrc + htmlSrc))

console.log('\n3. Import-time interception: nothing phones home on console module load')
const calls = []
globalThis.fetch = (u) => { calls.push(String(u)); return Promise.reject(new Error('egress blocked')) }
globalThis.XMLHttpRequest = class { open(m, u) { calls.push(String(u)) } send() { throw new Error('egress blocked') } setRequestHeader() {} }
globalThis.WebSocket = class { constructor(u) { calls.push(String(u)); throw new Error('egress blocked') } }
const domFree = ['../console/config.mjs', '../console/ledgerlog.mjs', '../console/ttl.mjs',
  '../console/nvoygrant.mjs', '../lib/nipxx.mjs', '../lib/liverelay.mjs', '../lib/relay.mjs']
let importErr = null
let config
try {
  for (const m of domFree) {
    const mod = await import(m)
    if (m.includes('config')) config = mod
  }
} catch (err) { importErr = err }
check('all DOM-free console + lib modules import cleanly under the traps', importErr === null, importErr?.message ?? '')
check('zero network calls at console import time', calls.length === 0, calls.join(', '))

console.log('\n4. Live config: shipped defaults stay inside the allowlist; garbage cannot widen them')
const dflt = config.defaultConfig()
check('defaultConfig relays ⊆ allowlist',
  dflt.relays.length >= 2 && dflt.relays.every(r => NETWORK.has(r)), dflt.relays.join(', '))
// A corrupt / hostile stored config must sanitize to the defaults, never
// inject arbitrary origins with invalid schemes.
const bad = { getItem: () => JSON.stringify({ relays: ['javascript:alert(1)', 'http://evil.example', 'ftp://evil.example'] }) }
check('invalid schemes sanitize back to defaults',
  JSON.stringify(config.loadConfig(bad)) === JSON.stringify(dflt))
// A user-chosen relay (their own policy) survives the round trip; ws:// is
// deliberately allowed for a local test relay.
const store = new Map()
const stub = { getItem: k => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: k => store.delete(k) }
config.saveConfig({ relays: ['ws://localhost:4460/', 'wss://my.relay.example/'] }, stub)
const mine = config.loadConfig(stub)
check('user relay config round-trips (trailing slash stripped, ws:// kept)',
  mine.relays[0] === 'ws://localhost:4460' && mine.relays[1] === 'wss://my.relay.example')

console.log('\n5. At-rest discipline: the console persists secrets only as a NIP-49 ncryptsec')
const mainSrc = readFileSync(join(root, 'console', 'main.mjs'), 'utf8')
const settingsSrc = readFileSync(join(root, 'console', 'settings.mjs'), 'utf8')
const allConsoleSrc = consoleFiles.map(f => readFileSync(f, 'utf8')).join('\n')
const lsWrites = allConsoleSrc.match(/localStorage\.setItem\([^\n]*/g) ?? []
// The ONE localStorage write that touches key material must go through
// nip49.encrypt; every other write is non-secret (relays, dismissed ids).
check('the only key-material localStorage write is the nip49 ncryptsec',
  lsWrites.length >= 1
  && lsWrites.some(w => w.includes('NC_KEY') && w.includes('nip49.encrypt'))
  && lsWrites.every(w => !/nsec|hexOf|\bsk\b|generateSecretKey/.test(w) || w.includes('nip49.encrypt')),
  lsWrites.join(' | '))
// saveConfig (endpoints) and dismissed-request ids are the only other
// persisted state, and neither is secret.
check('config + dismissed-request writes carry no key material',
  !/localStorage\.setItem\([^)]*nsec/i.test(allConsoleSrc)
  && !/setItem\(\s*CONFIG_KEY[^)]*sk\b/.test(settingsSrc))
const consentSrc = readFileSync(join(root, 'console', 'consent.mjs'), 'utf8')
const consentHtml = readFileSync(join(root, 'consent.html'), 'utf8')
check('the consent testing key is password-masked, immediately cleared, and never persisted',
  /id="test-nsec" type="password"/.test(consentHtml)
  && /field\.value = ''/.test(consentSrc)
  && !/Storage\.(?:setItem|removeItem).*test-nsec|test-nsec.*Storage\.(?:setItem|removeItem)/s.test(consentSrc),
  'the burner-only key must remain a one-tab, one-shot signer')
const ssWrites = mainSrc.match(/sessionStorage\.setItem\('([^']+)'/g) ?? []
check('sessionStorage keys are exactly the tab-session login + protect opt-out',
  ssWrites.length === 2
  && ssWrites.join().includes('nvoy-login')
  && ssWrites.join().includes('nvoy-no-protect'), ssWrites.join(' | '))

// ==========================================================================
console.log('\nB. MCP SERVER (agent runtime)')
// ==========================================================================

const srcDir = join(root, 'mcp', 'src')
const distDir = join(root, 'mcp', 'dist')
check('mcp/dist exists (run `npm run build` first)', existsSync(distDir),
  'the static + import scans below need the compiled output')

console.log('\n6. Static scan: mcp/src and the built mcp/dist reach only relays + the local transport')
{
  const files = [
    ...readdirSync(srcDir).filter(f => f.endsWith('.ts')).map(f => join(srcDir, f)),
    ...(existsSync(distDir) ? readdirSync(distDir).filter(f => f.endsWith('.js')).map(f => join(distDir, f)) : []),
  ]
  const [scanned, found, offenders] = scan(files, { allowServerTemplates: true })
  check(`no unexpected origins in ${scanned} mcp files (${found} real URLs found)`,
    offenders.length === 0, offenders.join(' | '))
  check('the mcp scan sees the relay set', found >= 3, 'regex or file list broke if this collapses')
}

console.log('\n7. Consistency: mcp default relays ⊆ allowlist')
let ident = null
if (existsSync(join(distDir, 'identity.js'))) {
  ident = await import('../mcp/dist/identity.js')
  check('DEFAULT_RELAYS ⊆ allowlist',
    ident.DEFAULT_RELAYS.length >= 2 && ident.DEFAULT_RELAYS.every(r => NETWORK.has(r)),
    ident.DEFAULT_RELAYS.join(', '))
  check('loadRelays() default ⊆ allowlist',
    ident.loadRelays({}).every(r => NETWORK.has(r)), ident.loadRelays({}).join(', '))
} else {
  check('DEFAULT_RELAYS ⊆ allowlist', false, 'mcp/dist not built')
}

console.log('\n8. Import-time interception: built mcp leaf modules do not dial out at load')
{
  const calls2 = []
  globalThis.fetch = (u) => { calls2.push(String(u)); return Promise.reject(new Error('egress blocked')) }
  globalThis.WebSocket = class { constructor(u) { calls2.push(String(u)); throw new Error('egress blocked') } }
  const leaves = ['terms.js', 'grants.js', 'scopes.js', 'outbox.js', 'notices.js', 'app.js']
    .filter(f => existsSync(join(distDir, f)))
  let mcpImportErr = null
  try { for (const f of leaves) await import(`../mcp/dist/${f}`) }
  catch (err) { mcpImportErr = err }
  check('built mcp leaf modules import cleanly under the traps', mcpImportErr === null && leaves.length >= 5,
    mcpImportErr?.message ?? `${leaves.length} modules`)
  check('zero network calls at mcp import time', calls2.length === 0, calls2.join(', '))
}

console.log('\n9. At-rest discipline: the MCP server writes NO key material to disk')
{
  const srcFiles = readdirSync(srcDir).filter(f => f.endsWith('.ts')).map(f => join(srcDir, f))
  const src = srcFiles.map(f => `\n// ${f}\n` + readFileSync(f, 'utf8')).join('')
  // No file-write API is used anywhere in the server (writeFile/appendFile/
  // WriteStream/createWriteStream). Identity files are read only; lstatSync
  // is also used to reject unsafe NIP-46 URI-file permissions/symlinks.
  check('no writeFile / appendFile / WriteStream in mcp/src',
    !/writeFile|appendFile|WriteStream/.test(src))
  const identSrc = readFileSync(join(srcDir, 'identity.ts'), 'utf8')
  check('identity.ts imports only readFileSync/lstatSync from fs (identity reads, never writes)',
    /import\s*\{\s*lstatSync\s*,\s*readFileSync\s*\}\s*from\s*'node:fs'/.test(identSrc)
    && !/writeFileSync|writeSync/.test(identSrc))
  // server.ts uses fs.writeSync ONLY to fd 2 (stderr shutdown line) — never a file.
  const serverSrc = readFileSync(join(srcDir, 'server.ts'), 'utf8')
  const writeSyncCalls = serverSrc.match(/writeSync\(([^,]+),/g) ?? []
  check('the only fs.writeSync targets fd 2 (stderr), not a file',
    writeSyncCalls.length >= 1 && writeSyncCalls.every(w => /writeSync\(\s*2\s*,/.test(w)),
    writeSyncCalls.join(' | '))
}

console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
process.exit(failed === 0 ? 0 : 1)
