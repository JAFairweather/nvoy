// fsintercept.mjs — no_persist conformance preload (spec §5, §8).
//
// Loaded into the REAL server binary via NODE_OPTIONS="--import <this file>"
// BEFORE any app module links, so every later `require('fs')`, default
// import, and static named import of the fs builtins snapshots the patched
// functions. Each intercepted write API scans its arguments for the canary
// string in NVOY_TEST_MARKER; a hit prints "[fsintercept] VIOLATION <api>"
// to stderr (never to a file — the watchdog must not itself persist).
//
// NVOY_TEST_SELFCHECK=1 proves the interception is live (not a vacuous
// pass): it writes the marker to /dev/null — intercepted, nothing persisted
// — and reports "[fsintercept] selfcheck ok".

import fs from 'node:fs'

const marker = process.env.NVOY_TEST_MARKER
let selfchecking = false

const asText = (x) => {
  try {
    if (typeof x === 'string') return x
    if (x instanceof Uint8Array) return Buffer.from(x).toString('utf8')
    if (Array.isArray(x)) return x.map(asText).join('')
    return ''
  } catch {
    return ''
  }
}

const inspect = (api, args) => {
  if (!marker) return
  for (const a of args) {
    if (asText(a).includes(marker)) {
      console.error(selfchecking ? '[fsintercept] selfcheck ok' : `[fsintercept] VIOLATION ${api}`)
      return
    }
  }
}

const wrap = (obj, name) => {
  const orig = obj?.[name]
  if (typeof orig !== 'function') return
  obj[name] = function (...args) {
    inspect(name, args)
    return orig.apply(this, args)
  }
}

// callback + sync surface
for (const name of ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
                    'write', 'writeSync', 'writev', 'writevSync']) wrap(fs, name)

// stream surface: scan everything written through created streams
{
  const orig = fs.createWriteStream
  fs.createWriteStream = function (...args) {
    const stream = orig.apply(this, args)
    for (const name of ['write', 'end']) {
      const m = stream[name]
      stream[name] = function (...a) {
        inspect(`createWriteStream.${name}`, a)
        return m.apply(this, a)
      }
    }
    return stream
  }
}

// promises surface — fs.promises IS the fs/promises module exports object in
// Node, so patching here covers `import ... from 'node:fs/promises'` too.
for (const name of ['writeFile', 'appendFile']) wrap(fs.promises, name)
{
  const origOpen = fs.promises.open
  fs.promises.open = async function (...args) {
    const handle = await origOpen.apply(this, args)
    for (const name of ['write', 'writev', 'writeFile', 'appendFile']) wrap(handle, name)
    return handle
  }
}

console.error('[fsintercept] armed')

if (process.env.NVOY_TEST_SELFCHECK) {
  selfchecking = true
  try {
    fs.writeFileSync('/dev/null', marker ?? 'no-marker')
  } catch {
    console.error('[fsintercept] selfcheck FAILED to exercise writeFileSync')
  }
  selfchecking = false
}
