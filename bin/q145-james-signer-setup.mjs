#!/usr/bin/env node
// James-run, once, on his Mac: makes the two files bin/q145-grants.mjs --apply
// signs with, proves the Bunker signs as James, and prints the three paste lines.
//   1. a NIP-46 client key, 64-hex, mode 0600, made here and never printed;
//   2. the bunker:// connection he copies from Bunker46, read by hidden prompt
//      (never from argv, never echoed), stored mode 0600 only once proven;
//   3. one get_public_key call that must answer James's key. Nothing is signed.
// Default paths are the ones herd-infra mac/bin/herd-memory --bunker reads.
// In Bunker46 grant the connection only sign_event kind 440 and kind 441 (see
// docs/Q160_GRANT_SIGNING_RUNBOOK.md); this script cannot check that.
import { closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { makeBunkerSigner } from '../mcp/tools/nip46-signer.mjs'
import { secretKey } from '../mcp/tools/secret_key.mjs'
import { JAMES } from './q145-grants.mjs'

const CRED = join(homedir(), '.nvoy-harness', 'credentials')
export const DEFAULT_URI_FILE = join(CRED, 'james-bunker-uri')
export const DEFAULT_CLIENT_FILE = join(CRED, 'james-bunker-client')
const BUNKER = /^bunker:\/\/[0-9a-f]{64}\?/i
const VERIFY_MS = 60000

export function options(argv) {
  const out = { 'uri-file': DEFAULT_URI_FILE, 'client-file': DEFAULT_CLIENT_FILE, 'new-uri': false }
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]
    // A pasted connection on the command line is already in shell history; say so without quoting it.
    if (/bunker:\/\//i.test(key)) throw new Error('never put the Bunker connection on the command line; paste it only at the hidden prompt, and clear it from your shell history')
    if (key === '--new-uri') out['new-uri'] = true
    else if (key === '--uri-file' || key === '--client-file') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) throw new Error(`${key} needs a path`)
      out[key.slice(2)] = resolve(value)
    } else throw new Error(`unknown option ${key}`)
  }
  if (out['uri-file'] === out['client-file']) throw new Error('--uri-file and --client-file must differ')
  return out
}

// The connection must parse as makeBunkerSigner reads it, with at least one wss relay.
// Errors name the problem, never the value.
export function checkBunkerUri(text) {
  const value = String(text ?? '').trim()
  if (!BUNKER.test(value)) throw new Error('that is not a bunker:// connection (bunker://<64 hex>?relay=...); nothing stored')
  let uri
  try { uri = new URL(value) } catch { throw new Error('that bunker:// connection does not parse; nothing stored') }
  if (!uri.searchParams.getAll('relay').some(v => /^wss:\/\//.test(v))) throw new Error('that bunker:// connection names no wss relay; nothing stored')
  return value
}

// A credential file must be a regular file (not a link), owned by this user, with no group or other access.
export function assertPrivateFile(path, stat = lstatSync(path), uid = process.getuid?.()) {
  if (!stat.isFile()) throw new Error(`${path} is not a regular file`)
  if (uid !== undefined && stat.uid !== uid) throw new Error(`${path} is not owned by you`)
  if (stat.mode & 0o077) throw new Error(`${path} is readable by others; run chmod 600 on it, or remove it, then rerun`)
}

function writeExclusive(path, text) {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600)
  try { writeSync(fd, text); fsyncSync(fd) } finally { closeSync(fd) }
}

// Reuses an existing client key (Bunker46 may already know it) or makes a new one.
export function ensureClientFile(path, fs = { existsSync, readFileSync, writeExclusive, assertPrivateFile }) {
  if (fs.existsSync(path)) {
    fs.assertPrivateFile(path)
    secretKey(fs.readFileSync(path, 'utf8'), path)
    return 'kept'
  }
  fs.writeExclusive(path, `${randomBytes(32).toString('hex')}\n`)
  return 'made'
}

// Hidden prompt, as herd-infra bin/put-credential asks: no echo from a terminal,
// one line from a pipe (a password manager's CLI). Ctrl-C or Ctrl-D stops.
export function readHidden(prompt, input = process.stdin, output = process.stderr) {
  if (!input.isTTY) {
    return new Promise((done, fail) => {
      let text = ''
      input.setEncoding('utf8')
      input.on('data', chunk => { text += chunk })
      input.on('end', () => done(text.split(/\r?\n/)[0]))
      input.on('error', fail)
    })
  }
  return new Promise((done, fail) => {
    let text = ''
    output.write(`${prompt}: `)
    input.setRawMode(true); input.setEncoding('utf8'); input.resume()
    const finish = (error) => {
      input.setRawMode(false); input.pause(); input.removeListener('data', onData)
      output.write('\n')
      error ? fail(error) : done(text)
    }
    const onData = chunk => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return finish()
        if (ch === '\u0003' || ch === '\u0004') return finish(new Error('stopped at the prompt; nothing stored'))
        if (ch === '\u007f' || ch === '\b') text = text.slice(0, -1)
        else text += ch
      }
    }
    input.on('data', onData)
  })
}

export function pasteLines(uriFile, clientFile) {
  const q = path => `'${path.replaceAll("'", "'\\''")}'`
  const flags = `--bunker-uri-file ${q(uriFile)} --bunker-client-file ${q(clientFile)}`
  return ['revokes', 'task', 'mention'].map(batch => `node bin/q145-grants.mjs --apply --batch ${batch} ${flags}`)
}

async function withTimeout(promise, ms, message) {
  let timer
  try { return await Promise.race([promise, new Promise((_, fail) => { timer = setTimeout(() => fail(new Error(message)), ms) })]) } finally { clearTimeout(timer) }
}

// Opens the signer, asks only for the public key, and closes it.
export async function proveJames(uriText, clientText, openSigner = makeBunkerSigner, ms = VERIFY_MS) {
  const signer = openSigner(uriText, clientText, { idleMs: 0, clientSource: 'the NIP-46 client file' })
  try {
    const pubkey = await withTimeout(signer.getPublicKey(), ms, 'the Bunker did not answer get_public_key in time; check the connection is approved in Bunker46, then rerun')
    if (pubkey !== JAMES) throw new Error(`Bunker signer is not James: it answered ${String(pubkey).slice(0, 12)}…, expected ${JAMES.slice(0, 12)}…; check you copied the connection for James's own key`)
    return pubkey
  } finally { try { signer.close?.() } catch {} }
}

export async function run(argv, deps = {}) {
  const opts = options(argv)
  const {
    ask = () => readHidden('Bunker connection for James (bunker://..., not shown)'),
    openSigner = makeBunkerSigner,
    log = line => console.log(line),
    fs = { existsSync, readFileSync, writeExclusive, assertPrivateFile, mkdirSync, renameSync, unlinkSync },
    verifyMs = VERIFY_MS,
  } = deps
  const uriFile = opts['uri-file'], clientFile = opts['client-file']
  for (const dir of new Set([dirname(uriFile), dirname(clientFile)])) fs.mkdirSync(dir, { recursive: true, mode: 0o700 })

  const client = ensureClientFile(clientFile, fs)
  log(`client key: ${client} ${clientFile} (mode 0600, not shown)`)

  const reuseUri = fs.existsSync(uriFile) && !opts['new-uri']
  let uriText, staged
  if (reuseUri) {
    fs.assertPrivateFile(uriFile)
    uriText = checkBunkerUri(fs.readFileSync(uriFile, 'utf8'))
    log(`bunker connection: kept ${uriFile} (pass --new-uri to replace it)`)
  } else {
    uriText = checkBunkerUri(await ask())
    staged = `${uriFile}.new-${process.pid}`
    fs.writeExclusive(staged, `${uriText}\n`)
  }
  const clientText = fs.readFileSync(clientFile, 'utf8').trim()
  try {
    await proveJames(uriText, clientText, openSigner, verifyMs)
    if (staged) { fs.renameSync(staged, uriFile); staged = undefined; log(`bunker connection: stored ${uriFile} (mode 0600, not shown)`) }
  } catch (error) {
    // A library error must never carry either credential to the terminal.
    const message = String(error?.message || error)
    const secret = new URL(uriText).searchParams.get('secret')
    if (message.includes(uriText) || message.includes(clientText) || (secret && message.includes(secret))) throw new Error('the Bunker check failed (details withheld: they quoted a credential)')
    throw error
  } finally {
    if (staged) try { fs.unlinkSync(staged) } catch {}
  }
  uriText = undefined
  log(`signer: James (${JAMES}), read by get_public_key only; nothing was signed.`)
  log('Dry-run first (no signer): node bin/q145-grants.mjs --batch revokes')
  log('Then paste these one at a time, in order, from this checkout:')
  for (const line of pasteLines(uriFile, clientFile)) log(line)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) run(process.argv.slice(2)).catch(error => {
  console.error(`q145-james-signer-setup stopped: ${error?.message || error}`)
  process.exitCode = 1
})
