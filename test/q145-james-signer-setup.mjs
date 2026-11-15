import test from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { options, checkBunkerUri, assertPrivateFile, ensureClientFile, readHidden, pasteLines, proveJames, run, DEFAULT_URI_FILE, DEFAULT_CLIENT_FILE } from '../bin/q145-james-signer-setup.mjs'
import { JAMES } from '../bin/q145-grants.mjs'

const SECRET = 'f00dfeedf00dfeedf00dfeed'
const URI = `bunker://${'e'.repeat(64)}?relay=wss://relay.example&secret=${SECRET}`
const tmp = () => mkdtempSync(join(tmpdir(), 'q145-setup-'))
const signerAs = (pubkey, trace = []) => (uri, client, opts) => {
  trace.push({ uri, client, opts })
  return { getPublicKey: async () => pubkey, close: () => trace.push('closed'), signEvent: () => { throw new Error('must not sign') } }
}
const quiet = () => { const lines = []; return { lines, log: l => lines.push(l) } }

test('options: herd-memory defaults, overrides, and no connection on argv', () => {
  assert.deepEqual(options([]), { 'uri-file': DEFAULT_URI_FILE, 'client-file': DEFAULT_CLIENT_FILE, 'new-uri': false })
  assert.match(DEFAULT_URI_FILE, /\.nvoy-harness\/credentials\/james-bunker-uri$/)
  assert.match(DEFAULT_CLIENT_FILE, /\.nvoy-harness\/credentials\/james-bunker-client$/)
  assert.equal(options(['--uri-file', '/x/u', '--new-uri'])['uri-file'], '/x/u')
  assert.throws(() => options([URI]), error => /never put the Bunker connection on the command line/.test(error.message) && !error.message.includes(SECRET))
  assert.throws(() => options(['--uri-file']), /needs a path/)
  assert.throws(() => options(['--nope']), /unknown option/)
  assert.throws(() => options(['--uri-file', '/a', '--client-file', '/a']), /must differ/)
})

test('checkBunkerUri accepts the signer format and never quotes a bad value', () => {
  assert.equal(checkBunkerUri(`  ${URI}\n`), URI)
  for (const bad of [`nostrconnect://${'e'.repeat(64)}?relay=wss://r`, `bunker://${'e'.repeat(63)}?relay=wss://r&secret=${SECRET}`, `bunker://${'e'.repeat(64)}?relay=ws://r&secret=${SECRET}`, '']) {
    assert.throws(() => checkBunkerUri(bad), error => /nothing stored/.test(error.message) && !error.message.includes(SECRET))
  }
})

test('assertPrivateFile refuses group/other access, links and other owners', () => {
  const dir = tmp(), path = join(dir, 'f')
  writeFileSync(path, 'x', { mode: 0o644 }); chmodSync(path, 0o644)
  assert.throws(() => assertPrivateFile(path), /readable by others/)
  chmodSync(path, 0o600)
  assertPrivateFile(path)
  assert.throws(() => assertPrivateFile(path, { isFile: () => true, uid: 1, mode: 0o100600 }, 2), /not owned by you/)
  assert.throws(() => assertPrivateFile(path, { isFile: () => false, uid: 2, mode: 0o120777 }, 2), /not a regular file/)
})

test('ensureClientFile makes a 0600 64-hex key once and keeps it after', async () => {
  const dir = tmp(), path = join(dir, 'client')
  const { lines, log } = quiet()
  await run(['--uri-file', join(dir, 'uri'), '--client-file', path], { ask: async () => URI, openSigner: signerAs(JAMES), log })
  const key = readFileSync(path, 'utf8').trim()
  assert.match(key, /^[0-9a-f]{64}$/)
  assert.equal(statSync(path).mode & 0o777, 0o600)
  assert.equal(lines.some(l => l.includes(key)), false)
  assert.equal(ensureClientFile(path), 'kept')
  assert.equal(readFileSync(path, 'utf8').trim(), key)
  writeFileSync(path, 'not a key', { mode: 0o600 })
  assert.throws(() => ensureClientFile(path), error => /not a valid/.test(error.message) && !error.message.includes('not a key'))
})

test('run stores the connection 0600 only after the signer answers James, and prints the three lines', async () => {
  const dir = tmp(), uri = join(dir, 'cred', 'uri'), client = join(dir, 'cred', 'client'), trace = []
  const { lines, log } = quiet()
  await run(['--uri-file', uri, '--client-file', client], { ask: async () => `${URI}\n`, openSigner: signerAs(JAMES, trace), log })
  assert.equal(readFileSync(uri, 'utf8'), `${URI}\n`)
  assert.equal(statSync(uri).mode & 0o777, 0o600)
  assert.equal(statSync(join(dir, 'cred')).mode & 0o777, 0o700)
  assert.equal(trace[0].uri, URI)
  assert.equal(trace.at(-1), 'closed')
  assert.equal(lines.some(l => l.includes(SECRET) || l.includes(trace[0].client)), false)
  const paste = lines.filter(l => l.startsWith('node bin/q145-grants.mjs --apply'))
  assert.deepEqual(paste, pasteLines(uri, client))
  assert.deepEqual(paste.map(l => l.split(' ')[4]), ['revokes', 'task', 'mention'])
  assert.ok(paste.every(l => l.includes(`--bunker-uri-file '${uri}' --bunker-client-file '${client}'`)))
  assert.deepEqual(readdirSync(join(dir, 'cred')).sort(), ['client', 'uri'])
})

test('run leaves no connection file when the signer is not James', async () => {
  const dir = tmp(), uri = join(dir, 'uri'), client = join(dir, 'client')
  const { lines, log } = quiet()
  await assert.rejects(() => run(['--uri-file', uri, '--client-file', client], { ask: async () => URI, openSigner: signerAs('a'.repeat(64)), log }), /Bunker signer is not James/)
  assert.equal(existsSync(uri), false)
  assert.deepEqual(readdirSync(dir), ['client'])
  assert.equal(lines.some(l => l.startsWith('node bin/q145-grants.mjs')), false)
})

test('run withholds an error that quotes a credential, and times out a silent Bunker', async () => {
  const dir = tmp(), uri = join(dir, 'uri'), client = join(dir, 'client')
  const leaky = () => ({ getPublicKey: async () => { throw new Error(`relay said ${SECRET}`) }, close() {} })
  await assert.rejects(() => run(['--uri-file', uri, '--client-file', client], { ask: async () => URI, openSigner: leaky, log() {} }), error => /details withheld/.test(error.message) && !error.message.includes(SECRET))
  const silent = () => ({ getPublicKey: () => new Promise(() => {}), close() {} })
  await assert.rejects(() => proveJames(URI, 'c'.repeat(64), silent, 20), /did not answer get_public_key in time/)
  assert.equal(existsSync(uri), false)
})

test('run keeps an existing connection unless --new-uri, and refuses a loose one', async () => {
  const dir = tmp(), uri = join(dir, 'uri'), client = join(dir, 'client')
  writeFileSync(uri, `${URI}\n`, { mode: 0o600 })
  let asked = 0
  await run(['--uri-file', uri, '--client-file', client], { ask: async () => { asked++; return URI }, openSigner: signerAs(JAMES), log() {} })
  assert.equal(asked, 0)
  const other = URI.replace(SECRET, 'beef')
  await run(['--uri-file', uri, '--client-file', client, '--new-uri'], { ask: async () => { asked++; return other }, openSigner: signerAs(JAMES), log() {} })
  assert.equal(asked, 1)
  assert.equal(readFileSync(uri, 'utf8'), `${other}\n`)
  chmodSync(uri, 0o640)
  await assert.rejects(() => run(['--uri-file', uri, '--client-file', client], { ask: async () => URI, openSigner: signerAs(JAMES), log() {} }), /readable by others/)
})

test('readHidden: no echo from a terminal, one line from a pipe, Ctrl-C stops', async () => {
  const tty = () => { const input = new PassThrough(); input.isTTY = true; input.modes = []; input.setRawMode = m => input.modes.push(m); return input }
  const out = new PassThrough(); let shown = ''; out.on('data', d => { shown += d })
  const input = tty()
  const answer = readHidden('Bunker connection', input, out)
  input.write('bunker://ab'); input.write('x\u007f'); input.write('cd\r')
  assert.equal(await answer, 'bunker://abcd')
  assert.deepEqual(input.modes, [true, false])
  assert.equal(shown.includes('bunker://'), false)
  const stop = tty(), stopped = readHidden('p', stop, new PassThrough())
  stop.write('bunker://\u0003')
  await assert.rejects(stopped, /stopped at the prompt; nothing stored/)
  const pipe = new PassThrough()
  const piped = readHidden('p', pipe, new PassThrough())
  pipe.end(`${URI}\nsecond line\n`)
  assert.equal(await piped, URI)
})

test('pasteLines quotes paths with spaces and quotes', () => {
  const [line] = pasteLines("/Users/j a/it's/uri", '/c')
  assert.ok(line.endsWith(`--bunker-uri-file '/Users/j a/it'\\''s/uri' --bunker-client-file '/c'`))
})
