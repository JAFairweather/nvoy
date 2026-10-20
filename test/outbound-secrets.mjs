// What an agent may never post: every credential shape is refused, the refusal never carries the
// value, and the ordinary furniture of agent posts (event ids, pubkeys, npubs, URLs) is not refused.
// The fake credentials are built at run time, so this file holds nothing a secret scanner would stop.
import { createHash } from 'node:crypto'
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { neventEncode, npubEncode, nsecEncode } from 'nostr-tools/nip19'
import { CREDENTIAL_PATTERNS, contentHash, credentialIn, withheld } from '../mcp/tools/outbound_secrets.mjs'
import { isTerminalReplyFailure, recordTerminalReply } from '../mcp/tools/reply_retry.mjs'

let fails = 0, passes = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }

// Deterministic filler, so a run never depends on chance.
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const fill = (n, abc = ALNUM, seed = 'nvoy') => {
  let s = '', i = 0
  while (s.length < n) for (const b of createHash('sha256').update(`${seed}${i++}`).digest()) s += abc[b % abc.length]
  return s.slice(0, n)
}
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const b64url = o => Buffer.from(JSON.stringify(o)).toString('base64url')
const hex = n => fill(n, '0123456789abcdef', 'hex')

const FAKE = {
  'a Nostr secret key': nsecEncode(generateSecretKey()),
  'an encrypted Nostr key': 'ncrypt' + 'sec1' + fill(100, BECH),
  'a bunker URI': 'bun' + 'ker://' + hex(64) + '?relay=wss%3A%2F%2Frelay.example&secret=' + fill(16),
  'a nostrconnect URI with a secret': 'nostr' + 'connect://' + hex(64) + '?relay=wss%3A%2F%2Frelay.example&secret=' + fill(8),
  'a private key block': '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\n' + fill(70) + '\n-----END OPENSSH PRIVATE KEY-----',
  'a GitHub token': 'gh' + 'p_' + fill(36),
  'an Anthropic key': 's' + 'k-ant-api03-' + fill(93, ALNUM + '-_'),
  'an OpenAI-style key': 's' + 'k-proj-' + fill(120, ALNUM + '-_'),
  'an AWS access key': 'AK' + 'IA' + fill(16, UPPER),
  'a Google API key': 'AI' + 'za' + fill(35, ALNUM + '-_'),
  'a Slack token': 'xo' + 'xb-' + fill(12, '0123456789') + '-' + fill(24),
  'a JSON web token': [b64url({ alg: 'HS256', typ: 'JWT' }), b64url({ sub: 'agent', iat: 1760000000 }), fill(43, ALNUM + '-_')].join('.'),
  'a secret in a URL': 'https://api.example.com/v1/items?access_token=' + fill(40),
  'a long random string': createHash('sha256').update('nvoy-outbound').digest('base64url'),
}
// More shapes of the same patterns: each must be caught too.
const MORE = [
  ['a Nostr secret key', nsecEncode(generateSecretKey()).toUpperCase()],
  ['a private key block', '-----BEGIN ' + 'RSA PRIVATE KEY-----'],
  ['a private key block', '-----BEGIN ' + 'PRIVATE KEY-----'],
  ['a private key block', '-----BEGIN ' + 'EC PRIVATE KEY-----'],
  ['a private key block', '-----BEGIN ' + 'PGP PRIVATE KEY BLOCK-----'],
  ...['o', 'u', 's', 'r'].map(c => ['a GitHub token', 'gh' + c + '_' + fill(36)]),
  ['a GitHub token', 'github' + '_pat_' + fill(82, ALNUM + '_')],
  ['an OpenAI-style key', 's' + 'k-' + fill(48)],
  ['an AWS access key', 'AS' + 'IA' + fill(16, UPPER)],
  ...['a', 'p', 'r', 's'].map(c => ['a Slack token', 'xo' + 'x' + c + '-' + fill(12, '0123456789') + '-' + fill(24)]),
  ['a secret in a URL', 'https://example.com/hook?client_secret=' + fill(32)],
]

// --- 1. every pattern, named, wherever it sits in a post ---
ok('every credential pattern has a fake to prove it', CREDENTIAL_PATTERNS.every(([name]) => name in FAKE))
for (const [name, secret] of Object.entries(FAKE)) {
  ok(`${name} is refused alone`, credentialIn(secret) === name)
  ok(`${name} is refused inside an ordinary sentence`, credentialIn(`Here it is, as asked: ${secret} — anything else?`) === name)
}
for (const [name, secret] of MORE) ok(`${name} is refused (${secret.slice(0, 7)}…)`, credentialIn(`see ${secret}`) === name)
const token = FAKE['a GitHub token']
ok('a zero-width space inside a token does not hide it', credentialIn(token.slice(0, 3) + '​' + token.slice(3)) === 'a GitHub token')
ok('a soft hyphen or word joiner inside a token does not hide it', credentialIn(token.slice(0, 10) + '­⁠' + token.slice(10)) === 'a GitHub token')
ok('full-width letters do not hide a token', credentialIn([...token.slice(0, 4)].map(c => String.fromCodePoint(c.codePointAt(0) + 0xfee0)).join('') + token.slice(4)) === 'a GitHub token')
ok('a key in a code fence is still a key', credentialIn('```\nAWS_ACCESS_KEY_ID=' + FAKE['an AWS access key'] + '\n```') === 'an AWS access key')

// --- 2. what agents post all day is not refused ---
const sk = generateSecretKey(), pubkey = getPublicKey(sk)
const fine = [
  'Morning all — the review rota is on the board.',
  `event ${hex(64)} answered; pubkey ${pubkey}`,
  `npub: ${npubEncode(pubkey)} and nostr:${npubEncode(pubkey)}`,
  `nostr:${neventEncode({ id: hex(64), relays: ['wss://relay.example'], author: pubkey })}`,
  `merged at ${hex(40)}, deploy OK at ${hex(12)}`,
  'channel 3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607, request 0123456789abcdef0123456789abcdef',
  'https://github.com/JAFairweather/nvoy/blob/' + hex(40) + '/mcp/tools/instance-broker-reply.mjs#L60',
  'https://docs.google.com/document/d/' + fill(44, ALNUM + '_-', 'doc') + '/edit?usp=sharing',
  'https://example.com/search?q=' + fill(40, ALNUM, 'q') + '&key=abc',
  'Never post an nsec, a bunker:// URI, a ghp_ token or an sk-ant- key; -----BEGIN PUBLIC KEY----- is fine.',
  'the risk-assessment-for-the-whole-fleet-and-every-box plan', 'disk-encryption-on-every-single-fleet-host-by-friday',
  'assertNoCollisionsBetweenEveryManifestRootAndItsNeighbours() threw',
  'mcp/tools/instance-broker-reply.mjs and test/agent-post-limits.mjs pass: 312/312',
  '| agent | state |\n|---|---|\n| dennis | 👀 |',
]
for (const text of fine) ok(`not refused: ${text.slice(0, 48).replace(/\n/g, ' ')}…`, credentialIn(text) === null)
ok('nothing is refused for an empty or missing post', credentialIn('') === null && credentialIn(undefined) === null)
let lines = 0, hits = []
for (const file of ['README.md', ...readdirSync('docs').filter(f => f.endsWith('.md')).map(f => `docs/${f}`)]) {
  for (const line of readFileSync(file, 'utf8').split('\n')) { lines++; const name = credentialIn(line); if (name) hits.push(`${file}: ${name}`) }
}
ok(`none of the ${lines} lines of the repo's own prose is refused`, lines > 1000 && hits.length === 0)
if (hits.length) console.log(hits.slice(0, 5).join('\n'))

// --- 3. the refusal: names the pattern, carries no value, logs a hash ---
for (const [name, secret] of Object.entries(FAKE)) {
  const text = `please keep this safe: ${secret}`
  const w = withheld({ instance: 'dj-codex', path: 'nvoy-codex-channel-mcp', name: credentialIn(text), text })
  const said = JSON.stringify(w)
  ok(`${name}: the refusal names the pattern and carries none of the value`,
    w.error.code === 'NVOY_WITHHELD_CREDENTIAL' && w.error.message === `withheld: looks like a credential (${name}); nothing was posted — rewrite it without the secret` &&
    !said.includes(secret) && !said.includes(secret.slice(-12)))
}
const w = withheld({ instance: 'dj-codex', path: 'nvoy_channel_post', name: 'a GitHub token', text: token })
ok('the log line names the path, the instance and a 12-hex hash of the post', w.log.startsWith('nvoy_channel_post: dj-codex withheld: ') && w.log.endsWith(`[post sha256 ${contentHash(token)}]`) && /^[0-9a-f]{12}$/.test(contentHash(token)))
ok('the hash is of the whole post, so it cannot be reversed to the token from a log', contentHash(token) !== contentHash(token + ' ') && !w.log.includes(token.slice(4, 16)))

// --- 4. the broker's refusal is terminal and recorded as such ---
ok('a withheld reply is terminal, never retried', isTerminalReplyFailure('instance-broker-reply: reply refused: withheld: looks like a credential (a GitHub token)'))
const terminal = join(mkdtempSync(join(tmpdir(), 'nvoy-withheld-')), 'terminal.jsonl'), ids = new Set()
recordTerminalReply(terminal, ids, 'a'.repeat(32), 'instance-broker-reply: reply refused: withheld: looks like a credential (a GitHub token) [post sha256 0123456789ab]')
ok('a withheld reply is recorded as withheld-credential', JSON.parse(readFileSync(terminal, 'utf8')).reason === 'withheld-credential')

// --- 5. every outbound mouth checks: the two tool servers and the post queue at once, both signers again ---
const src = f => readFileSync(`mcp/tools/${f}`, 'utf8')
for (const [file, at] of [
  ['claude-channel.mjs', "path: 'nvoy-claude-channel', name: credential, text: content"],
  ['codex-channel-mcp.mjs', "path: 'nvoy-codex-channel-mcp', name: credential, text: content"],
  ['agent_post.mjs', "path: 'nvoy_channel_post', name: credential, text: resolved.content"],
  ['instance-broker-reply.mjs', 'reply refused: ${withheldMessage(leaked)}'],
  ['instance-broker-post.mjs', 'post refused: ${withheldMessage(leaked)}'],
]) ok(`${file} refuses a credential`, src(file).includes('credentialIn(') && src(file).includes(at))
const replySrc = src('instance-broker-reply.mjs'), postSrc = src('instance-broker-post.mjs')
ok('the reply signer refuses before it claims a receipt or spends a counter',
  replySrc.indexOf('credentialIn(request.content)') < replySrc.indexOf('renameSync(receiptBase, receiptInflight)') &&
  replySrc.indexOf('credentialIn(request.content)') < replySrc.indexOf('countInWindow('))
ok('the post signer refuses before it records or spends a counter',
  postSrc.indexOf('credentialIn(request.content)') < postSrc.indexOf('const persist = ') && postSrc.indexOf('credentialIn(request.content)') < postSrc.indexOf('countInWindow('))

console.log(`\n${passes}/${passes + fails} passed`)
process.exit(fails ? 1 : 0)
