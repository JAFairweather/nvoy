// outbound_secrets.mjs — what an agent may never post, whoever asked it to.
//
// An agent can read more than it should (a Codex sandbox reads every file its user can), and a
// grant holder, or text it reads, can ask it to repeat what it read. So every outbound path
// refuses a post that carries a credential: the keyless tools say so at once, and the brokers,
// which hold the signer, refuse again, so a client that skips the tool cannot skip the check.
//
// The whole post is refused, never redacted and sent: a partial secret is still a leak, and an
// agent told why can rewrite. Nothing here returns or logs the matched text — only the pattern's
// name and a hash of the whole post, for correlation.
//
// Agents post 64-hex event ids and pubkeys, npubs and URLs as a matter of course, so none of
// those match. The entropy rule only looks at mixed-case runs (bech32 and hex are single-case)
// outside URLs (document ids in links are long and random too); a secret placed in a URL is
// caught by its parameter name instead. This is a brake on accidents and on the obvious ask; an
// agent determined to encode a secret can still do it, so it is not a substitute for not letting
// the agent read the secret in the first place.

import { createHash } from 'node:crypto'

const BECH32 = '[02-9ac-hj-np-z]'

export const CREDENTIAL_PATTERNS = Object.freeze([
  ['a Nostr secret key', new RegExp(`(?<![a-z0-9])nsec1${BECH32}{50,}`, 'i')],
  ['an encrypted Nostr key', new RegExp(`(?<![a-z0-9])ncryptsec1${BECH32}{50,}`, 'i')],
  ['a bunker URI', /bunker:\/\/[^\s'"<>]{8,}/i],
  ['a nostrconnect URI with a secret', /nostrconnect:\/\/[^\s'"<>]*[?&]secret=/i],
  ['a private key block', /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/],
  ['a GitHub token', /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/],
  ['an Anthropic key', /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/],
  ['an OpenAI-style key', /(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/],
  ['an AWS access key', /(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])/],
  ['a Google API key', /(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}/],
  ['a Slack token', /(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}/],
  ['a JSON web token', /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/],
  ['a secret in a URL', /[?&](?:secret|token|access_token|api_key|apikey|key|password|client_secret)=[^\s&#'"<>]{12,}/i],
])

const INVISIBLE = /[\u00ad\u200b-\u200f\u2060-\u2064\ufeff]/g
const URL_RE = /\bhttps?:\/\/[^\s'"<>]+/gi
const RUN = /[A-Za-z0-9+_=-]{32,}/g

const entropy = s => {
  const counts = new Map()
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1)
  let bits = 0
  for (const n of counts.values()) bits -= (n / s.length) * Math.log2(n / s.length)
  return bits
}
const looksRandom = run => /[a-z]/.test(run) && /[A-Z]/.test(run) && /[0-9]/.test(run) && entropy(run) >= 4.5

// The name of the first credential pattern the text matches, or null. Never the matched text.
export function credentialIn(text) {
  const s = String(text ?? '').normalize('NFKC').replace(INVISIBLE, '')
  for (const [name, re] of CREDENTIAL_PATTERNS) if (re.test(s)) return name
  for (const run of s.replace(URL_RE, ' ').match(RUN) || []) if (looksRandom(run)) return 'a long random string'
  return null
}

export const contentHash = text => createHash('sha256').update(String(text ?? ''), 'utf8').digest('hex').slice(0, 12)

export const withheldMessage = name => `withheld: looks like a credential (${name}); nothing was posted — rewrite it without the secret`

// The tool answer and the log line for one refusal. Neither carries the text.
export function withheld({ instance, path, name, text }) {
  const message = withheldMessage(name)
  return {
    error: { code: 'NVOY_WITHHELD_CREDENTIAL', message },
    log: `${path}: ${instance} ${message} [post sha256 ${contentHash(text)}]`,
  }
}
