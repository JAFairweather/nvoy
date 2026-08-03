// consent-request.mjs — parser/guard for waggle's public mirror-consent link.
//
// The link carries an UNSIGNED, public 440 draft in its fragment.  Nothing in
// it is a credential; the participant's NIP-07/NIP-46 signer creates the only
// authority.  Keep this module DOM-free so malformed links are testable.

const hex = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/i.test(v)
const text = (v, name, max = 256) => {
  if (typeof v !== 'string' || !v.trim() || v.length > max || /[\r\n`]/.test(v)) throw new Error(`invalid ${name}`)
  return v.trim()
}
const tag = (tags, name) => tags.find(t => t[0] === name)

export function consentTerms({ hiveId, hiveName, hiveHandle, termsUrl }) {
  const id = hex(hiveId) ? hiveId.toLowerCase() : (() => { throw new Error('invalid hive id') })()
  const name = text(hiveName, 'hive name', 64)
  const handle = text(hiveHandle, 'hive handle', 128)
  const url = new URL(text(termsUrl, 'terms URL', 2048))
  if (!['https:', 'http:'].includes(url.protocol)) throw new Error('invalid terms URL')
  return [
    '**waggle — mirror consent (v1)**', '',
    `Hello from waggle. ${name}'s hive (${handle}) would love to share your public wisdom in its meadow — with the bees already in the hive. Nothing crosses unless you say yes.`, '',
    `1. **What happens.** Your public Nostr content would be reposted into ${name} (${handle}) — a private, invite-walled Buzz hive you are not a member of.`,
    `2. **Who sees it.** Only members of ${name}, inside their space, under that hive's own terms (${url}).`,
    `3. **How it's posted, honestly.** Today the mirror reposts your content under the bridge's own key, attributed to you — not as your own signed event. Until that limitation is fixed, moderation and the platform's content license attach to the operator's copy, not to you.`,
    `4. **Your public self is untouched.** Your notes stay yours on the open network. This covers only the mirrored copy inside ${name}; it does not change, claim, or move your originals.`,
    '5. **You can stop it anytime.** Revoke and no new content crosses — a `441`, or ask the operator / use the console. Content already seen can\'t be un-seen; that\'s physics, not a permission you\'re giving.', '',
    `**The boundary.** Your consent is for this one hive, not for one chat channel: \`community_id:${id}\`. The director may route a consented feed to one or more channels inside this hive; moving it between those channels does not widen your consent.`, '',
    '**To agree:** return a signed `440` naming waggle, capability `mirror`, scoped to this hive, carrying the hash of these terms. **To decline:** ignore this — silence is a no, and you won\'t be asked again. An explicit no is honored permanently.', '',
    'Nothing of yours crosses until you say yes.',
  ].join('\n')
}

export function encodeConsentRequest(request) {
  return btoa(unescape(encodeURIComponent(JSON.stringify(request))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodeConsentRequest(fragment) {
  const raw = String(fragment || '').replace(/^#/, '')
  const value = new URLSearchParams(raw).get('request')
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 12000) throw new Error('missing or malformed consent request')
  try {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4)
    return JSON.parse(decodeURIComponent(escape(atob(base64))))
  } catch { throw new Error('consent request could not be decoded') }
}

/** Validate the exact, deliberately narrow event a participant is invited to sign. */
export function validateConsentRequest(request) {
  if (!request || typeof request !== 'object') throw new Error('invalid consent request')
  const terms = consentTerms(request)
  const ev = request.prefill
  if (!ev || typeof ev !== 'object' || ev.kind !== 440 || typeof ev.created_at !== 'number' || ev.content !== '') throw new Error('not an unsigned mirror-consent 440')
  if ('id' in ev || 'pubkey' in ev || 'sig' in ev) throw new Error('consent draft must be unsigned')
  if (!Array.isArray(ev.tags) || ev.tags.length !== 4) throw new Error('consent draft has unexpected tags')
  const allowed = new Set(['p', 'da-scope', 'da-cap', 'tos'])
  if (ev.tags.some(t => !Array.isArray(t) || !allowed.has(t[0])) || new Set(ev.tags.map(t => t[0])).size !== 4) throw new Error('consent draft has unexpected tags')
  const p = tag(ev.tags, 'p')?.[1]
  const scope = tag(ev.tags, 'da-scope')
  const cap = tag(ev.tags, 'da-cap')?.[1]
  const tos = tag(ev.tags, 'tos')?.[1]
  if (!hex(p) || !scope || !hex(scope[1]) || !/^[0-9a-f]{32}$/i.test(scope[2] || '') || cap !== 'mirror' || !hex(tos)) throw new Error('consent draft is incomplete')
  return { prefill: { kind: 440, created_at: Math.floor(ev.created_at), tags: ev.tags.map(t => [...t]), content: '' }, terms, hive: { id: request.hiveId.toLowerCase(), name: request.hiveName.trim(), handle: request.hiveHandle.trim(), termsUrl: request.termsUrl.trim() }, tos: tos.toLowerCase(), bridge: p.toLowerCase() }
}

export async function termsHash(terms) {
  const bytes = new TextEncoder().encode(terms)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}
