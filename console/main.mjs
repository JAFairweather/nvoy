// main.mjs — Nvoy console shell: sign-in via nave-connect (NIP-07 extension
// or NIP-46 bunker as the front door; the local key with its NIP-49 protect
// offer stays as a gated advanced path), tabs, shared state. agents.mjs =
// registry, delegate.mjs = scope authoring + issuance, ledger.mjs = the audit
// view. Pure NIP-DA client plus the payload-level nvoy terms extension (§4).

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import * as nip49 from 'nostr-tools/nip49'
import { LiveRelay } from '../lib/liverelay.mjs'
import { localSigner, loadGrantIndex, latestGrants } from '../lib/nipxx.mjs'
import { nip07Signer, nip46Signer, serializeSession, parseSession, signerFromSession } from '../lib/nave-connect.mjs'
import { renderTitlebar, updateTitlebar } from '../lib/nave-titlebar.mjs'
import { loadConfig } from './config.mjs'
import { deriveDelegations } from './ledgerlog.mjs'
import { receiveGrantsWithTerms, receiveNotices } from './nvoygrant.mjs'
import { expiryRotationPlan, nextExpiry, runExpiryRotation, relinquishPlan, runRelinquishRotation } from './ttl.mjs'
import { renderAgents } from './agents.mjs'
import { renderDelegate } from './delegate.mjs'
import { renderLedger } from './ledger.mjs'
import { renderSettings } from './settings.mjs'

export const config = loadConfig()
export const RELAYS = config.relays

export const $ = (id) => document.getElementById(id)
export const esc = (s) => String(s).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
export const short = (pk) => { const n = nip19.npubEncode(pk); return n.slice(0, 12) + '…' + n.slice(-4) }
export const fmtWhen = (sec) => new Date(sec * 1000).toISOString().slice(0, 16).replace('T', ' ')

export const state = {
  relay: null, signer: null, me: null,
  index: { issued: [], received: [] },   // the Grant Index — the whole record
  delegations: [],                       // derived rows: deriveDelegations(index)
  profiles: new Map(),                   // pubkey → kind-0 metadata
  received: [],                          // grants TO me (agent outboxes, §6.5)
  requests: [],                          // pending access requests (§6.2)
  pendingRelinquish: [],                 // relinquish notices awaiting one-tap confirm (§6.6)
}

export const agentsOf = () => state.index.nvoy_agents ?? []
export const agentName = (pk) =>
  state.profiles.get(pk)?.display_name || state.profiles.get(pk)?.name || short(pk)

function parseKey(input) {
  const s = input.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return Uint8Array.from(s.match(/../g), h => parseInt(h, 16))
  const { type, data } = nip19.decode(s)
  if (type !== 'nsec') throw new Error('not an nsec')
  return data
}

/** Accept npub1… or 64-char hex; return hex pubkey. */
export function parsePub(input) {
  const s = input.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase()
  const { type, data } = nip19.decode(s)
  if (type !== 'npub') throw new Error('not an npub')
  return data
}

const TABS = { agents: renderAgents, delegate: renderDelegate, ledger: renderLedger, settings: renderSettings }
let current = 'agents'
export function showTab(t) {
  current = t
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('active', b.dataset.tab === t)
  for (const id of Object.keys(TABS)) $(id).style.display = t === id ? '' : 'none'
  TABS[t]()
  location.hash = t
}
for (const b of document.querySelectorAll('.tab')) b.onclick = () => showTab(b.dataset.tab)
export const rerender = () => TABS[current]()

export async function login(signer, remember) {
  state.signer = signer
  try { state.me = await signer.getPublicKey() }   // nip46: first use → lazy bunker connect
  catch (err) {
    state.signer = null
    try { await signer.close?.() } catch { /* best effort */ }
    $('err').textContent = `sign-in failed: ${err.message}`
    return
  }
  if (remember) sessionStorage.setItem('nvoy-login', remember)
  state.relay ??= new LiveRelay(RELAYS)
  $('login').style.display = 'none'
  $('unlock').style.display = 'none'
  $('tabs').style.display = 'flex'
  updateTitlebar('#titlebar', {
    npub: nip19.npubEncode(state.me), kind: signer.kind,
    onRefresh: () => load(), onLogout: logout,
  })
  showTab(Object.keys(TABS).includes(location.hash.slice(1)) ? location.hash.slice(1) : 'agents')
  if (remember && parseSession(remember)?.kind === 'local') offerProtect(remember)
  load()
}

// --- NIP-49: passphrase-protected key at rest (Nvelope pattern) --------------
// The ncryptsec in localStorage is the ONLY persisted secret. NIP-07 keys
// never touch us; unprotected local keys live in sessionStorage for the tab
// session only until the user takes the protect offer.

const NC_KEY = 'nvoy-ncryptsec'

function offerProtect(hex) {
  if (localStorage.getItem(NC_KEY) || sessionStorage.getItem('nvoy-no-protect')) return
  $('protect').style.display = 'flex'
  $('protect-go').onclick = async () => {
    const pass = $('protect-pass').value
    if (pass.length < 8) { $('protect-msg').textContent = 'use at least 8 characters'; return }
    $('protect-msg').textContent = 'encrypting key (scrypt — a second or two)…'
    await new Promise(r => setTimeout(r, 30))                // let the message paint
    const sk = Uint8Array.from(hex.match(/../g), h => parseInt(h, 16))
    localStorage.setItem(NC_KEY, nip49.encrypt(sk, pass))
    sessionStorage.removeItem('nvoy-login')                  // ncryptsec replaces it
    $('protect-pass').value = ''
    $('protect').style.display = 'none'
    $('status').textContent = 'Key protected. Next visit asks for the passphrase; the nsec still works anywhere.'
  }
  $('protect-pass').onkeydown = (e) => { if (e.key === 'Enter') $('protect-go').onclick() }
  $('protect-skip').onclick = () => {
    sessionStorage.setItem('nvoy-no-protect', '1')
    $('protect').style.display = 'none'
  }
}

function showUnlock(ncryptsec) {
  $('login').style.display = 'none'
  $('unlock').style.display = ''
  $('unlock-pass').focus()
  $('unlock-go').onclick = async () => {
    $('unlock-err').textContent = 'decrypting (scrypt — a second or two)…'
    await new Promise(r => setTimeout(r, 30))
    try {
      const sk = nip49.decrypt(ncryptsec, $('unlock-pass').value)
      $('unlock-pass').value = ''
      login(keySigner(sk), null)                             // nothing new persisted
    } catch { $('unlock-err').textContent = 'wrong passphrase' }
  }
  $('unlock-pass').onkeydown = (e) => { if (e.key === 'Enter') $('unlock-go').onclick() }
  $('unlock-forget').onclick = () => {
    if (!confirm('Forget the protected key stored on this device?\n\nThis deletes the only local copy — make sure the nsec is written down; it is the only way back into this account.')) return
    localStorage.removeItem(NC_KEY)
    $('unlock').style.display = 'none'
    $('login').style.display = ''
  }
}

// --- dismissed access requests: a local-only judgment (deny = "not now"),
// deliberately NOT in the Grant Index — nothing was granted or revoked.
const DISMISS_KEY = 'nvoy-dismissed-requests'
const dismissedIds = () => { try { return JSON.parse(localStorage.getItem(DISMISS_KEY)) ?? [] } catch { return [] } }
export function dismissRequest(id) {
  localStorage.setItem(DISMISS_KEY, JSON.stringify([...dismissedIds(), id].slice(-300)))
  state.requests = state.requests.filter(r => r.id !== id)
}

// --- TTL scheduler (§6.4.3): sweep overdue expiries, then arm a timer for
// the next deadline while the console stays open. Honesty: this is
// client-side cron — the ledger banner says so.
let ttlTimer = null
async function sweepExpiries() {
  let rotated = 0
  for (const item of expiryRotationPlan(state.index)) {
    try {
      await runExpiryRotation(state.relay, state.signer, state.index, item, { relayHint: RELAYS[0] })
      rotated++
    } catch (err) { console.warn(`TTL rotation of ${item.scope} skipped: ${err.message}`) }
  }
  return rotated
}
function armTtlTimer() {
  clearTimeout(ttlTimer)
  const next = nextExpiry(state.index)
  if (next === null) return
  const ms = (next - Math.floor(Date.now() / 1000)) * 1000 + 1500
  if (ms > 2 ** 31 - 1) return // > ~24 days out; every load() re-arms anyway
  ttlTimer = setTimeout(() => { load() }, Math.max(ms, 1000))
}

/** Reload everything from the Grant Index — the single authoritative record.
 *  Agents, delegations, and history all derive from it; kind-0 profiles are
 *  presentation only, fetched fresh per load. Also the scheduler beat: every
 *  load sweeps overdue TTLs, applies the relinquish policy (decision 6), and
 *  re-arms the expiry timer. */
export async function load() {
  const { relay, signer } = state
  $('status').textContent = 'loading your Grant Index from relays…'
  try {
    state.index = await loadGrantIndex(relay, signer)

    // hard expiry (§6.4.3): rotate anything already past deadline, arm the rest
    const expired = await sweepExpiries()
    armTtlTimer()

    // inbound gift wraps: agent outboxes (§6.5) + notices (§6.2, §6.6)
    const [grants, notices] = await Promise.all([
      receiveGrantsWithTerms(relay, signer).catch(() => []),
      receiveNotices(relay, signer).catch(() => ({ accessRequests: [], relinquishes: [] })),
    ])
    state.received = latestGrants(grants)
    const dismissed = new Set(dismissedIds())
    state.requests = notices.accessRequests.filter(r => !dismissed.has(r.id))

    // relinquish policy (§6.6, decision 6): sole grantee → rotate NOW;
    // otherwise queue the one-tap confirm on the ledger card
    const plan = relinquishPlan(state.index, notices.relinquishes)
    for (const item of plan.auto) {
      try { await runRelinquishRotation(relay, signer, state.index, item, { relayHint: RELAYS[0] }) }
      catch (err) { console.warn(`relinquish rotation of ${item.scope} skipped: ${err.message}`) }
    }
    state.pendingRelinquish = plan.confirm

    state.delegations = deriveDelegations(state.index)
    const pubs = [...new Set([
      ...agentsOf().map(a => a.pub),
      ...state.delegations.map(d => d.agent),
      ...state.requests.map(r => r.from),
    ])]
    state.profiles = new Map()
    if (pubs.length)
      for (const ev of await relay.query({ kinds: [0], authors: pubs, limit: pubs.length * 3 }))
        if (!state.profiles.has(ev.pubkey)) {
          try { state.profiles.set(ev.pubkey, JSON.parse(ev.content)) } catch { /* skip */ }
        }
    const active = state.delegations.filter(d => d.status === 'active').length
    $('status').textContent =
      `${agentsOf().length} agent${agentsOf().length === 1 ? '' : 's'} · ` +
      `${active} active delegation${active === 1 ? '' : 's'}` +
      (state.requests.length ? ` · ${state.requests.length} pending access request${state.requests.length === 1 ? '' : 's'}` : '') +
      (state.pendingRelinquish.length ? ` · ${state.pendingRelinquish.length} relinquish to confirm` : '') +
      (expired ? ` · ${expired} expired scope${expired === 1 ? '' : 's'} rotated` : '') +
      `. Everything below derives from your encrypted Grant Index — sign in with this key anywhere and it reconstitutes.`
    rerender()
  } catch (err) { $('status').textContent = `relay error: ${err.message}` }
}

/** Print a paper recovery card: the nsec IS the account, and paper survives
 *  dead laptops. @media print CSS hides everything but the card. */
export function printKey(sk) {
  const nsec = nip19.nsecEncode(sk)
  const npub = nip19.npubEncode(getPublicKey(sk))
  $('printcard').innerHTML = `
    <h1>Nvoy recovery key</h1>
    <p>This key is the whole account — there is no reset and no server copy.
       Sign in with the secret key on any device and the console reconstitutes:
       your agents, every delegation, the full ledger.</p>
    <div class="lbl">Secret key — keep this on paper, never in email or chat</div>
    <div class="k">${esc(nsec)}</div>
    <div class="lbl">Public key — safe to give out</div>
    <div class="k">${esc(npub)}</div>
    <div class="foot">Printed ${new Date().toISOString().slice(0, 10)} ·
      nvoy — scoped, revocable data delegation to agents</div>`
  window.print()
  $('printcard').innerHTML = ''            // the key does not linger in the DOM
}

const hexOf = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')

// nave-connect supplies nip07 + nip46; local keys stay on nipxx's localSigner.
// (The module's own localSigner has no nip44, and the Grant Index is NIP-44
// encrypted to self — signerFromSession returning null for `local` is the
// module telling the app to rebuild from its own key material.)
function keySigner(sk) { return { kind: 'local', ...localSigner(sk) } }

// NIP-46: the bunker may want a one-time interactive approval — surface its
// auth_url as a link rather than window.open (popup blockers eat those).
function onAuthUrl(url) {
  $('bunker-auth').style.display = ''
  $('bunker-auth').innerHTML = `The bunker asks for a one-time approval:
    <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">open its dashboard</a>,
    approve, then return here.`
}

$('bunker-go').onclick = async () => {
  const uri = $('bunker-uri').value.trim()
  if (!uri) { $('err').textContent = 'Paste the bunker:// URI from your remote signer first.'; return }
  $('err').textContent = 'connecting to the bunker over its relays… (approve there if asked)'
  $('bunker-go').disabled = true
  try {
    const signer = nip46Signer(uri, { onAuthUrl })
    await login(signer, serializeSession('nip46', { uri, clientSecretHex: signer.clientSecretHex }))
    if (state.me) { $('err').textContent = ''; $('bunker-auth').style.display = 'none' }
  } finally { $('bunker-go').disabled = false }
}
$('bunker-uri').onkeydown = (e) => { if (e.key === 'Enter') $('bunker-go').onclick() }

// The local key is deliberately not a headline option (Director, nact#16):
// it stays available, behind this explicit reveal.
$('advanced-toggle').onclick = () => {
  const open = $('advanced').style.display === 'none'
  $('advanced').style.display = open ? '' : 'none'
  $('advanced-toggle').textContent = open
    ? 'Hide the local-key option'
    : 'Advanced: use a local key in this tab (demo / recovery)'
  if (open) $('nsec').focus()
}

$('go').onclick = () => {
  try { const k = parseKey($('nsec').value); login(keySigner(k), hexOf(k)) }
  catch { $('err').textContent = 'Expected nsec1… or 64 hex chars.' }
}
$('nsec').onkeydown = (e) => { if (e.key === 'Enter') $('go').onclick() }
$('gen').onclick = () => {
  // The key is shown in-page (selectable, with a Copy button) — an alert()
  // can't be copied, and this key is the only way back in.
  const k = generateSecretKey()
  $('err').textContent = ''
  $('newkey').style.display = ''
  $('newkey-nsec').textContent = nip19.nsecEncode(k)
  $('newkey-copy').onclick = async () => {
    await navigator.clipboard.writeText(nip19.nsecEncode(k))
    $('newkey-copy').textContent = 'Copied ✓'
    setTimeout(() => { $('newkey-copy').textContent = 'Copy' }, 2000)
  }
  $('newkey-print').onclick = () => printKey(k)
  $('newkey-continue').onclick = () => login(keySigner(k), hexOf(k))
}
$('nip07').onclick = () => {
  if (!window.nostr?.nip44) { $('err').textContent = 'No NIP-07 extension found (needs nip44 support — Alby or nos2x).'; return }
  login(nip07Signer(), 'nip07')
}
function logout() {
  try { state.signer?.close?.() } catch { /* best effort */ }   // drop a live bunker pairing
  sessionStorage.removeItem('nvoy-login'); location.hash = ''; location.reload()
}

// The unified Nave title bar (nact#16): boots signed out (brand only — the
// login card in <main> is the sign-in affordance); login() flips it via
// updateTitlebar. Refresh / Log out / copy-npub live inside the component.
const NVOY_SEAL = `<svg viewBox="0 0 32 32" aria-hidden="true">
  <rect x="1" y="1" width="30" height="30" rx="7" fill="#0b0906" stroke="#6fa8a0" stroke-opacity=".5" stroke-width="1.2"/>
  <g transform="translate(4 4)" fill="none" stroke="#6fa8a0" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12 H16"/><path d="M12 7 L17 12 L12 17"/><circle cx="20" cy="12" r="1.6" fill="#6fa8a0" stroke="none"/></g>
</svg>`
renderTitlebar('#titlebar', { appName: 'Nvoy', tagline: 'delegator console', sealSvg: NVOY_SEAL })

// Boot order: any tab-session sign-in first (nave-connect parses all three
// kinds — a bare-hex legacy remember still reads as `local`), then a
// protected key (ncryptsec present → passphrase prompt), else the login
// screen. nip46 remembers carry the bunker URI + client key, so a reload
// re-pairs the SAME bunker session without re-approval.
const saved = sessionStorage.getItem('nvoy-login')
const sess = parseSession(saved)
if (sess?.kind === 'nip07') setTimeout(() => { if (window.nostr?.nip44) login(nip07Signer(), 'nip07') }, 250)
else if (sess?.kind === 'nip46') login(signerFromSession(sess, { onAuthUrl }), saved)
else if (sess?.kind === 'local') login(keySigner(parseKey(sess.hexKey)), saved)
else if (localStorage.getItem(NC_KEY)) showUnlock(localStorage.getItem(NC_KEY))
