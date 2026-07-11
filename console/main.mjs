// main.mjs — Nvoy console shell: sign-in (NIP-07 or local key with NIP-49
// protect offer), tabs, shared state. agents.mjs = registry, delegate.mjs =
// scope authoring + issuance, ledger.mjs = the audit view. Pure NIP-DA
// client plus the payload-level nvoy terms extension (spec §4).

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import * as nip49 from 'nostr-tools/nip49'
import { LiveRelay } from '../lib/liverelay.mjs'
import { localSigner, loadGrantIndex } from '../lib/nipxx.mjs'
import { loadConfig } from './config.mjs'
import { deriveDelegations } from './ledgerlog.mjs'
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

function nip07Signer() {
  const n = window.nostr
  let pub = null
  return {
    getPublicKey: async () => (pub ??= await n.getPublicKey()),
    signEvent: (e) => n.signEvent(e),
    nip44Encrypt: (pk, pt) => n.nip44.encrypt(pk, pt),
    nip44Decrypt: (pk, ct) => n.nip44.decrypt(pk, ct),
  }
}

const TABS = { agents: renderAgents, delegate: renderDelegate, ledger: renderLedger, settings: renderSettings }
let current = 'agents'
function showTab(t) {
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
  try { state.me = await signer.getPublicKey() }
  catch (err) { $('err').textContent = `extension refused: ${err.message}`; return }
  if (remember) sessionStorage.setItem('nvoy-login', remember)
  state.relay ??= new LiveRelay(RELAYS)
  $('login').style.display = 'none'
  $('unlock').style.display = 'none'
  $('me').style.display = 'flex'
  $('tabs').style.display = 'flex'
  const npub = nip19.npubEncode(state.me)
  $('my-npub').textContent = npub.slice(0, 12) + '…' + npub.slice(-4)
  $('my-npub').onclick = () => navigator.clipboard.writeText(npub)
  showTab(Object.keys(TABS).includes(location.hash.slice(1)) ? location.hash.slice(1) : 'agents')
  if (remember && remember !== 'nip07') offerProtect(remember)
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
      login(localSigner(sk), null)                           // nothing new persisted
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

/** Reload everything from the Grant Index — the single authoritative record.
 *  Agents, delegations, and history all derive from it; kind-0 profiles are
 *  presentation only, fetched fresh per load. */
export async function load() {
  const { relay, signer } = state
  $('status').textContent = 'loading your Grant Index from relays…'
  try {
    state.index = await loadGrantIndex(relay, signer)
    state.delegations = deriveDelegations(state.index)
    const pubs = [...new Set([...agentsOf().map(a => a.pub), ...state.delegations.map(d => d.agent)])]
    state.profiles = new Map()
    if (pubs.length)
      for (const ev of await relay.query({ kinds: [0], authors: pubs, limit: pubs.length * 3 }))
        if (!state.profiles.has(ev.pubkey)) {
          try { state.profiles.set(ev.pubkey, JSON.parse(ev.content)) } catch { /* skip */ }
        }
    const active = state.delegations.filter(d => d.status === 'active').length
    $('status').textContent =
      `${agentsOf().length} agent${agentsOf().length === 1 ? '' : 's'} · ` +
      `${active} active delegation${active === 1 ? '' : 's'}. ` +
      `Everything below derives from your encrypted Grant Index — sign in with this key anywhere and it reconstitutes.`
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
$('go').onclick = () => {
  try { const k = parseKey($('nsec').value); login(localSigner(k), hexOf(k)) }
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
  $('newkey-continue').onclick = () => login(localSigner(k), hexOf(k))
}
$('nip07').onclick = () => {
  if (!window.nostr?.nip44) { $('err').textContent = 'No NIP-07 extension found (needs nip44 support — Alby or nos2x).'; return }
  login(nip07Signer(), 'nip07')
}
$('refresh').onclick = () => load()
$('logout').onclick = () => { sessionStorage.removeItem('nvoy-login'); location.hash = ''; location.reload() }

// Boot order: protected key (ncryptsec present → passphrase prompt), then
// any tab-session sign-in, else the login screen.
const saved = sessionStorage.getItem('nvoy-login')
if (saved === 'nip07') setTimeout(() => { if (window.nostr?.nip44) login(nip07Signer(), 'nip07') }, 250)
else if (saved) login(localSigner(Uint8Array.from(saved.match(/../g), h => parseInt(h, 16))), saved)
else if (localStorage.getItem(NC_KEY)) showUnlock(localStorage.getItem(NC_KEY))
