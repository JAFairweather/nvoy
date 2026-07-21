// settings.mjs — per-device relay configuration (Nvelope pattern, relays
// only). Stored in localStorage; saving reloads so every module reads one
// consistent snapshot. ws:// is allowed so a local test relay can drive the
// console offline (test/wsrelay.mjs).

import { CONFIG_KEY, loadConfig, saveConfig, resetConfig } from './config.mjs'
import { $, esc, state, agentsOf } from './main.mjs'
import { LiveRelay } from '../lib/liverelay.mjs'

let draft = null            // working copy; edits live here until Save

const validRelay = (u) => { try { return /^wss?:$/.test(new URL(u).protocol) } catch { return false } }

const relayRow = (r, i) => `
  <div class="row cfg">
    <input class="r-url" data-i="${i}" value="${esc(r)}" placeholder="wss://relay.example" spellcheck="false" autocomplete="off">
    <button class="icon r-mirror" data-u="${esc(r)}" title="mirror my existing events to this relay (rebroadcast — nothing is re-signed)">⇉</button>
    <button class="icon r-del" data-i="${i}" title="remove relay">×</button>
  </div>`

// Mirror = rebroadcast, the durability story made actionable: adding a relay
// only affects FUTURE publishes, so a new relay holds none of your history
// until you push it there. Everything mirrored is already end-to-end
// protected (encrypted scopes, gift-wrapped grants, nip44-to-self index) and
// already SIGNED — we re-send the same events, the key is never touched.
async function mirrorTo(url, msgEl) {
  if (!validRelay(url)) { msgEl.textContent = 'save a valid relay URL first'; return }
  if (!state.me || !state.relay) { msgEl.textContent = 'sign in first — mirroring gathers YOUR events'; return }
  msgEl.textContent = 'gathering your events from the configured relays…'
  const filters = [
    { kinds: [30440, 10440], authors: [state.me] },            // scopes + index
    { kinds: [1059], '#p': [state.me] },                        // wraps addressed to me
    ...agentsOf().map(a => ({ kinds: [1059], '#p': [a.pub] })), // grants delivered to my agents
  ]
  const seen = new Map()
  for (const f of filters) {
    try { for (const ev of await state.relay.query(f)) seen.set(ev.id, ev) } catch { /* per-filter best effort */ }
  }
  const events = [...seen.values()]
  if (!events.length) { msgEl.textContent = 'nothing to mirror yet'; return }
  const target = new LiveRelay([url])
  let ok = 0, rejected = 0
  try {
    for (let i = 0; i < events.length; i++) {
      msgEl.textContent = `mirroring… ${i + 1}/${events.length}`
      try { await target.publish(events[i]); ok++ } catch { rejected++ }
    }
  } finally { target.close() }
  msgEl.textContent = `mirrored ${ok}/${events.length} event${events.length === 1 ? '' : 's'} to this relay`
    + (rejected ? ` · ${rejected} rejected — relay policy (write allowlists refuse gift wraps' ephemeral authors)` : '')
}

export function renderSettings() {
  draft ??= loadConfig()
  const custom = !!localStorage.getItem(CONFIG_KEY)
  $('settings').innerHTML = `
    <div class="banner">The default relays are public infrastructure — no accounts, no payment,
      and no persistence guarantee. They see only ciphertext: encrypted scopes, gift-wrapped
      grants, your encrypted Grant Index. Your key re-creates everything.</div>
    <div class="card">
      <div class="head"><span class="name">Relays</span>
        <span class="badge ${custom ? 'active' : ''}">${custom ? 'custom · this device' : 'defaults'}</span></div>
      <div class="note">Where scopes, grants, and your Grant Index live. wss:// for real relays;
        ws:// works for a local test relay.</div>
      <div id="cfg-relays">${draft.relays.map(relayRow).join('')}</div>
      <div class="actions"><button id="r-add">+ add relay</button></div>
      <div class="actions" style="margin-top:16px">
        <button class="primary" id="cfg-save">Save &amp; reload</button>
        <button id="cfg-reset">Restore defaults</button>
        <span class="msg" id="cfg-msg"></span>
      </div>
    </div>`

  const msg = $('cfg-msg')
  const pull = () => {       // DOM → draft (keeps typing across add/remove re-renders)
    draft.relays = [...document.querySelectorAll('#cfg-relays .r-url')].map(x => x.value.trim())
  }
  $('r-add').onclick = () => { pull(); draft.relays.push(''); renderSettings() }
  for (const d of document.querySelectorAll('.r-del'))
    d.onclick = () => { pull(); draft.relays.splice(Number(d.dataset.i), 1); renderSettings() }
  for (const b of document.querySelectorAll('.r-mirror'))
    b.onclick = () => mirrorTo(b.dataset.u, msg)

  $('cfg-save').onclick = () => {
    pull()
    draft.relays = draft.relays.filter(Boolean)
    const bad = draft.relays.filter(r => !validRelay(r))
    if (bad.length) { msg.textContent = `${bad[0]} is not a ws(s):// URL`; return }
    if (!draft.relays.length) { msg.textContent = 'need at least one relay'; return }
    saveConfig(draft)
    draft = null
    msg.textContent = 'saved — reloading…'
    location.reload()
  }
  $('cfg-reset').onclick = () => {
    resetConfig()
    draft = null
    msg.textContent = 'defaults restored — reloading…'
    location.reload()
  }
}
