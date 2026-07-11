// settings.mjs — per-device relay configuration (Nvelope pattern, relays
// only). Stored in localStorage; saving reloads so every module reads one
// consistent snapshot. ws:// is allowed so a local test relay can drive the
// console offline (test/wsrelay.mjs).

import { CONFIG_KEY, loadConfig, saveConfig, resetConfig } from './config.mjs'
import { $, esc } from './main.mjs'

let draft = null            // working copy; edits live here until Save

const validRelay = (u) => { try { return /^wss?:$/.test(new URL(u).protocol) } catch { return false } }

const relayRow = (r, i) => `
  <div class="row cfg">
    <input class="r-url" data-i="${i}" value="${esc(r)}" placeholder="wss://relay.example" spellcheck="false" autocomplete="off">
    <button class="icon r-del" data-i="${i}" title="remove relay">×</button>
  </div>`

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
