// delegate.mjs — scope authoring + grant issuance with terms (spec §6.4.2).
// Pick an agent, start from a template (or raw JSON), attach the §4 terms,
// Issue: publishScope under a fresh opaque scope id + key, grantWithTerms
// (nested content.nvoy carrier), then record it in the Grant Index —
// issued entry + nvoy_ledger granted event — in one save.

import { nip19 } from 'nostr-tools'
import { newScopeKey, publishScope, saveGrantIndex, toIssuedEntry } from '../lib/nipxx.mjs'
import { grantWithTerms, opaqueScopeId, TEMPLATES } from './nvoygrant.mjs'
import { appendLedger, grantedEvent } from './ledgerlog.mjs'
import { state, $, esc, agentsOf, agentName, load, RELAYS } from './main.mjs'

const emptyDraft = () => ({    // survives tab switches until issued
  tpl: null, agent: '', json: '', name: '', purpose: '', expires: '',
  credValue: '', reveal: false,
  no_persist: true, redelegate: false, reply_scope_requested: false, auto_relinquish: false,
})
let draft = emptyDraft()

// A credential scope carries exactly one secret under `value` (the convention
// Nactor's grant-reader keys on: scope_name `credential:<name>` → payload.value).
// For these we swap the raw-JSON editor for a dedicated, editable value field
// so pasting a real key is a first-class edit, never JSON surgery on a secret.
const isCredName = (n) => (n || '').trim().startsWith('credential:')

/** Approve flow for access requests (§6.2): agents.mjs pre-fills the form
 *  with the requesting agent + its stated purpose, then switches here.
 *  Credential-migration requests also carry a scope `name` and a `payload`
 *  ({ value }) — for a credential scope that value fills the editable value
 *  field (masked); you paste/fix the real key and Issue = approve-what-you-edited.
 *  Nothing is granted until you Issue. */
export function prefillDelegate({ agent, purpose, name, payload }) {
  draft.agent = agent || draft.agent
  if (purpose) draft.purpose = purpose
  if (name) draft.name = name
  if (payload !== undefined) {
    if (isCredName(name) && payload && typeof payload === 'object' && 'value' in payload) {
      draft.credValue = payload.value ?? ''      // editable value field, not raw JSON
    } else {
      draft.tpl = 'custom'; draft.json = JSON.stringify(payload, null, 2)
    }
  }
}

export function renderDelegate() {
  const agents = agentsOf()
  const isCred = isCredName(draft.name)
  const options = agents.map(a =>
    `<option value="${a.pub}"${a.pub === draft.agent ? ' selected' : ''}>${esc(agentName(a.pub))} — ${esc(nip19.npubEncode(a.pub).slice(0, 16))}…</option>`).join('')
  $('delegate').innerHTML = `
    <div class="card">
      <div class="name">New delegation</div>
      <div class="note" style="margin:4px 0 8px">One scope, one agent, explicit terms. The scope id on
        relays is opaque; the name and data live inside the ciphertext. Updates later are free —
        republish under the same key. Revocation rotates the key.</div>
      <div class="frow">
        <label>agent</label>
        ${agents.length
          ? `<select id="dg-agent">${options}</select>`
          : '<span class="msg">no agents registered — add one in the Agents tab first</span>'}
      </div>
      ${isCred ? '' : `<div class="frow">
        <label>template</label>
        <div class="chips" style="margin:0">
          <button class="tpl" data-tpl="credential" title="a scope carrying exactly one secret under {value} — the shape every credential reader dereferences">🔑 Credential value</button>
          ${Object.entries(TEMPLATES).map(([k, t]) =>
            `<button class="tpl${draft.tpl === k ? ' sel' : ''}" data-tpl="${k}">${esc(t.label)}</button>`).join('')}
          <button class="tpl${draft.tpl === 'custom' ? ' sel' : ''}" data-tpl="custom">Custom JSON</button>
        </div>
      </div>`}
      <div class="frow">
        <label>scope name</label>
        <input type="text" id="dg-name" value="${esc(draft.name)}" placeholder="human name, travels inside the ciphertext">
      </div>
      ${isCred ? `<div class="frow">
        <label>value</label>
        <input type="${draft.reveal ? 'text' : 'password'}" id="dg-credvalue" value="${esc(draft.credValue)}"
          autocomplete="off" spellcheck="false" placeholder="paste the real key here — it lives only inside the encrypted scope"
          style="flex:1;font-family:var(--mono,monospace)">
        <button class="tpl" id="dg-reveal" type="button" title="show/hide">${draft.reveal ? 'hide' : 'show'}</button>
      </div>
      <div class="note" style="margin:2px 0 8px">The runtime proposed this credential; you set the value it
        actually receives. Edit it here — the box never sees what you type until you Issue, and only ever
        dereferences it live from the relay. Change it later by re-issuing; revoke by rotating the scope.</div>`
      : `<textarea id="dg-json" rows="12" spellcheck="false"
        placeholder='scope payload JSON — pick a template or write your own, e.g. { "name": "…", "fields": { … } }'>${esc(draft.json)}</textarea>
      <div class="jsonerr" id="dg-jsonerr"></div>`}

      <div class="sect2">terms (§4 — honored by compliant runtimes, disclosed honestly as non-cryptographic)</div>
      <div class="frow">
        <label>purpose</label>
        <input type="text" id="dg-purpose" value="${esc(draft.purpose)}" placeholder="the contract line the ledger shows, e.g. Plan Q3 travel within stated preferences">
      </div>
      <div class="frow">
        <label>expires</label>
        <input type="datetime-local" id="dg-expires" value="${esc(draft.expires)}">
        <span class="msg">optional — soft expiry; hard expiry is the console's TTL rotation (M4)</span>
      </div>
      <div class="frow">
        <label>runtime</label>
        <label class="ck" title="serve scope data to model context only — no disk, no vector store, no logs">
          <input type="checkbox" id="dg-nopersist" ${draft.no_persist ? 'checked' : ''}> no_persist</label>
        <label class="ck" title="audit term: the runtime refuses to re-wrap keys for third parties">
          <input type="checkbox" id="dg-redelegate" ${draft.redelegate ? 'checked' : ''}> allow redelegate</label>
        <label class="ck" title="ask the agent to grant its results back via its outbox (M4)">
          <input type="checkbox" id="dg-reply" ${draft.reply_scope_requested ? 'checked' : ''}> reply scope requested</label>
        <label class="ck" title="agent destroys its key + cache on task completion / at expiry (§6.6)">
          <input type="checkbox" id="dg-relinquish" ${draft.auto_relinquish ? 'checked' : ''}> auto-relinquish</label>
      </div>
      <div class="frow">
        <label>contact</label>
        <input type="text" id="dg-contact" value="${esc(nip19.npubEncode(state.me))}" readonly
          title="your npub — where the agent sends claim/renewal/relinquish notices" style="color:var(--dim)">
      </div>
      <div class="actions">
        <button class="primary" id="dg-issue" ${agents.length ? '' : 'disabled'}>Issue delegation</button>
        <span class="msg" id="dg-msg"></span>
      </div>
    </div>`

  const pull = () => {
    draft.agent = $('dg-agent')?.value ?? draft.agent
    draft.name = $('dg-name').value
    if ($('dg-json')) draft.json = $('dg-json').value
    if ($('dg-credvalue')) draft.credValue = $('dg-credvalue').value
    draft.purpose = $('dg-purpose').value
    draft.expires = $('dg-expires').value
    draft.no_persist = $('dg-nopersist').checked
    draft.redelegate = $('dg-redelegate').checked
    draft.reply_scope_requested = $('dg-reply').checked
    draft.auto_relinquish = $('dg-relinquish').checked
  }

  for (const b of document.querySelectorAll('#delegate .tpl'))
    b.onclick = () => {
      pull()
      // The credential chip isn't a JSON template — it flips the form into
      // credential mode (masked value field; payload becomes {value}) by
      // seeding the name with the namespace prefix. Complete the name, paste
      // the value, Issue.
      if (b.dataset.tpl === 'credential') {
        draft.tpl = null
        if (!isCredName(draft.name)) draft.name = 'credential:'
        renderDelegate()
        const n = $('dg-name')
        if (n) { n.focus(); try { n.setSelectionRange(n.value.length, n.value.length) } catch {} }
        return
      }
      draft.tpl = b.dataset.tpl
      const t = TEMPLATES[draft.tpl]
      if (t) {
        draft.json = JSON.stringify(t.payload, null, 2)
        draft.name = t.payload.name
        if (!draft.purpose) draft.purpose = t.purpose
      } else if (!draft.json) {
        draft.json = JSON.stringify({ name: 'My scope', fields: {} }, null, 2)
      }
      renderDelegate()
    }

  const jsonErr = $('dg-jsonerr')
  const validate = () => {
    if (!jsonErr || !$('dg-json')) return null              // credential mode: no free-form JSON
    if (!$('dg-json').value.trim()) { jsonErr.textContent = ''; return null }
    try {
      const obj = JSON.parse($('dg-json').value)
      if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) throw new Error('payload must be a JSON object')
      jsonErr.textContent = ''
      return obj
    } catch (err) { jsonErr.textContent = `✗ ${err.message}`; return null }
  }
  if ($('dg-json')) { $('dg-json').oninput = validate; validate() }
  if ($('dg-reveal')) $('dg-reveal').onclick = () => { pull(); draft.reveal = !draft.reveal; renderDelegate() }
  // Credential mode follows the NAME field live: typing `credential:…` swaps
  // the JSON editor for the masked value field (and back). Re-render only on
  // crossing the boundary, restoring focus + caret so typing never drops.
  $('dg-name').oninput = () => {
    const wasCred = isCred
    const el = $('dg-name'); const pos = el.selectionStart
    pull()
    if (isCredName(draft.name) !== wasCred) {
      renderDelegate()
      const n2 = $('dg-name')
      if (n2) { n2.focus(); try { n2.setSelectionRange(pos, pos) } catch {} }
    }
  }

  const msg = $('dg-msg')
  $('dg-issue').onclick = async () => {
    pull()
    const agent = $('dg-agent')?.value
    if (!agent) { msg.textContent = 'pick an agent'; return }
    // Recompute at click time — the render-time isCred goes stale if the name
    // was edited without a re-render, and a credential issued down the JSON
    // path silently loses the masked-field ergonomics (the payload shape is
    // caller-controlled either way; the reader keys on `.value`).
    const credNow = isCredName(draft.name)
    let payload, scopeName
    if (credNow) {
      const v = draft.credValue.trim()
      if (!v) { msg.textContent = 'paste the credential value before issuing'; return }
      scopeName = draft.name.trim()
      if (!scopeName) { msg.textContent = 'scope name is required'; return }
      payload = { value: v }                                // exactly what the grant-reader dereferences
    } else {
      payload = validate()
      if (!payload) { msg.textContent = 'fix the payload JSON first'; return }
      scopeName = draft.name.trim() || payload.name || 'unnamed scope'
    }
    if (!draft.purpose.trim()) { msg.textContent = 'purpose is required — it is the line the ledger holds you to'; return }
    const terms = {
      purpose: draft.purpose.trim(),
      ...(draft.expires ? { expires_at: Math.floor(new Date(draft.expires).getTime() / 1000) } : {}),
      no_persist: draft.no_persist,
      redelegate: draft.redelegate,
      reply_scope_requested: draft.reply_scope_requested,
      auto_relinquish: draft.auto_relinquish,
      contact: nip19.npubEncode(state.me),
    }
    if (terms.expires_at && terms.expires_at <= Math.floor(Date.now() / 1000)) {
      msg.textContent = 'expiry is in the past'; return
    }
    const scopeId = opaqueScopeId()
    const scopeKey = newScopeKey()
    try {
      msg.textContent = 'publishing scope (30440)…'
      await publishScope(state.relay, state.signer, { scopeId, generation: 1, scopeKey, payload })
      msg.textContent = 'delivering grant with terms (440 in a gift wrap)…'
      await grantWithTerms(state.relay, state.signer, agent, {
        scopeId, generation: 1, scopeKey, scopeName, relayHint: RELAYS[0], terms,
      })
      msg.textContent = 'recording in your Grant Index…'
      state.index.issued = [...(state.index.issued ?? []),
        toIssuedEntry({ scopeId, scopeName, generation: 1, scopeKey }, [agent])]
      state.index.nvoy_ledger = appendLedger(state.index,
        grantedEvent({ scope: scopeId, agent, v: 1, terms: { nvoy: 1, ...terms }, name: scopeName }))
      await saveGrantIndex(state.relay, state.signer, state.index)
      draft = emptyDraft()
      msg.textContent = `delegated — scope ${scopeId} to ${agentName(agent)}. See the Ledger.`
      await load()
      $('dg-msg').textContent = `delegated — scope ${scopeId} to ${agentName(agent)}. See the Ledger.`
    } catch (err) { msg.textContent = err.message }
  }
}
