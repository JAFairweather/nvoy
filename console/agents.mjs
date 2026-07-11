// agents.mjs — the agent registry. Agents are contacts with a kind: agent
// flag (spec §6.4.1), stored as the app-level `nvoy_agents` field on the
// delegator's Grant Index (pattern: nvelope_invites — the 10440 payload is
// app-extensible JSON, lib untouched):
//   nvoy_agents: [{ pub, added_at }]
// kind-0 metadata (name / about = the agent's purpose statement) is fetched
// per load for display only — never stored, always current.

import { nip19 } from 'nostr-tools'
import { saveGrantIndex } from '../lib/nipxx.mjs'
import { state, $, esc, short, fmtWhen, load, parsePub, agentsOf, agentName, dismissRequest, showTab } from './main.mjs'
import { prefillDelegate } from './delegate.mjs'

const statusChip = (d) =>
  `<span class="chip scope-${d.status}" title="${esc(d.purpose ?? '')}">${esc(d.scopeName)} · ${d.status}</span>`

function agentCard(a, i) {
  const p = state.profiles.get(a.pub)
  const dels = state.delegations.filter(d => d.agent === a.pub)
  const activeCount = dels.filter(d => d.status === 'active').length
  const npub = nip19.npubEncode(a.pub)
  return `<div class="card" data-i="${i}">
    <div class="head">
      <div>
        <span class="name">${esc(agentName(a.pub))}</span>
        <span class="badge">agent</span>
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <span class="meta copy-npub" title="click to copy npub" style="cursor:pointer">${esc(short(a.pub))}</span>
        <button class="icon del-agent" title="${activeCount
          ? 'this agent holds active delegations — revoke them in the Ledger first'
          : 'remove from registry (ledger history is kept)'}"
          ${activeCount ? 'disabled' : ''}>×</button>
      </div>
    </div>
    ${p?.about ? `<div class="note">${esc(p.about)}</div>` : ''}
    <div class="sect2">delegations</div>
    <div class="chips">${dels.map(statusChip).join('') ||
      '<span class="msg">nothing delegated yet — use the Delegations tab</span>'}</div>
  </div>`
}

/** Pending access requests (§6.2): gift-wrapped nvoy_request_access rumors.
 *  Approve = register the agent (if new) + open the delegate form pre-filled;
 *  deny = dismiss locally — nothing was granted, so nothing goes on the wire. */
function requestCard(r, i) {
  return `<div class="reqrow" data-i="${i}">
    <div class="reqbody">
      <b>${esc(agentName(r.from))}</b> <span class="meta">${esc(short(r.from))}</span>
      <span class="meta">· ${fmtWhen(r.at)}</span>
      <div class="purpose">“${esc(r.purpose)}”</div>
    </div>
    <div class="reqacts">
      <button class="primary req-approve">Approve…</button>
      <button class="req-deny" title="dismiss on this device — the agent is not notified">Deny</button>
    </div>
  </div>`
}

export function renderAgents() {
  const agents = agentsOf()
  $('agents').innerHTML = `
    ${state.requests.length ? `<div class="card requests">
      <div class="name">Pending access requests</div>
      <div class="note" style="margin:2px 0 8px">Agents asking for a delegation. Approving opens the
        delegate form pre-filled — you still choose the data and the terms. Denying dismisses the
        request on this device only; the agent learns nothing.</div>
      ${state.requests.map(requestCard).join('')}
    </div>` : ''}
    <div class="newbar">
      <input id="ag-npub" placeholder="agent npub1… (from the Nvoy MCP server boot line, or its operator)" autocomplete="off" spellcheck="false">
      <button class="primary" id="ag-add">+ Add agent</button>
    </div>
    <div class="msg" id="ag-msg" style="margin:-8px 0 14px"></div>
    ${agents.map(agentCard).join('') || `<div class="empty">
      No agents yet. An agent is a keypair held by an Nvoy MCP server —
      boot one with <code>node mcp/dist/server.js --ephemeral</code> and paste its npub above.<br>
      You delegate scopes of data to it; it dereferences them live and loses access when you revoke.</div>`}`

  for (const row of document.querySelectorAll('#agents .reqrow')) {
    const r = state.requests[Number(row.dataset.i)]
    if (!r) continue
    row.querySelector('.req-approve').onclick = async () => {
      if (!agentsOf().some(a => a.pub === r.from)) {
        state.index.nvoy_agents = [...agentsOf(), { pub: r.from, added_at: Math.floor(Date.now() / 1000) }]
        try { await saveGrantIndex(state.relay, state.signer, state.index) }
        catch (err) { $('ag-msg').textContent = err.message; return }
      }
      dismissRequest(r.id)
      prefillDelegate({ agent: r.from, purpose: r.purpose })
      showTab('delegate')
    }
    row.querySelector('.req-deny').onclick = () => { dismissRequest(r.id); renderAgents() }
  }

  const msg = $('ag-msg')
  $('ag-add').onclick = async () => {
    let pub
    try { pub = parsePub($('ag-npub').value) }
    catch { msg.textContent = 'expected an npub1… or 64-char hex pubkey'; return }
    if (pub === state.me) { msg.textContent = 'that is your own key — agents have their own'; return }
    if (agentsOf().some(a => a.pub === pub)) { msg.textContent = 'already in the registry'; return }
    msg.textContent = 'saving to your Grant Index…'
    try {
      state.index.nvoy_agents = [...agentsOf(), { pub, added_at: Math.floor(Date.now() / 1000) }]
      await saveGrantIndex(state.relay, state.signer, state.index)
      $('ag-npub').value = ''
      await load()                                   // fetch its kind-0 for display
    } catch (err) { msg.textContent = err.message }
  }
  $('ag-npub').onkeydown = (e) => { if (e.key === 'Enter') $('ag-add').onclick() }

  for (const card of document.querySelectorAll('#agents .card')) {
    const a = agentsOf()[Number(card.dataset.i)]
    if (!a) continue
    card.querySelector('.copy-npub').onclick = () => navigator.clipboard.writeText(nip19.npubEncode(a.pub))
    const del = card.querySelector('.del-agent')
    if (!del.disabled) del.onclick = async () => {
      if (!confirm(`Remove ${agentName(a.pub)} from the registry?\n\nLedger history is kept; only the registry entry goes.`)) return
      state.index.nvoy_agents = agentsOf().filter(x => x.pub !== a.pub)
      try { await saveGrantIndex(state.relay, state.signer, state.index); await load() }
      catch (err) { msg.textContent = err.message }
    }
  }
}
