// agents.mjs — the agent registry. Agents are contacts with a kind: agent
// flag (spec §6.4.1), stored as the app-level `nvoy_agents` field on the
// delegator's Grant Index (pattern: nvelope_invites — the 10440 payload is
// app-extensible JSON, lib untouched):
//   nvoy_agents: [{ pub, added_at }]
// kind-0 metadata (name / about = the agent's purpose statement) is fetched
// per load for display only — never stored, always current.

import { nip19 } from 'nostr-tools'
import { saveGrantIndex } from '../lib/nipxx.mjs'
import { state, $, esc, short, fmtWhen, load, parsePub, agentsOf, agentName, openAgentPage } from './main.mjs'
import { openDelegationInLedger } from './ledger.mjs'

// Copy an npub to the clipboard with visual feedback, degrading gracefully:
// async clipboard API → execCommand → (both blocked) select nothing and just
// flash the label. The same robustness as the shared titlebar's npub pill.
// Inline SVGs so the button always renders — a font glyph (⧉) can come up as a
// blank box in some environments, which reads as "no button" (nvoy#17 follow-up).
const COPY_SVG = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>'
const CHECK_SVG = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>'

function copyNpub(btn, npub) {
  const done = () => { btn.innerHTML = CHECK_SVG; btn.classList.add('ok'); setTimeout(() => { btn.innerHTML = COPY_SVG; btn.classList.remove('ok') }, 1100) }
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(npub).then(done, () => fallbackCopy(npub, done))
  } else fallbackCopy(npub, done)
}
function fallbackCopy(text, done) {
  try {
    const ta = document.createElement('textarea')
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'
    document.body.appendChild(ta); ta.select()
    document.execCommand('copy'); ta.remove(); done()
  } catch { /* clipboard unavailable — nothing more we can do silently */ }
}

// Clickable (nvoy#17): opens this delegation in the Ledger, focused, where the
// ＋ grant-to-another-identity action lives. data-scope/data-agent identify it.
const statusChip = (d) =>
  `<button type="button" class="chip scope-${d.status} del-chip" data-scope="${esc(d.scope)}" data-agent="${esc(d.agent)}" title="${esc(d.purpose ?? 'open in the Ledger — re-grant to another identity')}">${esc(d.scopeName)} · ${d.status}</button>`

function agentCard(a, i) {
  const p = state.profiles.get(a.pub)
  const dels = state.delegations.filter(d => d.agent === a.pub)
  const activeCount = dels.filter(d => d.status === 'active').length
  const npub = nip19.npubEncode(a.pub)
  // Human-readable identity from the agent's kind-0 profile: avatar (icon),
  // name, and nip05 (its verified name@domain). Falls back to a gold monogram
  // when a key has published no picture, so an unprofiled key still reads clean.
  const name = agentName(a.pub)
  const initial = esc(((name || '?').trim()[0] || '?').toUpperCase())
  const avatarBox = 'width:34px;height:34px;border-radius:9px;flex:none'
  const avatar = p?.picture
    ? `<img class="avatar" src="${esc(p.picture)}" alt="" width="34" height="34" loading="lazy" style="${avatarBox};object-fit:cover;background:#0b0906">`
    : `<div class="avatar-mono" style="${avatarBox};display:flex;align-items:center;justify-content:center;background:#1a140c;color:#c39a56;font-weight:600">${initial}</div>`
  return `<div class="card ag-card" data-i="${i}" tabindex="0" role="button"
    aria-label="open ${esc(name)}" title="open this agent">
    <div class="head">
      <div style="display:flex;align-items:center;gap:11px;min-width:0">
        ${avatar}
        <div style="min-width:0">
          <span class="name">${esc(name)}</span>
          <span class="badge">agent</span>
          ${p?.nip05 ? `<div class="meta" style="margin-top:1px">${esc(p.nip05)}</div>` : ''}
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex:none">
        <span class="meta" style="font-family:var(--mono,monospace)">${esc(short(a.pub))}</span>
        <button class="icon copy-npub" title="copy npub" aria-label="copy npub" style="cursor:pointer">${COPY_SVG}</button>
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

export function renderAgents() {
  const agents = agentsOf()
  $('agents').innerHTML = `
    <div class="newbar">
      <input id="ag-npub" placeholder="agent npub1… (from the Nvoy MCP server boot line, or its operator)" autocomplete="off" spellcheck="false">
      <button class="primary" id="ag-add">+ Add agent</button>
    </div>
    <div class="msg" id="ag-msg" style="margin:-8px 0 14px"></div>
    ${agents.map(agentCard).join('') || `<div class="empty">
      No agents yet. An agent is a keypair held by an Nvoy MCP server —
      boot one with <code>node mcp/dist/server.js --ephemeral</code> and paste its npub above.<br>
      You delegate scopes of data to it; it dereferences them live and loses access when you revoke.</div>`}`

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
    const copyBtn = card.querySelector('.copy-npub')
    copyBtn.onclick = (e) => { e.stopPropagation(); copyNpub(copyBtn, nip19.npubEncode(a.pub)) }
    // Delegation chips open the grant in the Ledger, focused on its re-grant UI.
    for (const chip of card.querySelectorAll('.del-chip')) {
      chip.onclick = (e) => { e.stopPropagation(); openDelegationInLedger(chip.dataset.scope, chip.dataset.agent) }
    }
    // The card opens the agent page. Buttons inside it stop propagation so a copy or a remove is
    // not also a navigation — the roster was a dead end before this, and the fix should not make
    // every control ambiguous.
    card.addEventListener('click', (e) => {
      if (e.target.closest('button')) return
      openAgentPage(a.pub)
    })
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openAgentPage(a.pub) }
    })
    const del = card.querySelector('.del-agent')
    if (!del.disabled) del.onclick = async (e) => {
      e.stopPropagation()
      if (!confirm(`Remove ${agentName(a.pub)} from the registry?\n\nLedger history is kept; only the registry entry goes.`)) return
      state.index.nvoy_agents = agentsOf().filter(x => x.pub !== a.pub)
      try { await saveGrantIndex(state.relay, state.signer, state.index); await load() }
      catch (err) { msg.textContent = err.message }
    }
  }
}
