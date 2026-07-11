// ledger.mjs — THE screen (spec §6.4.4): the live answer to "exactly what
// data do my agents hold right now, under what terms — and show me the
// revocations". Every row derives from the Grant Index + nvoy_ledger event
// log, so the whole view reconstitutes from the delegator's nsec alone.
// Revoke-now (§6.4.5) lives here: rotate + re-grant survivors under their
// original terms + optional gift-wrapped 441 notice + ledger events.

import { fetchScope, saveGrantIndex, toIssuedEntry, fromIssuedEntry } from '../lib/nipxx.mjs'
import { rotateWithTerms, sendRevocationNotice } from './nvoygrant.mjs'
import { appendLedger, rotatedEvent, revokedEvent, eventsFor, computeTotals, fmtCountdown, deriveDelegations } from './ledgerlog.mjs'
import { state, $, esc, short, fmtWhen, agentName, load, RELAYS } from './main.mjs'

let filterAgent = ''            // '' = all agents

const termChips = (t) => !t ? '<span class="chip warn" title="granted without an nvoy terms object — a vanilla NIP-DA grant">vanilla grant · no terms</span>' : [
  t.no_persist ? '<span class="chip term" title="runtime serves this to model context only — no disk, no logs">no_persist</span>' : '',
  t.redelegate === false ? '<span class="chip term" title="audit term: runtime refuses to re-wrap keys for third parties">no redelegate</span>' : '',
  t.redelegate === true ? '<span class="chip warn" title="you allowed the runtime to re-wrap keys">redelegate allowed</span>' : '',
  t.reply_scope_requested ? '<span class="chip term" title="agent asked to grant results back via its outbox (M4)">reply requested</span>' : '',
  t.auto_relinquish ? '<span class="chip term" title="agent destroys key + cache on completion / at expiry (§6.6)">auto-relinquish</span>' : '',
].filter(Boolean).join('')

const hRow = (ev) => {
  const what = ev.t === 'granted'
    ? `<b>granted</b> v${ev.v}${ev.terms?.purpose ? ` — “${esc(ev.terms.purpose)}”` : ''}`
    : ev.t === 'rotated'
      ? `<b>rotated</b> v${ev.from_v} → v${ev.to_v} (${ev.survivors} survivor${ev.survivors === 1 ? '' : 's'} re-granted)`
      : `<b>revoked</b> at v${ev.v}${ev.notice ? ` — 441 notice sent${ev.reason ? `: “${esc(ev.reason)}”` : ''}` : ' — silent (no notice)'}`
  return `<div class="hrow"><span class="hdot ${ev.t}"></span><span class="when">${fmtWhen(ev.at)}</span><span class="what">${what}</span></div>`
}

function delegationCard(d, i) {
  const events = eventsFor(state.index, d.scope, d.agent)
  const soon = d.expiresAt !== null && d.expiresAt - Math.floor(Date.now() / 1000) < 24 * 3600
  return `<div class="card" data-i="${i}">
    <div class="head">
      <div>
        <span class="name">${esc(d.scopeName)}</span>
        <span class="badge ${d.status}">${d.status}</span>
        ${d.v !== null ? `<span class="meta" title="scope key generation">v${d.v}</span>` : ''}
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <span class="meta" title="opaque scope id (the d tag)">${esc(d.scope)}</span>
        ${d.status !== 'revoked'
          ? '<button class="danger revoke">Revoke now</button>' : ''}
      </div>
    </div>
    <div class="note">→ <b style="color:var(--text)">${esc(agentName(d.agent))}</b>
      <span class="meta">${esc(short(d.agent))}</span></div>
    ${d.purpose ? `<div class="purpose">“${esc(d.purpose)}”</div>` : ''}
    <div class="chips">${termChips(d.terms)}
      <span class="chip ${d.status === 'expired' || soon ? 'warn' : ''}" title="soft expiry — the runtime honors it; hard expiry is the M4 TTL rotation">${fmtCountdown(d.expiresAt)}</span>
    </div>
    ${events.length ? `<div class="history">${events.map(hRow).join('')}</div>` : ''}
    <div class="actions" style="margin-top:6px"><span class="msg lg-msg"></span></div>
  </div>`
}

export function renderLedger() {
  const all = state.delegations
  const agents = [...new Set(all.map(d => d.agent))]
  if (filterAgent && !agents.includes(filterAgent)) filterAgent = ''
  const rows = filterAgent ? all.filter(d => d.agent === filterAgent) : all
  const t = computeTotals(all, state.index.nvoy_ledger ?? [])
  $('ledger').innerHTML = `
    <div class="lhead">
      <span class="totals"><b>${t.active}</b> active delegation${t.active === 1 ? '' : 's'}
        to <b>${t.agents}</b> agent${t.agents === 1 ? '' : 's'},
        <b>${t.revokedThisMonth}</b> revoked this month</span>
      <span class="spacer"></span>
      <select id="lg-filter" title="filter by agent">
        <option value="">all agents</option>
        ${agents.map(a => `<option value="${a}"${a === filterAgent ? ' selected' : ''}>${esc(agentName(a))}</option>`).join('')}
      </select>
    </div>
    ${rows.map(delegationCard).join('') || `<div class="empty">
      Nothing delegated${filterAgent ? ' to this agent' : ''} yet.<br>
      The ledger is the audit view: every delegation, its terms, every rotation and revocation —
      a query over your encrypted Grant Index, not archaeology across admin panels.</div>`}`

  $('lg-filter').onchange = (e) => { filterAgent = e.target.value; renderLedger() }

  for (const card of document.querySelectorAll('#ledger .card')) {
    const d = rows[Number(card.dataset.i)]
    const btn = card.querySelector('.revoke')
    if (btn) btn.onclick = () => revoke(d, card.querySelector('.lg-msg'))
  }
}

/** Revoke now (§6.4.5): rotate the scope key past this agent, re-grant the
 *  other grantees under their original terms, optionally send a gift-wrapped
 *  441 notice, and record revoked + rotated events in the ledger. */
async function revoke(d, msg) {
  const entry = (state.index.issued ?? []).find(e => e.scope === d.scope)
  if (!entry) { msg.textContent = 'scope not in the index — cannot rotate'; return }
  const rec = fromIssuedEntry(entry)
  const others = rec.grantees.filter(p => p !== d.agent).length
  if (!confirm(`Revoke “${d.scopeName}” from ${agentName(d.agent)}?\n\n` +
    `The scope key rotates${others ? ` and the ${others} other grantee${others === 1 ? ' is' : 's are'} re-granted under their original terms` : ''}. ` +
    `The agent keeps whatever it already read — that is physics, and a compliant no_persist runtime has kept nothing — but its next dereference fails to decrypt.`)) return
  const reason = window.prompt(
    'Optional revocation notice (kind 441, gift-wrapped to the agent — the relay never sees it).\n\n' +
    'Leave empty or cancel to revoke silently.', '')

  msg.textContent = 'reading current scope data…'
  try {
    const res = await fetchScope(state.relay,
      { publisher: state.me, scopeId: rec.scopeId, generation: rec.generation, scopeKey: rec.scopeKey })
    if (res.status !== 'ok') {
      msg.textContent = `cannot read own scope back from relays (${res.status}) — not rotating, that would destroy the data. Retry with Refresh.`
      return
    }
    msg.textContent = 'rotating key + re-granting survivors…'
    const dels = deriveDelegations(state.index)
    const survivors = rec.grantees.filter(p => p !== d.agent).map(pub => ({
      pub, terms: dels.find(x => x.scope === d.scope && x.agent === pub)?.terms ?? null,
    }))
    const rot = await rotateWithTerms(state.relay, state.signer, {
      scopeId: rec.scopeId, generation: rec.generation, payload: res.data,
      scopeName: rec.scopeName, survivors, relayHint: RELAYS[0],
    })
    if (reason) {
      msg.textContent = 'sending 441 notice…'
      await sendRevocationNotice(state.relay, state.signer, d.agent, { scopeId: rec.scopeId, reason })
    }
    msg.textContent = 'recording in your Grant Index…'
    state.index.issued = state.index.issued.map(e => e.scope !== d.scope ? e :
      toIssuedEntry({ scopeId: rec.scopeId, scopeName: rec.scopeName,
        generation: rot.generation, scopeKey: rot.scopeKey }, survivors.map(s => s.pub)))
    state.index.nvoy_ledger = appendLedger(state.index,
      revokedEvent({ scope: d.scope, agent: d.agent, v: rec.generation, reason, notice: !!reason }))
    state.index.nvoy_ledger = appendLedger(state.index,
      rotatedEvent({ scope: d.scope, from_v: rec.generation, to_v: rot.generation, survivors: survivors.length }))
    await saveGrantIndex(state.relay, state.signer, state.index)
    await load()
  } catch (err) { msg.textContent = err.message }
}
