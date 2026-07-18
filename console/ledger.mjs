// ledger.mjs — THE screen (spec §6.4.4): the live answer to "exactly what
// data do my agents hold right now, under what terms — and show me the
// revocations". Every row derives from the Grant Index + nvoy_ledger event
// log, so the whole view reconstitutes from the delegator's nsec alone.
// M4 additions: relinquish one-tap confirms (§6.6, decision 6), the agent
// "outputs" surface (§6.5 — reply scopes dereferenced live, never stored),
// and the honest TTL banner (§6.4.3 — hard expiry runs while this is open).
// Revoke-now (§6.4.5) shares the rotation spine in ttl.mjs.

import { fetchScope, saveGrantIndex } from '../lib/nipxx.mjs'
import { sendRevocationNotice, grantWithTerms } from './nvoygrant.mjs'
import { revokedEvent, rotatedEvent, grantedEvent, appendLedger, eventsFor, computeTotals, fmtCountdown } from './ledgerlog.mjs'
import { rotateDropping, runRelinquishRotation, nextExpiry } from './ttl.mjs'
import { state, $, esc, short, fmtWhen, agentName, agentsOf, load, RELAYS } from './main.mjs'

let filterAgent = ''            // '' = all agents

const termChips = (t) => !t ? '<span class="chip warn" title="granted without an nvoy terms object — a vanilla NIP-DA grant">vanilla grant · no terms</span>' : [
  t.no_persist ? '<span class="chip term" title="runtime serves this to model context only — no disk, no logs">no_persist</span>' : '',
  t.redelegate === false ? '<span class="chip term" title="audit term: runtime refuses to re-wrap keys for third parties">no redelegate</span>' : '',
  t.redelegate === true ? '<span class="chip warn" title="you allowed the runtime to re-wrap keys">redelegate allowed</span>' : '',
  t.reply_scope_requested ? '<span class="chip term" title="agent grants results back via its outbox (§6.5) — see the output panel below">reply requested</span>' : '',
  t.auto_relinquish ? '<span class="chip term" title="agent destroys key + cache on completion / at expiry (§6.6)">auto-relinquish</span>' : '',
].filter(Boolean).join('')

const hRow = (ev) => {
  const what = ev.t === 'granted'
    ? `<b>granted</b> v${ev.v}${ev.terms?.purpose ? ` — “${esc(ev.terms.purpose)}”` : ''}`
    : ev.t === 'rotated'
      ? `<b>rotated</b> v${ev.from_v} → v${ev.to_v} (${ev.survivors} survivor${ev.survivors === 1 ? '' : 's'} re-granted)`
      : ev.t === 'relinquished'
        ? `<b>relinquished</b> by the agent at v${ev.v}${ev.reason ? ` — “${esc(ev.reason)}”` : ''}`
          + `<span class="meta" title="when the runtime reported destroying its key + cache"> (key destroyed ${fmtWhen(ev.destroyed_at ?? ev.at)})</span>`
        : ev.t === 'expired-rotated'
          ? `<b>expired</b> — TTL rotation v${ev.from_v} → v${ev.to_v} (${ev.expired} lapsed grantee${ev.expired === 1 ? '' : 's'} dropped, ${ev.survivors} re-granted)`
          : `<b>revoked</b> at v${ev.v}${ev.notice ? ` — 441 notice sent${ev.reason ? `: “${esc(ev.reason)}”` : ''}` : ' — silent (no notice)'}`
  return `<div class="hrow"><span class="hdot ${ev.t}"></span><span class="when">${fmtWhen(ev.at)}</span><span class="what">${what}</span></div>`
}

function delegationCard(d, i) {
  const events = eventsFor(state.index, d.scope, d.agent)
  const soon = d.expiresAt !== null && d.expiresAt - Math.floor(Date.now() / 1000) < 24 * 3600
  // 'expired' can mean lapsed-but-still-holding (sweep imminent) OR already
  // dropped by an expiry rotation — only a holder has anything to revoke.
  const held = !!(state.index.issued ?? []).find(e => e.scope === d.scope)?.grantees?.includes(d.agent)
  const pendingRel = state.pendingRelinquish.find(x => x.scope === d.scope && x.agent === d.agent)
  // Outputs outlive the input delegation deliberately (§6.5): you can revoke
  // a misbehaving agent's INPUT while retaining its output history.
  const wantsOutput = !!d.terms?.reply_scope_requested || state.received.some(g => g.publisher === d.agent)
  return `<div class="card" data-i="${i}">
    <div class="head">
      <div>
        <span class="name">${esc(d.scopeName)}</span>
        <span class="badge ${d.status}">${d.status}</span>
        ${d.v !== null ? `<span class="meta" title="scope key generation">v${d.v}</span>` : ''}
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <span class="meta" title="opaque scope id (the d tag)">${esc(d.scope)}</span>
        ${held ? '<button class="danger revoke">Revoke now</button>' : ''}
      </div>
    </div>
    <div class="note">→ <b style="color:var(--text)">${esc(agentName(d.agent))}</b>
      <span class="meta">${esc(short(d.agent))}</span></div>
    ${d.purpose ? `<div class="purpose">“${esc(d.purpose)}”</div>` : ''}
    <div class="chips">${termChips(d.terms)}
      ${d.status === 'active' || d.status === 'expired' ? `<span class="chip ${d.status === 'expired' || soon ? 'warn' : ''}" title="${held ? 'while this console is open, the TTL scheduler rotates the key at the deadline — hard expiry' : 'hard expiry landed: the key was rotated past this agent'}">${fmtCountdown(d.expiresAt)}</span>` : ''}
    </div>
    ${pendingRel ? `<div class="relq">
      <span>Agent relinquished this delegation${pendingRel.reason ? ` — “${esc(pendingRel.reason)}”` : ''} and reports its key destroyed.
      ${pendingRel.others} other grantee${pendingRel.others === 1 ? ' holds' : 's hold'} this scope, so rotation needs your tap
      (survivors are re-granted under their original terms).</span>
      <button class="primary rel-confirm">Rotate now</button>
    </div>` : ''}
    ${wantsOutput ? `<div class="sect2">agent output (§6.5 — dereferenced live, never stored)</div>
      <div class="outbox" data-agent="${d.agent}"><span class="msg">loading output scope…</span></div>` : ''}
    ${events.length ? `<div class="history">${events.map(hRow).join('')}</div>` : ''}
    <div class="actions" style="margin-top:6px">
      <button class="addg" title="grant this exact scope — same key, same value — to another identity (credential sovereignty: the identity that consumes it becomes a grantee, no secret re-entered)">＋ grant to another identity</button>
      <span class="addg-ui"></span>
      <span class="msg lg-msg"></span>
    </div>
  </div>`
}

/** Fill an output panel: find the agent's outbox grant among the gift wraps
 *  addressed to us and dereference it NOW — a read, never a stored copy. */
async function fillOutput(el, agentPub) {
  const grant = state.received
    .filter(g => g.publisher === agentPub)
    .sort((a, b) => b.issuedAt - a.issuedAt)[0]
  if (!grant) { el.innerHTML = '<span class="msg">no output yet — the agent has not written its outbox</span>'; return }
  try {
    const res = await fetchScope(state.relay, grant)
    if (res.status === 'ok') {
      const { updated_at, ...data } = res.data
      el.innerHTML = `<pre class="outjson">${esc(JSON.stringify(data, null, 2))}</pre>
        <span class="meta">v${res.generation}${updated_at ? ` · updated ${fmtWhen(updated_at)}` : ''} · scope ${esc(grant.scopeId)}</span>`
    } else {
      el.innerHTML = `<span class="msg">output scope ${res.status === 'stale' ? 'was rotated by the agent' : 'not found on the relays'}</span>`
    }
  } catch (err) { el.innerHTML = `<span class="msg">${esc(err.message)}</span>` }
}

export function renderLedger() {
  const all = state.delegations
  const agents = [...new Set(all.map(d => d.agent))]
  if (filterAgent && !agents.includes(filterAgent)) filterAgent = ''
  const rows = filterAgent ? all.filter(d => d.agent === filterAgent) : all
  const t = computeTotals(all, state.index.nvoy_ledger ?? [])
  const next = nextExpiry(state.index)
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
    ${all.some(d => d.expiresAt !== null && (d.status === 'active' || d.status === 'expired')) ? `<div class="ttlnote">
      Hard expiry runs <b>while this console is open</b>: at each deadline the scope key is rotated and only
      unexpired grantees are re-granted${next ? ` (next: ${fmtCountdown(next).replace('expires', 'fires')})` : ''}.
      Console closed = soft expiry only — compliant runtimes stop serving at the deadline, and the sweep
      completes on your next visit. To cover the gap without the browser, run the operator daemon
      (<code>node bin/nvoy-ttl.mjs</code>, holds your nsec — documented in its header); a hosted scheduler is future work.</div>` : ''}
    ${rows.map(delegationCard).join('') || `<div class="empty">
      Nothing delegated${filterAgent ? ' to this agent' : ''} yet.<br>
      The ledger is the audit view: every delegation, its terms, every rotation and revocation —
      a query over your encrypted Grant Index, not archaeology across admin panels.</div>`}`

  $('lg-filter').onchange = (e) => { filterAgent = e.target.value; renderLedger() }

  for (const card of document.querySelectorAll('#ledger .card')) {
    const d = rows[Number(card.dataset.i)]
    const msg = card.querySelector('.lg-msg')
    const btn = card.querySelector('.revoke')
    if (btn) btn.onclick = () => revoke(d, msg)
    const rel = card.querySelector('.rel-confirm')
    if (rel) rel.onclick = () => confirmRelinquish(d, msg)
    const out = card.querySelector('.outbox')
    if (out) fillOutput(out, out.dataset.agent)
    const addg = card.querySelector('.addg')
    if (addg) addg.onclick = () => {
      const entry = (state.index.issued ?? []).find(e => e.scope === d.scope)
      const cands = agentsOf().filter(a => !(entry?.grantees ?? []).includes(a.pub))
      const ui = card.querySelector('.addg-ui')
      if (!cands.length) { ui.textContent = ' — every registered identity already holds this scope'; return }
      ui.innerHTML = ` <select class="addg-sel">${cands.map(a =>
        `<option value="${a.pub}">${esc(agentName(a.pub))}</option>`).join('')}</select> <button class="addg-go primary">grant</button>`
      ui.querySelector('.addg-go').onclick = () => addGrantee(d, ui.querySelector('.addg-sel').value, msg)
    }
  }
}

/** Add another identity as a grantee to an EXISTING scope — the credential
 *  sovereignty primitive (nact/docs/credential-sovereignty.md): re-grant a scope
 *  to the identity that actually consumes it, reusing the SAME scope key and the
 *  SAME published value. No secret is re-entered, and no duplicate scope is
 *  created — the new grantee's own grant-reader can decrypt it, while any prior
 *  grantee (e.g. the Nave Nactor during transition) keeps its grant until you
 *  revoke it at cutover. This is how a credential moves from being addressed to
 *  the broker to being addressed to the owning identity, one tap at a time. */
async function addGrantee(d, newPub, msg) {
  const entry = (state.index.issued ?? []).find(e => e.scope === d.scope)
  if (!entry) { msg.textContent = 'scope not in the index — cannot re-grant'; return }
  if ((entry.grantees ?? []).includes(newPub)) { msg.textContent = `${agentName(newPub)} already holds this scope`; return }
  const scopeKey = Uint8Array.from(atob(entry.key), c => c.charCodeAt(0))   // reuse the SAME key — same value, no re-entry
  const scopeName = entry.scope_name ?? d.scopeName
  const terms = d.terms ? { ...d.terms } : { purpose: d.purpose || scopeName }
  msg.textContent = `granting “${scopeName}” to ${agentName(newPub)} (v${entry.v}, same value)…`
  try {
    await grantWithTerms(state.relay, state.signer, newPub, {
      scopeId: d.scope, generation: entry.v, scopeKey, scopeName, relayHint: RELAYS[0], terms,
    })
    entry.grantees = [...(entry.grantees ?? []), newPub]
    state.index.nvoy_ledger = appendLedger(state.index,
      grantedEvent({ scope: d.scope, agent: newPub, v: entry.v, terms: { nvoy: 1, ...terms }, name: scopeName }))
    await saveGrantIndex(state.relay, state.signer, state.index)
    await load()
  } catch (err) { msg.textContent = err.message }
}

/** One-tap finalization of a queued relinquishment (§6.6 phase 2). */
async function confirmRelinquish(d, msg) {
  const item = state.pendingRelinquish.find(x => x.scope === d.scope && x.agent === d.agent)
  if (!item) return
  msg.textContent = 'rotating key + re-granting survivors…'
  try {
    await runRelinquishRotation(state.relay, state.signer, state.index, item, { relayHint: RELAYS[0] })
    await load()
  } catch (err) { msg.textContent = err.message }
}

/** Revoke now (§6.4.5): rotate the scope key past this agent, re-grant the
 *  other grantees under their original terms, optionally send a gift-wrapped
 *  441 notice, and record revoked + rotated events in the ledger. */
async function revoke(d, msg) {
  const entry = (state.index.issued ?? []).find(e => e.scope === d.scope)
  if (!entry) { msg.textContent = 'scope not in the index — cannot rotate'; return }
  const others = (entry.grantees ?? []).filter(p => p !== d.agent).length
  if (!confirm(`Revoke “${d.scopeName}” from ${agentName(d.agent)}?\n\n` +
    `The scope key rotates${others ? ` and the ${others} other grantee${others === 1 ? ' is' : 's are'} re-granted under their original terms` : ''}. ` +
    `The agent keeps whatever it already read — that is physics, and a compliant no_persist runtime has kept nothing — but its next dereference fails to decrypt.`)) return
  const reason = window.prompt(
    'Optional revocation notice (kind 441, gift-wrapped to the agent — the relay never sees it).\n\n' +
    'Leave empty or cancel to revoke silently.', '')

  msg.textContent = 'rotating key + re-granting survivors…'
  try {
    await rotateDropping(state.relay, state.signer, state.index, {
      scope: d.scope, drop: [d.agent], relayHint: RELAYS[0],
      makeEvents: ({ from_v, to_v, survivors }) => [
        revokedEvent({ scope: d.scope, agent: d.agent, v: from_v, reason, notice: !!reason }),
        rotatedEvent({ scope: d.scope, from_v, to_v, survivors }),
      ],
    })
    if (reason) {
      msg.textContent = 'sending 441 notice…'
      await sendRevocationNotice(state.relay, state.signer, d.agent, { scopeId: d.scope, reason })
    }
    await load()
  } catch (err) { msg.textContent = err.message }
}
