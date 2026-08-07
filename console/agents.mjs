// agents.mjs — the agent registry. Agents are contacts with a kind: agent
// flag (spec §6.4.1), stored as the app-level `nvoy_agents` field on the
// delegator's Grant Index (pattern: nvelope_invites — the 10440 payload is
// app-extensible JSON, lib untouched):
//   nvoy_agents: [{ pub, added_at }]
// kind-0 metadata (name / about = the agent's purpose statement) is fetched
// per load for display only — never stored, always current.

import { nip19 } from 'nostr-tools'
import { saveGrantIndex, newScopeKey, publishScope, fetchScope, toIssuedEntry } from '../lib/nipxx.mjs'
import { state, $, esc, short, fmtWhen, load, parsePub, agentsOf, agentName, openAgentPage, RELAYS } from './main.mjs'
import { openDelegationInLedger } from './ledger.mjs'
import { grantWithTerms, rotateWithTerms, opaqueScopeId, sendRevocationNotice } from './nvoygrant.mjs'
import { appendLedger, grantedEvent, rotatedEvent, revokedEvent } from './ledgerlog.mjs'
import {
  REGISTRY_SCOPE, REGISTRY_PROJECTION_FIELD, buildProjection, projectionChanged,
  planProjectionPublish, granteesOf, enrol,
} from './registry.mjs'

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

/**
 * The registry projection panel.
 *
 * A headless slice — the Nactor, the waggle bridge — cannot read this roster: it lives on the
 * Director's kind-10440, NIP-44-encrypted to himself. That is exactly why an agent could exist here
 * and be invisible in Nact, with an ABSENCE as the only symptom. nact#57 made both sides key on the
 * hex pubkey; a join still needs two sets, and this is how the second one gets there.
 *
 * Publishing it is a grant, not an export: revoking a slice's view is then a scope-key rotation, a
 * mechanism that already exists and is already audited (AD-6 — roster content is sensitive and the
 * bridge is off-box, so grant-to-app).
 */
/**
 * The terms the registry read grant carries.
 *
 * `purpose` is the line the Ledger holds you to, so it says what the grant is FOR rather than what it
 * is — a runtime reading this roster is doing one specific job and the Ledger row should say which.
 * `redelegate: false` because a projection is already a copy: a copy of a copy has no generation to
 * rotate and no way to be revoked.
 */
const registryTerms = () => ({
  purpose: 'read your agent registry, so this runtime can say “known only to Nvoy” instead of showing nothing',
  no_persist: true,
  redelegate: false,
  contact: nip19.npubEncode(state.me),
})

/** The issued entry for the projection scope, or null. The key lives here; nothing else holds it. */
function registryIssued() {
  const scopeId = state.index?.[REGISTRY_PROJECTION_FIELD]?.scopeId
  if (!scopeId) return null
  return (state.index.issued ?? []).find(e => e?.scope === scopeId) ?? null
}

function registryPanel() {
  const { payload, dropped } = buildProjection(state.index, { now: Math.floor(Date.now() / 1000) })
  const published = state.index?.[REGISTRY_PROJECTION_FIELD] || null
  const plan = planProjectionPublish(state.index, payload)
  const issued = registryIssued()
  const holders = granteesOf(issued)
  const when = published?.at ? fmtWhen(published.at) : null

  // A holder can only read the generation it was granted. If the issued entry has moved past the
  // recorded publish, some holder is reading an older roster than the one you last signed — which is
  // the projection's own staleness failure, and it must be visible here rather than inferred there.
  const unverified = published && published.verified === false

  const grantable = agentsOf().map(a => a.pub).filter(p => !holders.includes(p))

  return `<div class="card" style="margin-top:18px">
    <div class="sect2">Registry projection — <code>${esc(REGISTRY_SCOPE)}</code></div>
    <div class="msg" style="margin:6px 0 10px">A runtime cannot read this roster: it is encrypted to you.
      Publishing it as a scoped dataset is what lets Nact say <b>“known only to Nvoy”</b> instead of
      showing nothing — an absence nobody can see is the bug the Director reported. Revoking a slice's
      view is then a key rotation, not a new mechanism.</div>
    <div class="chips">
      <span class="chip">${payload.agents.length} agent${payload.agents.length === 1 ? '' : 's'}</span>
      ${dropped ? `<span class="chip warn" title="rows in your registry that are not a valid 64-hex pubkey. They are NOT projected — a slice must not receive a roster quietly shorter than yours without being told.">${dropped} unprojectable</span>` : ''}
      ${published
        ? `<span class="chip" title="the generation a holder must be able to read">v${esc(String(issued?.v ?? published.generation ?? '?'))}</span>
           ${unverified
             ? '<span class="chip warn" title="the relay accepted the 30440 but it did not read back, so no runtime is known to be able to read it. Publish again.">published, but not readable back</span>'
             : plan.action === 'none'
               ? `<span class="chip">published ${esc(when || '')}</span>`
               : '<span class="chip warn">roster changed since publish</span>'}`
        : '<span class="chip warn">never published — no runtime can verify this roster</span>'}
    </div>
    <div class="actions" style="margin-top:10px">
      <button class="primary" id="reg-publish"${plan.action === 'none' ? ` disabled title="${esc(plan.why)}"` : ''}>
        ${published ? 'Republish projection' : 'Publish projection'}</button>
      <span class="msg" id="reg-msg"></span>
    </div>

    ${published ? `<div class="sect2" style="margin-top:16px">Who can read it</div>
      <div class="msg" style="margin:4px 0 8px">A published projection nobody holds is still unreadable —
        publishing and granting are two steps, and only the second one lets a runtime answer.
        ${holders.length ? '' : '<b>No runtime holds this grant, so Nact cannot check any key against your registry yet.</b>'}</div>
      ${holders.map(pub => `<div class="frow reg-holder" data-pub="${esc(pub)}">
          <span>${esc(agentName(pub))} <span class="meta">${esc(short(nip19.npubEncode(pub)))}</span></span>
          <button class="reg-revoke" title="Rotates the scope key and re-grants everyone else. This runtime keeps whatever roster it already read — unavoidable, and honest to say so — and is cut off from every update after this.">Revoke read</button>
        </div>`).join('')}
      <div class="newbar" style="margin-top:10px">
        <select id="reg-grantee"${grantable.length ? '' : ' disabled'}>
          ${grantable.length
            ? grantable.map(p => `<option value="${esc(p)}">${esc(agentName(p))} — ${esc(short(nip19.npubEncode(p)))}</option>`).join('')
            : '<option>every registered agent already holds it</option>'}
        </select>
        <button id="reg-grant"${grantable.length ? '' : ' disabled'}>Grant read</button>
      </div>
      <div class="msg" id="reg-hmsg" style="margin-top:6px"></div>` : ''}

    <div class="msg" style="margin-top:12px">Publishing signs a 30440; republishing rotates its key and
      re-delivers to every holder above. <b>The projection is a copy and can be stale</b>, so it carries
      its own <code>generated_at</code> and a consumer must render that age rather than implying it is
      live.</div>
  </div>`
}

/**
 * Publish the projection for real.
 *
 * THE ORDER HERE IS THE POINT. Sign → record → verify → report, and the verification result is STORED,
 * not just displayed. A relay can accept a 30440 that no relay will then serve back; if that happens,
 * the roster is not readable by anybody and saying "published" would be a fabricated success on the
 * exact surface whose job is to make an invisible absence visible (AD-11).
 *
 * The record is written BEFORE verification because it is bookkeeping of what was signed, and that did
 * happen — losing it would strand the scope key and make the next rotation impossible. What must never
 * be claimed is readability, so `verified` is a stored field and the chip renders it.
 */
function wireRegistryPanel() {
  const btn = $('reg-publish')
  if (!btn) return
  const msg = $('reg-msg')

  btn.onclick = async () => {
    const stop = (why) => { msg.textContent = `nothing changed: ${why}` }
    const now = () => Math.floor(Date.now() / 1000)
    const { payload } = buildProjection(state.index, { now: now() })
    const plan = planProjectionPublish(state.index, payload)
    if (plan.action === 'none' || plan.action === 'blocked') return stop(plan.why)

    btn.disabled = true
    try {
      let scopeId, generation, scopeKey
      if (plan.action === 'publish') {
        // Opaque, like every other scope in the estate: a semantic `d` tag would tell any relay that
        // this pubkey maintains an agent roster and how often it changes. The grantee learns the name
        // from `scope_name` inside its gift-wrapped grant, which is the channel that is actually private.
        scopeId = opaqueScopeId(); generation = 1; scopeKey = newScopeKey()
        msg.textContent = 'publishing the projection (30440)…'
        await publishScope(state.relay, state.signer, { scopeId, generation, scopeKey, payload })
      } else {
        scopeId = plan.scopeId
        msg.textContent = plan.grantees.length
          ? `rotating to v${plan.to} and re-delivering to ${plan.grantees.length} holder(s)…`
          : `rotating to v${plan.to}…`
        const rot = await rotateWithTerms(state.relay, state.signer, {
          scopeId, generation: plan.from, payload, scopeName: REGISTRY_SCOPE,
          survivors: plan.grantees.map(pub => ({ pub, terms: registryTerms() })), relayHint: RELAYS[0],
        })
        generation = rot.generation; scopeKey = rot.scopeKey
      }

      msg.textContent = 'recording in your Grant Index…'
      const others = (state.index.issued ?? []).filter(e => e?.scope !== scopeId)
      state.index.issued = [...others,
        toIssuedEntry({ scopeId, scopeName: REGISTRY_SCOPE, generation, scopeKey }, plan.grantees)]
      state.index[REGISTRY_PROJECTION_FIELD] = {
        scopeId, scopeName: REGISTRY_SCOPE, generation, at: now(), payload, verified: false,
      }
      if (plan.action === 'rotate') {
        state.index.nvoy_ledger = appendLedger(state.index,
          rotatedEvent({ scope: scopeId, from_v: plan.from, to_v: generation, survivors: plan.grantees }))
      }
      await saveGrantIndex(state.relay, state.signer, state.index)

      // Read-back, the house pattern: a relay acknowledgement is not evidence that anyone can read it.
      msg.textContent = 'verifying the projection reads back…'
      const back = await fetchScope(state.relay, { publisher: state.me, scopeId, generation, scopeKey })
      if (back.status === 'ok') {
        state.index[REGISTRY_PROJECTION_FIELD].verified = true
        await saveGrantIndex(state.relay, state.signer, state.index)
        msg.textContent = `published v${generation} — ${payload.agents.length} agent(s), read back and verified.`
          + (plan.grantees.length ? '' : ' No runtime holds it yet — grant read below.')
      } else {
        msg.textContent = `the relay accepted v${generation} but it did not read back (${back.status}), `
          + 'so nothing is claimed as readable. Your scope key is recorded — publish again.'
      }
      await load()
    } catch (err) {
      stop(err.message)
    } finally {
      btn.disabled = false
    }
  }

  wireRegistryHolders()
}

/** Grant and revoke the projection read. Both are the existing mechanisms, on the existing key. */
function wireRegistryHolders() {
  const msg = $('reg-hmsg')
  const grant = $('reg-grant')

  if (grant) grant.onclick = async () => {
    const pub = $('reg-grantee')?.value
    const issued = registryIssued()
    if (!pub) return
    if (!issued) { msg.textContent = 'nothing changed: the projection scope is not in your issued list, so its key cannot be recovered.'; return }
    grant.disabled = true
    try {
      const scopeKey = Uint8Array.from(atob(issued.key), c => c.charCodeAt(0))   // the SAME key — same value, no rotation
      const terms = registryTerms()
      msg.textContent = `granting read to ${agentName(pub)} (v${issued.v}, same value)…`
      await grantWithTerms(state.relay, state.signer, pub, {
        scopeId: issued.scope, generation: issued.v, scopeKey, scopeName: REGISTRY_SCOPE,
        relayHint: RELAYS[0], terms,
      })
      issued.grantees = [...granteesOf(issued), pub]
      state.index.nvoy_ledger = appendLedger(state.index, grantedEvent({
        scope: issued.scope, agent: pub, v: issued.v, terms: { nvoy: 1, ...terms }, name: REGISTRY_SCOPE,
      }))
      await saveGrantIndex(state.relay, state.signer, state.index)
      await load()
    } catch (err) { msg.textContent = `nothing changed: ${err.message}` }
    finally { grant.disabled = false }
  }

  for (const row of document.querySelectorAll('#agents .reg-holder')) {
    const pub = row.dataset.pub
    const btn = row.querySelector('.reg-revoke')
    if (!btn) continue
    btn.onclick = async () => {
      const issued = registryIssued()
      if (!issued) { msg.textContent = 'nothing changed: the projection scope is not in your issued list.'; return }
      btn.disabled = true
      try {
        // Revocation IS the rotation — the claim this panel's own header makes. Survivors are everyone
        // else; the revoked runtime keeps whatever roster it already read and gets nothing after this.
        const survivors = granteesOf(issued).filter(p => p !== pub)
        const from = Number(issued.v)
        msg.textContent = `rotating past ${agentName(pub)} and re-delivering to ${survivors.length} holder(s)…`
        const { payload } = buildProjection(state.index, { now: Math.floor(Date.now() / 1000) })
        const rot = await rotateWithTerms(state.relay, state.signer, {
          scopeId: issued.scope, generation: from, payload, scopeName: REGISTRY_SCOPE,
          survivors: survivors.map(p => ({ pub: p, terms: registryTerms() })), relayHint: RELAYS[0],
        })
        await sendRevocationNotice(state.relay, state.signer, pub, {
          scopeId: issued.scope, reason: 'the registry projection read was revoked',
        })
        issued.v = rot.generation
        issued.key = btoa(String.fromCharCode(...rot.scopeKey))
        issued.grantees = survivors
        const rec = state.index[REGISTRY_PROJECTION_FIELD]
        if (rec) { rec.generation = rot.generation; rec.at = Math.floor(Date.now() / 1000); rec.payload = payload }
        state.index.nvoy_ledger = appendLedger(state.index, revokedEvent({
          scope: issued.scope, agent: pub, v: rot.generation,
          reason: 'the registry projection read was revoked', notice: null,
        }))
        await saveGrantIndex(state.relay, state.signer, state.index)
        await load()
      } catch (err) { msg.textContent = `nothing changed: ${err.message}` }
      finally { btn.disabled = false }
    }
  }
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
      You delegate scopes of data to it; it dereferences them live and loses access when you revoke.</div>`}
    ${registryPanel()}`

  wireRegistryPanel()
  const msg = $('ag-msg')
  $('ag-add').onclick = async () => {
    let pub
    try { pub = parsePub($('ag-npub').value) }
    catch { msg.textContent = 'expected an npub1… or 64-char hex pubkey'; return }
    // One enrolment rule, three doors into it: here, approving a request, and issuing a grant.
    // Each keeps its own wording — the codes exist so they can.
    const enrolled = enrol(state.index, pub, { me: state.me, now: Math.floor(Date.now() / 1000) })
    if (!enrolled.added) {
      msg.textContent = { self: 'that is your own key — agents have their own',
                          duplicate: 'already in the registry',
                          malformed: 'expected an npub1… or 64-char hex pubkey' }[enrolled.reason]
      return
    }
    msg.textContent = 'saving to your Grant Index…'
    try {
      state.index.nvoy_agents = enrolled.agents
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
