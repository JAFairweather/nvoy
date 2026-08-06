// ledger.mjs — THE screen (spec §6.4.4): the live answer to "exactly what
// data do my agents hold right now, under what terms — and show me the
// revocations". Every row derives from the Grant Index + nvoy_ledger event
// log, so the whole view reconstitutes from the delegator's nsec alone.
// M4 additions: relinquish one-tap confirms (§6.6, decision 6), the agent
// "outputs" surface (§6.5 — reply scopes dereferenced live, never stored),
// and the honest TTL banner (§6.4.3 — hard expiry runs while this is open).
// Revoke-now (§6.4.5) shares the rotation spine in ttl.mjs.

import { saveGrantIndex } from '../lib/nipxx.mjs'
import { sendRevocationNotice, grantWithTerms } from './nvoygrant.mjs'
import { revokedEvent, rotatedEvent, grantedEvent, appendLedger, eventsFor, computeTotals, fmtCountdown, receivedActions } from './ledgerlog.mjs'
import { rotateDropping, runRelinquishRotation, nextExpiry } from './ttl.mjs'
import { state, $, esc, short, fmtWhen, agentName, agentsOf, load, RELAYS, showTab } from './main.mjs'
import { buildExternalRevocation } from './capgrants.mjs'
import { childrenOf, coverageNote, unrenderedLineage, parentKey } from './lineage.mjs'
import { settleAgentOutputs } from './output-state.mjs'
import { bucketGrantees, granteeKind, KIND_LABEL, KIND_NOTE } from './grantee-kind.mjs'

// Ledger organization (a grant has three axes — who / what / state).
let groupBy = 'agent'           // primary axis — see GROUP_OPTS
// Filters: Type and Status are MULTI-select (empty set = all); Agent narrows to
// one grantee. Left-nav checkmarks toggle the sets (nvoy#20).
let fTypes = new Set()          // subset of TYPES; empty = all
let fStatuses = new Set()       // subset of STATUSES; empty = all
let fKinds = new Set()          // subset of {'agent','identity'}; empty = all (nvoy#20 grantee kind)
let fAgent = ''                 // '' = all agents, else a grantee hex
let fQuery = ''                 // free text over scope name / grantee / purpose / d-tag
// Which groups are expanded. Empty = ALL COLLAPSED (the default the Director
// asked for). Preserved across re-renders so toggling a filter never collapses
// what you opened.
let openGroups = new Set()
// The two grantee super-sections. Agents open by default, Other identities
// collapsed (the Director's default). Toggles persist across re-renders.
let openSupers = new Set(['agents'])
// A pending "open this delegation" request from the Agents tab. renderLedger
// consumes it: expand its group, scroll it into view (AFTER the tab's hash
// scroll — deferred to a frame, which is the click-through fix), ring it, and
// open its re-grant UI. Fires exactly once.
let pendingFocus = null         // { scope, agent } | null
export function openDelegationInLedger(scope, agent) {
  pendingFocus = { scope, agent }
  // Clear every filter that could hide the target so it's always in the set.
  fQuery = ''; fTypes.clear(); fStatuses.clear(); fKinds.clear(); fAgent = ''
  showTab('ledger')             // renders, then sets location.hash
}

const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s
// A small mark for a grantee that is a registered agent — so agents stand out
// from other identities (npubs that hold a grant but aren't agents). Inline SVG
// so it always renders (a bot/agent glyph: a rounded head with two eyes + antenna).
const AGENT_ICON = '<svg class="lg-grantee-ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-label="agent"><rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 8V4"/><circle cx="12" cy="3" r="1"/><circle cx="9" cy="14" r="1" fill="currentColor" stroke="none"/><circle cx="15" cy="14" r="1" fill="currentColor" stroke="none"/></svg>'
// …and a person glyph for an identity that isn't an agent (a real npub that
// holds a grant — a contact, a peer). Same size, muted colour (see CSS).
const PERSON_ICON = '<svg class="lg-grantee-ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-label="identity"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
import { scopeKind, TYPES } from './scope-facet.mjs'

const STATUSES = ['active', 'expired', 'revoked', 'relinquished']
const STATUS_RANK = { active: 0, expired: 1, relinquished: 2, revoked: 3 }
// The primary grouping axis. 'scope' groups all grantees of one credential under
// it — the clearest view of a delegation's fan-out (re-grants chained to a root).
const GROUP_OPTS = [['agent', 'Grantee'], ['scope', 'Credential'], ['type', 'Type'], ['status', 'Status']]

const LEDGER_STYLE = `<style>
/* two-column: a sticky filter rail on the left, the grouped ledger on the right */
#ledger .lg-wrap{display:grid;grid-template-columns:184px 1fr;gap:22px;align-items:start}
@media (max-width:720px){#ledger .lg-wrap{grid-template-columns:1fr}}
#ledger .lg-nav{position:sticky;top:12px;display:flex;flex-direction:column;gap:16px}
#ledger .lg-nav-sect{display:flex;flex-direction:column;gap:3px}
#ledger .lg-nav-h{font-size:10.5px;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);margin:0 0 4px 2px}
#ledger .lg-nav select{width:100%;font-family:var(--mono);font-size:12px;padding:5px 8px;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--text)}
/* a checkmark row — Type / Status / Group-by all use it */
#ledger .lg-check{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:12.5px;padding:4px 7px;border-radius:7px;border:1px solid transparent;background:transparent;color:var(--dim);cursor:pointer;text-align:left;text-transform:capitalize}
#ledger .lg-check:hover{color:var(--text);background:color-mix(in srgb,var(--panel-2) 60%,transparent)}
#ledger .lg-check.on{color:var(--text)}
#ledger .lg-box{flex:none;width:15px;height:15px;border-radius:4px;border:1.5px solid var(--line);display:inline-grid;place-items:center;font-size:11px;line-height:1;color:var(--accent-ink)}
#ledger .lg-check.on .lg-box{background:var(--accent);border-color:var(--accent)}
#ledger .lg-check .lg-box::after{content:'';}
#ledger .lg-check.on .lg-box::after{content:'✓'}
/* group-by is single-select: a filled dot instead of a check */
#ledger .lg-check.radio .lg-box{border-radius:50%}
#ledger .lg-check.radio.on .lg-box::after{content:'';width:7px;height:7px;border-radius:50%;background:var(--accent-ink)}
#ledger .lg-nav-clear{font-size:11px;color:var(--accent);cursor:pointer;margin-top:2px}
#ledger .lhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
#ledger .lg-search{font-family:var(--mono);font-size:12px;padding:5px 12px;border-radius:999px;border:1px solid var(--line);background:transparent;color:var(--text);min-width:230px;flex:1;outline:none}
#ledger .lg-search:focus{border-color:var(--accent)}
/* focus ring when a delegation is opened from another tab (nvoy#17) */
#ledger .card.lg-focused{outline:2px solid var(--accent);outline-offset:2px;animation:lgfocus 2.6s ease-out}
@keyframes lgfocus{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--accent) 55%,transparent)}60%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
#ledger .lg-search::placeholder{color:var(--dim)}
/* group = a lineage container */
#ledger .lg-group{margin:0 0 16px;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:color-mix(in srgb,var(--panel) 55%,transparent)}
#ledger .lg-group>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;padding:12px 16px;background:color-mix(in srgb,var(--panel-2) 65%,transparent);user-select:none;border-bottom:1px solid transparent}
#ledger .lg-group[open]>summary{border-bottom-color:var(--line)}
#ledger .lg-group>summary::-webkit-details-marker{display:none}
#ledger .lg-group>summary::before{content:'▸';color:var(--dim);font-size:12px;transition:transform .12s;flex:none;width:10px}
#ledger .lg-group[open]>summary::before{transform:rotate(90deg)}
#ledger .lg-gname{font-family:var(--serif);font-weight:600;font-size:16px;color:var(--text);display:inline-flex;align-items:center;gap:7px}
/* grantee super-sections (Agents / Other identities) */
#ledger .lg-super{margin:0 0 18px}
#ledger .lg-super>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;padding:6px 2px 10px;user-select:none}
#ledger .lg-super>summary::-webkit-details-marker{display:none}
#ledger .lg-super>summary::before{content:'▾';color:var(--dim);font-size:12px;transition:transform .12s;flex:none;width:12px}
#ledger .lg-super:not([open])>summary::before{transform:rotate(-90deg)}
#ledger .lg-super-name{font-size:11px;text-transform:uppercase;letter-spacing:.11em;color:var(--accent);font-weight:700}
#ledger .lg-super-count{font-family:var(--mono);font-size:11.5px;color:var(--dim)}
#ledger .lg-super-body{padding-left:2px}
#ledger .lg-super-note{margin:2px 2px 12px;line-height:1.55;max-width:70ch}
#ledger .lg-super-bar{height:1px;background:linear-gradient(to right,var(--line),transparent);margin:2px 0 18px}
/* grantee avatar in the group header */
#ledger .lg-avatar{width:22px;height:22px;border-radius:6px;flex:none;object-fit:cover;background:#0b0906}
#ledger .lg-avatar.mono{display:inline-grid;place-items:center;background:#1a140c;color:#c39a56;font-weight:600;font-size:11px}
#ledger .lg-grantee-badge{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:6px;flex:none}
#ledger .lg-grantee-badge.agent{color:var(--gold-bright,var(--accent));background:color-mix(in srgb,var(--accent) 15%,transparent);border:1px solid color-mix(in srgb,var(--accent) 40%,transparent)}
#ledger .lg-grantee-badge.identity{color:var(--dim);background:color-mix(in srgb,var(--dim) 12%,transparent);border:1px solid color-mix(in srgb,var(--dim) 35%,transparent)}
#ledger .lg-grantee-ic{display:block}
#ledger .lg-gcount{font-family:var(--mono);font-size:11.5px;color:var(--dim)}
#ledger .lg-pips{display:inline-flex;gap:3px;margin-left:auto}
#ledger .lg-pip{width:7px;height:7px;border-radius:50%;flex:none}
#ledger .lg-pip.active{background:var(--ok)}
#ledger .lg-pip.expired{background:var(--warn)}
#ledger .lg-pip.revoked{background:var(--danger)}
#ledger .lg-pip.relinquished{background:var(--accent)}
/* the chain: a rail with status nodes, one per grant */
#ledger .lg-chain{position:relative;padding:12px 14px 12px 34px}
#ledger .lg-chain::before{content:'';position:absolute;left:15px;top:6px;bottom:14px;width:2px;background:linear-gradient(to bottom,var(--line),color-mix(in srgb,var(--line) 20%,transparent));border-radius:2px}
#ledger .lg-chain .card{position:relative;margin:0 0 10px;border-radius:10px;border:1px solid var(--line);border-left-width:3px}
#ledger .lg-chain .card:last-child{margin-bottom:0}
#ledger .lg-chain .card::before{content:'';position:absolute;left:-24px;top:16px;width:12px;height:12px;border-radius:50%;background:var(--bg);border:2px solid var(--dim);z-index:1}
#ledger .lg-chain .card::after{content:'';position:absolute;left:-13px;top:21px;width:13px;height:2px;background:var(--line)}
/* status colour: left stripe + node */
#ledger .card.st-active{border-left-color:var(--ok)}
#ledger .card.st-active::before{border-color:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 20%,transparent)}
#ledger .card.st-expired{border-left-color:var(--warn)}
#ledger .card.st-expired::before{border-color:var(--warn);box-shadow:0 0 0 3px color-mix(in srgb,var(--warn) 20%,transparent)}
#ledger .card.st-revoked{border-left-color:var(--danger)}
#ledger .card.st-revoked::before{border-color:var(--danger)}
#ledger .card.st-relinquished{border-left-color:var(--accent)}
#ledger .card.st-relinquished::before{border-color:var(--accent)}
/* type icon + grantee monogram + the scope→grantee flow */
#ledger .lg-ic{font-size:14px;margin-right:3px;filter:grayscale(.2)}
#ledger .lg-flow{display:flex;align-items:center;gap:7px;margin-top:8px}
#ledger .lg-arrow{color:var(--dim)}
#ledger .lg-lineage{margin:4px 0 0 2px;display:flex;flex-direction:column;gap:3px}
#ledger .lg-kid{display:flex;align-items:center;gap:7px;font-size:12.5px}
#ledger .lg-kid.dead{opacity:.62}
#ledger .lg-kid.dead .lg-kid-name{text-decoration:line-through}
#ledger .lg-kid-arm{font-family:var(--mono);color:var(--faint)}
#ledger .lg-kid-name{font-weight:600}
#ledger .lg-coverage{margin-top:5px;max-width:66ch}
#ledger .lg-mono{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:50%;background:color-mix(in srgb,var(--gold) 16%,transparent);border:1px solid color-mix(in srgb,var(--gold) 45%,transparent);color:var(--gold-bright);font-family:var(--mono);font-size:11px;font-weight:700;flex:none}
/* onward = children whose parent is a grant this key HOLDS, so it has no card above */
#ledger .lg-onward{margin-top:14px;border:1px solid var(--line);border-radius:10px;background:var(--panel-2,var(--panel));padding:10px 12px}
#ledger .lg-onward-h{font-size:12px;font-weight:600;color:var(--text)}
#ledger .lg-onward-p{margin:6px 0 10px;font-size:12px;color:var(--muted);line-height:1.5}
#ledger .lg-onward-parent{padding:8px 0;border-top:1px solid var(--line)}
#ledger .lg-onward-parent:first-of-type{border-top:0}
</style>`

const termChips = (t) => !t ? '<span class="chip warn" title="granted without an nvoy terms object — a vanilla NIP-DA grant">vanilla grant · no terms</span>' : [
  t.no_persist ? '<span class="chip term" title="runtime serves this to model context only — no disk, no logs">no_persist</span>' : '',
  t.redelegate === false ? '<span class="chip term" title="audit term: runtime refuses to re-wrap keys for third parties">no redelegate</span>' : '',
  t.redelegate === true ? '<span class="chip warn" title="you allowed the holder to derive attenuated children from this grant. Their derivations are recorded on THEIR own encrypted index, so any descendants are not visible in this ledger — publishing that chain would link you to every leaf.">redelegate allowed</span>' : '',
  t.reply_scope_requested ? '<span class="chip term" title="agent grants results back via its outbox (§6.5) — see the output panel below">reply requested</span>' : '',
  t.auto_relinquish ? '<span class="chip term" title="agent destroys key + cache on completion / at expiry (§6.6)">auto-relinquish</span>' : '',
].filter(Boolean).join('')

/** One attenuation chain, rendered identically wherever its parent turns out to live. */
const kidList = (kids) => `<div class="lg-lineage">${kids.map(k => {
  const dead = k.state === 'revoked'
  return `<div class="lg-kid${dead ? ' dead' : ''}">
    <span class="lg-kid-arm">└─</span>
    <span class="lg-kid-name">${esc(k.child.scope_name || k.child.scope)}</span>
    <span class="chip scope-${dead ? 'revoked' : 'active'}">${dead ? 'severed' : 'active'}</span>
    <span class="msg">→ ${esc(short(k.child.grantee))} · v${k.child.generation}${
      dead && k.revoked_at ? ` · severed ${esc(fmtWhen(k.revoked_at))}` : ''}</span>
  </div>`
}).join('')}</div>`

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
  // External grants (read off the relays from another app — a waggle admit, a future app's
  // capability) get a COMPACT card of their own. They are not in Nvoy's scope index, have no scope
  // key, no TTL, no outputs — so none of the machinery below applies. Rendering them here, isolated,
  // is what keeps the full Nvoy card path untouched while still showing every grant on one plane.
  if (d.external) {
    const gname = agentName(d.agent) || short(d.agent)
    const canRevoke = d.status === 'active'
    return `<div class="card st-${d.status} kind-external" data-i="${i}" data-scope="${esc(d.scope)}" data-agent="${esc(d.agent)}">
      <div class="head">
        <div>
          <span class="lg-ic" title="external capability grant">🔗</span>
          <span class="name">${esc(d.scopeName)}</span>
          <span class="badge ${d.status}">${d.status}</span>
          <span class="meta" title="issued by another app in the NIP-DA family and read from the relays — not an Nvoy scope">external</span>
        </div>
        <div style="display:flex;align-items:center;gap:10px">
          <span class="meta" title="the 440 event id this grant is">${esc(short(d.scope))}</span>
          ${canRevoke ? '<button class="danger revoke">Revoke now</button>' : ''}
        </div>
      </div>
      <div class="note lg-flow"><span class="lg-arrow">granted to</span>
        <b style="color:var(--text)">${esc(gname)}</b> <span class="meta">${esc(short(d.agent))}</span></div>
      <div class="chips">
        ${d.purpose ? `<span class="chip" title="the capability this grant conveys">${esc(d.purpose)}</span>` : ''}
        ${d.scopeHash ? `<span class="chip" title="what this grant is OVER (a channel, an agent, …) is a salted hash chosen by the issuing app. It is private by design — resolvable only by someone who already knows the subject — so Nvoy shows it hashed rather than coupling itself to any one app's scheme.">🔒 subject: ${esc(d.scopeHash.slice(0, 10))}… (app-private)</span>` : ''}
      </div>
    </div>`
  }
  const events = eventsFor(state.index, d.scope, d.agent)
  const soon = d.expiresAt !== null && d.expiresAt - Math.floor(Date.now() / 1000) < 24 * 3600
  // 'expired' can mean lapsed-but-still-holding (sweep imminent) OR already
  // dropped by an expiry rotation — only a holder has anything to revoke.
  const held = !!(state.index.issued ?? []).find(e => e.scope === d.scope)?.grantees?.includes(d.agent)
  const pendingRel = state.pendingRelinquish.find(x => x.scope === d.scope && x.agent === d.agent)
  // Outputs outlive the input delegation deliberately (§6.5): you can revoke
  // a misbehaving agent's INPUT while retaining its output history.
  const wantsOutput = !!d.terms?.reply_scope_requested || state.received.some(g => g.publisher === d.agent)
  const kind = scopeKind(d)
  const icon = kind === 'credential' ? '🔑' : kind === 'admission' ? '🚪'
    : kind === 'action' ? '✋' : kind === 'unnamespaced' ? '❔' : '📄'
  const gname = agentName(d.agent) || short(d.agent)
  const mono = esc(((gname || '?').trim()[0] || '?').toUpperCase())
  return `<div class="card st-${d.status} kind-${kind}" data-i="${i}" data-scope="${esc(d.scope)}" data-agent="${esc(d.agent)}">
    <div class="head">
      <div>
        <span class="lg-ic" title="${kind}">${icon}</span>
        <span class="name">${esc(d.scopeName)}</span>
        <span class="badge ${d.status}">${d.status}</span>
        ${d.v !== null ? `<span class="meta" title="scope key generation">v${d.v}</span>` : ''}
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <span class="meta" title="opaque scope id (the d tag)">${esc(d.scope)}</span>
        ${held ? '<button class="danger revoke">Revoke now</button>' : ''}
      </div>
    </div>
    <div class="note lg-flow"><span class="lg-arrow">granted to</span> <span class="lg-mono">${mono}</span> <b style="color:var(--text)">${esc(gname)}</b>
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
    ${(() => {
      // What THIS key granted onward from this scope. Readable only because the rows are on our
      // own index; an agent's derivations from the same scope are encrypted to the agent and are
      // deliberately unavailable here (see lineage.mjs).
      const kids = childrenOf(state.index, d.scope, state.me)
      const note = coverageNote(d, state.index, state.me)
      if (!kids.length && !note) return ''
      return `<div class="sect2">granted onward (attenuated children you issued)</div>` +
        (kids.length ? kidList(kids) : '') +
        (note ? `<div class="msg lg-coverage">${esc(note)}</div>` : '')
    })()}
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

export function renderLedger() {
  const all = state.delegations
  // FOUR kinds of grantee, not two. The old split asked only "is this in nvoy_agents?", which put a
  // community member holding a waggle admission, an unregistered agent runtime, and the DIRECTOR HIMSELF
  // under one heading — three different facts, so the heading meant nothing. See grantee-kind.mjs for
  // the two judgement calls behind the split.
  const agentPubs = new Set((state.index.nvoy_agents ?? []).map(a => a.pub))
  const kindOpts = { me: state.me, registered: agentPubs, rows: all }
  const isAgent = pub => granteeKind(pub, kindOpts) === 'agent'
  const t = computeTotals(all, state.index.nvoy_ledger ?? [], undefined, agentPubs)
  const next = nextExpiry(state.index)

  // Lineage rows whose parent has no card above, and therefore no home in the grouped list.
  //
  // A card in `all` is an issued grant, so it can only ever host children whose parent publisher
  // is THIS key. The first hop of a chain — this key deriving from a grant it HOLDS — carries the
  // upstream delegator as `parent.publisher`, so it matches no card and would vanish. Computed
  // against the UNFILTERED `all` on purpose: whether a row has a parent card is a fact about the
  // index, not about the filter rail, and a disclosure that flickered with the filters would be
  // worse than none.
  const onward = unrenderedLineage(state.index, new Set(all.map(d => parentKey(state.me, d.scope))))
  // Name the held parent from the grants readable this session. A miss is reported, never guessed.
  const heldParent = (g) => state.received.find(r => r.publisher === g.publisher && r.scopeId === g.scope) || null

  // Multi-select filters (empty set = all) + agent + free-text; then group.
  const q = fQuery.trim().toLowerCase()
  const rows = all.filter(d =>
    (fTypes.size === 0 || fTypes.has(scopeKind(d))) &&
    (fStatuses.size === 0 || fStatuses.has(d.status)) &&
    (fKinds.size === 0 || fKinds.has(isAgent(d.agent) ? 'agent' : 'identity')) &&
    (!fAgent || d.agent === fAgent) &&
    (!q || `${d.scopeName || ''} ${agentName(d.agent) || ''} ${d.purpose || ''} ${d.scope || ''} ${d.status || ''}`
      .toLowerCase().includes(q)))

  const keyOf = d => groupBy === 'type' ? scopeKind(d) : groupBy === 'status' ? d.status : groupBy === 'scope' ? d.scope : d.agent
  const labelOf = k => groupBy === 'agent' ? agentName(k)
    : groupBy === 'scope' ? (rows.find(d => d.scope === k)?.scopeName || k)
    : cap(k)
  const groups = new Map()
  rows.forEach((d, i) => {                       // i = flat index into `rows` → card wiring stays valid
    const k = keyOf(d)
    if (!groups.has(k)) groups.set(k, [])
    groups.get(k).push({ d, i })
  })
  for (const g of groups.values()) g.sort((a, b) => (b.d.grantedAt ?? 0) - (a.d.grantedAt ?? 0)) // reverse-chron within group
  const groupKeys = [...groups.keys()].sort((a, b) =>
    groupBy === 'status'
      ? (STATUS_RANK[a] ?? 9) - (STATUS_RANK[b] ?? 9)   // canonical status order
      : groups.get(b).length - groups.get(a).length)    // else biggest group first

  // Distinct grantees, for the Agent filter — labelled, agents first, then by name.
  const agentList = [...new Set(all.map(d => d.agent))]
    .map(pub => ({ pub, name: agentName(pub) || short(pub), agent: isAgent(pub) }))
    .sort((x, y) => (y.agent - x.agent) || x.name.localeCompare(y.name))
  const filtered = fTypes.size || fStatuses.size || fKinds.size || fAgent || q

  // A checkmark row (Type/Status = checkbox multi-select; Group-by = radio).
  const check = (label, on, attr, radio) =>
    `<button class="lg-check${on ? ' on' : ''}${radio ? ' radio' : ''}" ${attr}><span class="lg-box"></span>${esc(label)}</button>`

  // Grantee avatar (profile pic → gold monogram) for the group header when
  // grouped by grantee. loadProfiles already fetches kind-0 for every grantee.
  const avatarFor = (pub) => {
    const p = state.profiles.get(pub)
    const initial = esc(((agentName(pub) || short(pub) || '?').trim()[0] || '?').toUpperCase())
    return p?.picture
      ? `<img class="lg-avatar" src="${esc(p.picture)}" alt="" width="22" height="22" loading="lazy">`
      : `<span class="lg-avatar mono">${initial}</span>`
  }

  // One grantee group (a collapsible <details>). Header order when grouped by
  // grantee: [kind icon] [profile pic] [name]. Card wiring keys off the flat
  // `i`, so nesting these inside super-sections is safe.
  const groupHtml = (k) => {
    const items = groups.get(k)
    const activeN = items.filter(x => x.d.status === 'active').length
    const byStatus = {}; for (const x of items) byStatus[x.d.status] = (byStatus[x.d.status] || 0) + 1
    const pips = STATUSES.filter(s => byStatus[s]).map(s => `<span class="lg-pip ${s}" title="${byStatus[s]} ${s}"></span>`).join('')
    const mark = groupBy === 'agent'
      ? (isAgent(k)
          ? `<span class="lg-grantee-badge agent" title="registered agent">${AGENT_ICON}</span>`
          : `<span class="lg-grantee-badge identity" title="identity — holds a grant but is not an agent">${PERSON_ICON}</span>`)
        + avatarFor(k)
      : ''
    return `<details class="lg-group" data-gkey="${esc(String(k))}"${openGroups.has(k) ? ' open' : ''}>
      <summary><span class="lg-gname">${mark}${esc(labelOf(k))}</span>
        <span class="lg-gcount">${items.length} grant${items.length === 1 ? '' : 's'}${activeN !== items.length ? ` · ${activeN} active` : ''}</span>
        <span class="lg-pips">${pips}</span></summary>
      <div class="lg-chain">${items.map(({ d, i }) => delegationCard(d, i)).join('')}</div>
    </details>`
  }

  // A super-section wrapping the grantee groups of one kind. `id` ∈
  // {'agents','identities'}; open state persists in openSupers (agents open,
  // identities collapsed by default — seeded at the module level).
  const superHtml = (id, label, keys, grantN, gh) =>
    `<details class="lg-super" data-super="${id}"${openSupers.has(id) ? ' open' : ''}>
      <summary><span class="lg-super-name">${esc(label)}</span>
        <span class="lg-super-count">${keys.length} grantee${keys.length === 1 ? '' : 's'} · ${grantN} grant${grantN === 1 ? '' : 's'}</span></summary>
      <div class="lg-super-body">${keys.map(gh).join('')}</div>
    </details>`

  $('ledger').innerHTML = `${LEDGER_STYLE}
    <div class="lg-wrap">
      <aside class="lg-nav">
        <div class="lg-nav-sect">
          <div class="lg-nav-h">Group by</div>
          ${GROUP_OPTS.map(([g, lbl]) => check(lbl, groupBy === g, `data-group="${g}"`, true)).join('')}
        </div>
        <div class="lg-nav-sect">
          <div class="lg-nav-h">Narrow to one grantee</div>
          <select id="lg-agent" title="filter to one grantee — agents and other identities are separated">
            <option value="">all grantees</option>
            ${(() => {
              const opt = a => `<option value="${a.pub}"${a.pub === fAgent ? ' selected' : ''}>${esc(a.name)}</option>`
              const agents = agentList.filter(a => a.agent), identities = agentList.filter(a => !a.agent)
              return (agents.length ? `<optgroup label="Agents">${agents.map(opt).join('')}</optgroup>` : '')
                + (identities.length ? `<optgroup label="Other identities">${identities.map(opt).join('')}</optgroup>` : '')
            })()}
          </select>
        </div>
        <div class="lg-nav-sect">
          <div class="lg-nav-h">Type</div>
          ${TYPES.map(x => check(x, fTypes.has(x), `data-type="${x}"`)).join('')}
        </div>
        <div class="lg-nav-sect">
          <div class="lg-nav-h">Status</div>
          ${STATUSES.map(x => check(x, fStatuses.has(x), `data-status="${x}"`)).join('')}
        </div>
        <div class="lg-nav-sect">
          <div class="lg-nav-h">Grantee kind</div>
          ${check('agents', fKinds.has('agent'), 'data-kind="agent"')}
          ${check('other identities', fKinds.has('identity'), 'data-kind="identity"')}
        </div>
        ${filtered ? `<a class="lg-nav-clear" id="lg-clear-nav">clear filters</a>` : ''}
      </aside>

      <div class="lg-main">
        <div class="lhead">
          <span class="totals"><b>${t.active}</b> active delegation${t.active === 1 ? '' : 's'}
            to <b>${t.agents}</b> agent${t.agents === 1 ? '' : 's'}${t.identities ? ` and <b>${t.identities}</b> other identit${t.identities === 1 ? 'y' : 'ies'}` : ''},
            <b>${t.revokedThisMonth}</b> revoked this month</span>
          <input class="lg-search" id="lg-search" type="search" placeholder="search scope / grantee / purpose / id…"
            value="${esc(fQuery)}" spellcheck="false" autocomplete="off">
          ${filtered ? `<span class="lg-gcount">${rows.length} shown</span>` : ''}
        </div>
        ${all.some(d => d.expiresAt !== null && (d.status === 'active' || d.status === 'expired')) ? `<div class="ttlnote">
          Hard expiry runs <b>while this console is open</b>: at each deadline the scope key is rotated and only
          unexpired grantees are re-granted${next ? ` (next: ${fmtCountdown(next).replace('expires', 'fires')})` : ''}.
          Console closed = soft expiry only — compliant runtimes stop serving at the deadline, and the sweep
          completes on your next visit. To cover the gap without the browser, run the operator daemon
          (<code>node bin/nvoy-ttl.mjs</code>, holds your nsec — documented in its header); a hosted scheduler is future work.</div>` : ''}
        ${groupKeys.length ? (groupBy === 'agent'
          // Grantee grouping: two collapsible super-sections — Agents (open by
          // default) above Other identities (collapsed), with a divider between.
          ? (() => {
              const total = ks => ks.reduce((n, k) => n + groups.get(k).length, 0)
              const buckets = bucketGrantees(groupKeys, kindOpts)
              // Each heading carries the sentence it owes the reader. `unregistered` is the only one that
              // names a defect, and it says whose defect it is: issuing a grant does not register its
              // grantee, so nothing reading the registry knows these keys exist.
              return [...buckets].map(([kind, keys], i) =>
                (i ? '<div class="lg-super-bar"></div>' : '')
                + superHtml(kind, KIND_LABEL[kind], keys, total(keys), groupHtml, KIND_NOTE[kind])
              ).join('')
            })()
          : groupKeys.map(groupHtml).join('')
        ) : `<div class="empty">
          ${filtered
            ? `Nothing matches these filters. <a id="lg-clear" style="color:var(--accent);cursor:pointer">Clear</a>`
            : `Nothing delegated yet.<br>
          The ledger is the audit view: every delegation, its terms, every rotation and revocation —
          a query over your encrypted Grant Index, not archaeology across admin panels.`}</div>`}
        ${(() => {
          // WHAT THIS KEY DID WITH GRANTS IT RECEIVED. Nothing else on this screen shows the inbound
          // direction: `deriveDelegations` answers "what did I grant", so a draft an agent granted TO
          // the Director had no card and no row. Ngage recorded it in localStorage only, which made
          // half of that desk invisible in the console that claims to be the source of truth for all
          // grants — invisible BY CONSTRUCTION, the same class of defect as the agent that showed in
          // Nvoy and not in Nact.
          const { rows: acted, dropped: actedDropped } = receivedActions(state.index)
          if (!acted.length && !actedDropped) return ''
          return `<div class="lg-onward">
            <div class="lg-onward-h">what you did with grants you received</div>
            <div class="lg-onward-p">These are not delegations you issued — an agent granted them to
              <b>you</b>, and you acted in your own hand. Kept separate for that reason: a received draft
              listed among your delegations would read as though you had delegated something.
              ${actedDropped ? `<b>${actedDropped} record${actedDropped === 1 ? '' : 's'} could not be read
                and ${actedDropped === 1 ? 'is' : 'are'} not shown.</b>` : ''}</div>
            ${acted.map(r => `<div class="lg-onward-parent">
              <div class="note lg-flow">
                <span class="lg-arrow">${r.outcome === 'posted' ? 'posted in your hand' : 'passed'}</span>
                <b style="color:var(--text)">${esc(r.name)}</b>
                <span class="meta" title="the agent that granted this to you">${esc(short(r.publisher))}</span>
                ${r.at ? `<span class="meta">${esc(fmtWhen(r.at))}</span>` : ''}
              </div>
              ${r.outcome === 'posted' && r.noteId
                ? `<div class="msg">published as ${esc(String(r.noteId).slice(0, 16))}… — signed by you, not by the agent.</div>`
                : r.outcome === 'passed'
                  ? '<div class="msg">You declined it. The grant was real; nothing was signed.</div>' : ''}
            </div>`).join('')}
          </div>`
        })()}
        ${onward.length ? `<div class="lg-onward">
          <div class="lg-onward-h">granted onward from grants you hold</div>
          <div class="lg-onward-p">You derived ${onward.reduce((n, g) => n + g.children.length, 0)}
            attenuated grant${onward.reduce((n, g) => n + g.children.length, 0) === 1 ? '' : 's'} from
            ${onward.length} grant${onward.length === 1 ? '' : 's'} <b>issued to you by someone else</b>.
            Those parents are not delegations you made, so they have no card above — but the children are
            recorded on your own index and are yours to answer for.</div>
          ${onward.map(g => {
            const p = heldParent(g)
            return `<div class="lg-onward-parent">
              <div class="note lg-flow"><span class="lg-arrow">from</span>
                <b style="color:var(--text)">${esc(p?.scopeName || g.scope)}</b>
                <span class="meta" title="the parent grant's publisher — the delegator who granted it to you">${esc(short(g.publisher))}</span>
                ${g.generation !== null ? `<span class="meta" title="parent scope key generation at derivation">v${g.generation}</span>` : ''}</div>
              ${p ? '' : `<div class="msg">The parent grant is not among the grants readable in this session —
                it may have been rotated or revoked since you derived from it. The children below are still
                recorded on your index; this is not a claim that the parent is gone.</div>`}
              ${kidList(g.children)}
            </div>`
          }).join('')}
        </div>` : ''}
      </div>
    </div>`

  // Left-nav filters. Group-by is single-select (radio); Type/Status toggle in
  // and out of their Set (multi-select); Agent is a select.
  const toggle = (set, v) => { set.has(v) ? set.delete(v) : set.add(v); renderLedger() }
  for (const b of document.querySelectorAll('#ledger .lg-check')) b.onclick = () => {
    if (b.dataset.group) { groupBy = b.dataset.group; renderLedger() }
    else if (b.dataset.type) toggle(fTypes, b.dataset.type)
    else if (b.dataset.status) toggle(fStatuses, b.dataset.status)
    else if (b.dataset.kind) toggle(fKinds, b.dataset.kind)
  }
  const ag = $('lg-agent'); if (ag) ag.onchange = (e) => { fAgent = e.target.value; renderLedger() }
  // Track expand/collapse so a filter change never collapses what you opened.
  for (const det of document.querySelectorAll('#ledger .lg-group')) det.addEventListener('toggle', () => {
    const k = det.dataset.gkey
    det.open ? openGroups.add(k) : openGroups.delete(k)
  })
  for (const det of document.querySelectorAll('#ledger .lg-super')) det.addEventListener('toggle', () => {
    det.open ? openSupers.add(det.dataset.super) : openSupers.delete(det.dataset.super)
  })
  // Live search: the whole tab re-renders per keystroke (house pattern), so
  // restore focus + caret into the fresh input or typing would drop after one
  // character.
  const srch = $('lg-search')
  if (srch) srch.oninput = () => {
    fQuery = srch.value
    const pos = srch.selectionStart
    renderLedger()
    const s2 = $('lg-search')
    if (s2) { s2.focus(); try { s2.setSelectionRange(pos, pos) } catch {} }
  }
  const clrAll = () => { fTypes.clear(); fStatuses.clear(); fKinds.clear(); fAgent = ''; fQuery = ''; renderLedger() }
  const clr = $('lg-clear'); if (clr) clr.onclick = clrAll
  const clrNav = $('lg-clear-nav'); if (clrNav) clrNav.onclick = clrAll

  for (const card of document.querySelectorAll('#ledger .card')) {
    const d = rows[Number(card.dataset.i)]
    const msg = card.querySelector('.lg-msg')
    const btn = card.querySelector('.revoke')
    if (btn) btn.onclick = () => revoke(d, msg)
    const rel = card.querySelector('.rel-confirm')
    if (rel) rel.onclick = () => confirmRelinquish(d, msg)
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
  void settleAgentOutputs($('ledger'), { relay: state.relay, grants: state.received, formatWhen: fmtWhen })

  // Consume a pending "open this delegation" from the Agents tab (nvoy#17/#20).
  // The scroll is DEFERRED to a frame: showTab() calls renderLedger() and THEN
  // sets location.hash='ledger', which the browser scrolls to (the ledger top).
  // Running our scrollIntoView on the next frame lets it win — that lands us on
  // the delegation instead of the top of the page (the reported bug).
  if (pendingFocus) {
    const { scope, agent } = pendingFocus
    pendingFocus = null
    const card = [...document.querySelectorAll('#ledger .card')]
      .find(c => c.dataset.scope === scope && c.dataset.agent === agent)
    if (card) {
      const det = card.closest('details')
      if (det) { det.open = true; openGroups.add(det.dataset.gkey) }   // expand its (default-collapsed) group
      card.querySelector('.addg')?.click()   // surface ＋ grant to another identity
      card.classList.add('lg-focused')
      setTimeout(() => card.classList.remove('lg-focused'), 2600)
      requestAnimationFrame(() => requestAnimationFrame(() =>
        card.scrollIntoView({ behavior: 'smooth', block: 'center' })))
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
  // An EXTERNAL grant has no scope key to rotate — it is revoked the way its own app's bridge
  // already honours: a plain, public kind-441 e-tagging the 440. This is the whole "administer from
  // Nvoy" for foreign grants; it signs with the same delegator key, verified before it publishes.
  if (d.external) {
    if (!confirm(`Revoke “${d.scopeName}” from ${agentName(d.agent) || short(d.agent)}?\n\n` +
      `Publishes a public 441 revocation. The grant's own bridge stops honouring it on its next read — ` +
      `no restart anywhere. It cannot be un-published, but you can always issue a new grant.`)) return
    msg.textContent = 'publishing 441 revocation…'
    try {
      const signed = await state.signer.signEvent(buildExternalRevocation(d.capId, Math.floor(Date.now() / 1000)))
      await state.relay.publish(signed)
      msg.textContent = 'revoked — the 441 is on the relays'
      setTimeout(() => load(), 1200)
    } catch (e) { msg.textContent = `revoke failed: ${e.message}` }
    return
  }
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
