// agent-page.mjs — the screen this estate did not have.
//
// The roster was a dead end: clicking an agent did nothing, and its delegation chips punted to
// the Ledger. So the question a Director actually asks — "who is this thing and what does it
// hold?" — had no surface. Eight of the twelve decisions in the refactor spec need the same
// five facts (identity, custody, approval path, what is held, liveness), which is one screen
// referenced eight ways rather than eight screens.
//
// THE HONESTY CONTRACT IS THE LOAD-BEARING PART, not the layout.
//
// This page assembles from up to six stores and most of them are unreachable from this plane:
// Nact's runtime state needs a NIP-98 call to a box, an agent's own derivation ledger is
// encrypted to the agent, a slice's roster lives in the slice. So every section declares where
// its rows came from, in one of three states:
//
//   a count            'from your Grant Index · 4 rows'
//   an affirmative     'nothing here'      — only when the store ANSWERED
//   a skeleton         '<store> did not answer. Nothing is shown because nothing could be
//                       verified — this is not the same as "nothing granted."'
//
// The third is why the component exists. A zero would be a lie (it claims the store said none)
// and a blank would be a shrug (it says nothing about why). AD-11's "disconnected means empty"
// means empty of CLAIMS, not empty of pixels — and as a doctrine it was easy to forget, which
// is why it is imported here rather than remembered.

import { nip19 } from 'nostr-tools'
import { sourceNote } from '../lib/nave-source-note.mjs'
import { capLabel, capLimit } from '../lib/nave-cap.mjs'
import { state, $, esc, short, fmtWhen, agentName, agentsOf, showTab } from './main.mjs'
import { scopeKind } from './scope-facet.mjs'
import { childrenTo, coverageNote } from './lineage.mjs'
import { projectManifest, withheldNote, runtimeState } from './runtime-facts.mjs'
import { openDelegationInLedger } from './ledger.mjs'
import { settleAgentOutputs } from './output-state.mjs'

// Which agent is open. Null = the page is not showing.
let openAgent = null
export const agentPageTarget = () => openAgent

/** Route in: `#agent/<npub>`. The join key IS the deep link (AD-12). */
export function openAgentPage(pub) {
  openAgent = pub
  showTab('agent')
  location.hash = `agent/${nip19.npubEncode(pub)}`
}

/** Parse `#agent/<npub>` on load, so the link lands from any surface. */
export function agentFromHash() {
  const seg = (location.hash || '').replace(/^#/, '').split('/')
  if (seg[0] !== 'agent' || !seg[1]) return null
  try {
    const { type, data } = nip19.decode(seg[1])
    return type === 'npub' ? data : null
  } catch { return null }
}

/** A scope `d` is not a pubkey. `short()` npub-encodes and THROWS on anything that is not 64-hex, so
 *  handing it a named scope like `house-style` takes the whole section down at render. */
const shortId = (s) => { const v = String(s || ''); return v.length > 18 ? `${v.slice(0, 16)}…` : v }

/**
 * @param note   the three-state source stamp; when it carries a `body` the store did not answer, so
 *               its ROWS must not render — that is the honesty contract.
 * @param extra  a sentence about a DIFFERENT store, which therefore survives a silent note. Kept
 *               separate from `body` because collapsing the two is how a skeleton silently swallowed
 *               the one line telling the reader what an admission does and does not prove.
 */
const sect = (title, note, body, actions = '', extra = '') => {
  const cls = note.state === 'silent' ? 'ap-silent' : note.state === 'empty' ? 'ap-empty' : ''
  return `<div class="card ap-sect ${cls}">
    <div class="sect2 ap-head"><span>${esc(title)}</span>
      <span class="ap-stamp ap-${note.state}" title="where these rows came from">${esc(note.stamp)}</span></div>
    ${note.body ? `<div class="msg ap-body">${esc(note.body)}</div>` : body}
    ${extra}
    ${actions ? `<div class="actions" style="margin-top:8px">${actions}</div>` : ''}
  </div>`
}

const grantRow = (d) => {
  const kind = scopeKind(d)
  const icon = kind === 'credential' ? '🔑' : kind === 'admission' ? '🚪' : kind === 'action' ? '✋' : kind === 'unnamespaced' ? '❔' : '📄'
  const cap = d.external && d.purpose ? d.purpose : null
  return `<div class="ap-row">
    <span class="ap-ic">${icon}</span>
    <span class="ap-name">${esc(cap ? capLabel(cap) : (d.scopeName || d.scope))}</span>
    <span class="chip scope-${d.status}">${d.status}</span>
    ${d.v !== null && d.v !== undefined ? `<span class="msg">v${d.v}</span>` : ''}
    ${cap && capLimit(cap) ? `<span class="msg ap-limit">${esc(capLimit(cap))}</span>` : ''}
    ${d.purpose && !cap ? `<span class="msg">“${esc(d.purpose)}”</span>` : ''}
    <button class="ap-open" data-scope="${esc(d.scope)}" data-agent="${esc(d.agent)}"
      title="open this grant in the Ledger">open ↗</button>
  </div>`
}

export function renderAgentPage() {
  const pub = openAgent
  const el = $('agent')
  if (!pub) { el.innerHTML = '<div class="empty">No agent selected.</div>'; return }

  const npub = nip19.npubEncode(pub)
  const profile = state.profiles.get(pub)
  const registered = agentsOf().find(a => a.pub === pub) || null
  const held = state.delegations.filter(d => d.agent === pub)
  const name = agentName(pub) || short(pub)
  const initial = esc(((name || '?').trim()[0] || '?').toUpperCase())

  // Identity. kind-0 is a HINT, not authority: it is fetched live from the agent's own key, so
  // whoever holds that key controls this label in the Director's console. The registry is the
  // authority once AD-12's record lands; until then the honest thing is to mark it unverified.
  const header = `<div class="card ap-id">
    <div class="ap-idrow">
      ${profile?.picture
        ? `<img class="avatar" src="${esc(profile.picture)}" alt="" width="46" height="46" loading="lazy">`
        : `<div class="avatar-mono ap-av">${initial}</div>`}
      <div style="min-width:0">
        <div class="name ap-title">${esc(name)}
          ${registered ? '<span class="badge">agent</span>' : '<span class="chip warn" title="holds a grant but is not in your agent registry — the Ledger calls these other identities">not registered</span>'}
        </div>
        <div class="meta ap-npub">${esc(npub)}</div>
        ${profile?.nip05 ? `<div class="meta">${esc(profile.nip05)}</div>` : ''}
        ${profile?.about ? `<div class="note ap-about">${esc(profile.about)}
          <span class="chip warn" title="read live from this key's own kind-0. Whoever holds the key controls this text, so it is a hint, not a verified name.">kind-0 · unverified</span></div>` : ''}
      </div>
      <div class="ap-since">${registered?.added_at ? `registered ${esc(fmtWhen(registered.added_at))}` : ''}</div>
    </div>
  </div>`

  // ── data + credential grants: this plane's own store, so a real count ────────
  const dataGrants = held.filter(d => ['data', 'credential', 'unnamespaced'].includes(scopeKind(d)))
  const dataNote = sourceNote({ store: 'your Grant Index', count: dataGrants.length, unit: 'grant' })
  const dataBody = dataGrants.length ? `<div class="ap-rows">${dataGrants.map(grantRow).join('')}</div>` : ''

  // ── action + admission grants: read from public 440s, also ours to see ───────
  const actionGrants = held.filter(d => ['action', 'admission'].includes(scopeKind(d)))
  const actionNote = sourceNote({ store: 'public grants your key signed', count: actionGrants.length, unit: 'grant' })
  const actionBody = actionGrants.length ? `<div class="ap-rows">${actionGrants.map(grantRow).join('')}</div>` : ''

  // ── granted onward: readable ONLY for this key's own derivations (#93) ───────
  const kids = childrenTo(state.index, pub)
  const onwardNote = sourceNote({ store: 'your own derivation ledger', count: kids.length, unit: 'child' })
  const onwardBody = kids.length ? `<div class="ap-rows">${kids.map(k => `<div class="ap-row${k.state === 'revoked' ? ' dead' : ''}">
      <span class="ap-ic">↳</span><span class="ap-name">${esc(k.child.scope_name || k.child.scope)}</span>
      <span class="chip scope-${k.state === 'revoked' ? 'revoked' : 'active'}">${k.state === 'revoked' ? 'severed' : 'active'}</span>
      <span class="msg">derived from ${esc(shortId(k.parent.scope))}</span></div>`).join('')}</div>` : ''

  // ── custody + approval path: NACT's to answer, and it is not reachable here ──
  // Deliberately a skeleton rather than an omission. Nact keys its identities by env-var name
  // and this console holds no NIP-98 credential for the box, so the honest report is "did not
  // answer" — and saying nothing at all would let a reader assume no key exists.
  const custodyNote = sourceNote({ store: 'Nact', answered: false, notSameAs: 'no key on the box' })
  const pathNote = sourceNote({ store: 'Nact', answered: false, notSameAs: 'no approval path' })

  // ── where it acts: the slice question, and no slice is reachable from here ───
  //
  // "What may this agent do" and "where does it do it" are different questions, and this plane can
  // only answer the first. A slice roster lives in the slice — waggle's in its bridge config, Ngage's
  // in a browser's localStorage — so this console cannot enumerate them, and AD-12 forbids keeping a
  // second copy to make the section look populated.
  //
  // What it CAN do is name the slices it knows exist and report that each did not answer. That is not
  // decoration: the omission it replaces is the one that let "an approval made in waggle is invisible
  // in Nvoy" go unnoticed, because a screen with no waggle row reads as "not in waggle" rather than as
  // "never asked".
  const sliceNote = sourceNote({ store: 'waggle and Ngage', answered: false, notSameAs: 'this agent acts nowhere' })
  const admissions = held.filter(d => scopeKind(d) === 'admission' && d.status === 'active')
  const sliceBody = admissions.length
    ? `<div class="msg ap-body">You signed ${admissions.length} admission${admissions.length === 1 ? '' : 's'} for this
        agent, listed under Actions granted. An admission is what you granted, not proof a slice is
        honouring it — no slice answered.</div>`
    : ''

  // ── liveness: promoted from three levels deep in a collapsed Ledger card ────
  // The runtime manifest, projected. It is READ-ONLY and an ALLOWLIST: STANDARDS forbids credential
  // locations, host addresses and service-account ids in a UI, and this manifest is full of all three, so
  // a field added upstream stays hidden until someone admits it on purpose (runtime-facts.mjs).
  //
  // `state.runtimeManifests` is null until an authenticated endpoint exists to fill it — and null means
  // SILENT, not "no runtime". Being unable to ask a box is not evidence that nothing runs there.
  const manifests = state.runtimeManifests ?? null
  const rt = runtimeState(manifests ? (manifests[pub] ?? null) : null, { reachable: manifests !== null })
  const proj = rt.state === 'answered' ? projectManifest(manifests[pub]) : null

  const wantsOutput = held.some(d => d.terms?.reply_scope_requested) || state.received.some(g => g.publisher === pub)
  const liveNote = wantsOutput
    ? sourceNote({ store: 'this agent\'s outbox', count: null })
    : sourceNote({ store: 'any runtime', answered: false, notSameAs: 'this agent is idle' })
  const liveBody = wantsOutput
    ? `<div class="outbox" data-agent="${esc(pub)}"><span class="msg">dereferencing the agent's output scope live…</span></div>`
    : ''

  const revokeAll = held.filter(d => d.status === 'active')
  const coverage = held.map(d => coverageNote(d, state.index, state.me)).find(Boolean) || null

  el.innerHTML = `
    <div class="ap-back"><button class="btn-back" id="ap-back">← Agents</button></div>
    ${header}
    ${sect('Data granted', dataNote, dataBody, `<button class="primary" id="ap-grant">＋ Grant data…</button>`)}
    ${sect('Actions granted', actionNote, actionBody, `<button id="ap-authority">＋ Give task authority…</button>`)}
    ${kids.length ? sect('Granted onward (children you derived to this key)', onwardNote, onwardBody) : ''}
    ${sect('Key custody', custodyNote, '')}
    ${sect('Approval path', pathNote, '')}
    ${sect('Where it acts', sliceNote, '', '', sliceBody)}
    ${(() => {
      // "Where does it run" is a different question from "what did it produce" — the outbox panel below
      // answers the second. Decision D7 in the spec had no surface at all before this.
      const note = rt.state === 'answered'
        ? sourceNote({ store: 'this agent\'s runtime manifest', count: proj.fields.length, unit: 'fact' })
        : { state: rt.state, stamp: rt.state === 'silent' ? 'the runtime endpoint did not answer' : 'no runtime manifest', body: rt.note }
      const body = rt.state === 'answered'
        ? `<div class="ap-rows">${proj.fields.map(f => `<div class="ap-row">
            <span class="ap-name">${esc(String(f.value))}</span>
            <span class="msg">${esc(f.meaning)}</span></div>`).join('')}</div>`
        : ''
      const held = rt.state === 'answered' ? withheldNote(proj.withheld) : null
      return sect('Where it runs', note, body, '',
        held ? `<div class="msg ap-body">${esc(held)}</div>` : '')
    })()}
    ${sect('Running now', liveNote, liveBody)}
    ${coverage ? `<div class="card ap-sect"><div class="msg ap-body">${esc(coverage)}</div></div>` : ''}
    <div class="actions ap-foot">
      ${revokeAll.length ? `<button class="danger" id="ap-revoke-all">Revoke everything…</button>` : ''}
      <span class="msg">${revokeAll.length
        ? `${revokeAll.length} active grant${revokeAll.length === 1 ? '' : 's'} — you will be shown each one before anything is signed`
        : 'Nothing active to revoke.'}</span>
    </div>`

  $('ap-back').onclick = () => { openAgent = null; showTab('agents') }
  for (const b of el.querySelectorAll('.ap-open')) {
    b.onclick = () => openDelegationInLedger(b.dataset.scope, b.dataset.agent)
  }
  $('ap-grant')?.addEventListener('click', () => openComposer('delegate', pub))
  $('ap-authority')?.addEventListener('click', () => openComposer('authority', pub))
  // The section is only a placeholder until this live read settles. A grant alone never proves
  // that the agent answered or is running.
  void settleAgentOutputs(el, { relay: state.relay, grants: state.received, formatWhen: fmtWhen })

  // Revoke-everything ENUMERATES before it confirms, and states its limits. A blanket confirm
  // that does not say what it touches — or implies it reaches stores that did not answer — is
  // the same defect as a count from a silent store.
  $('ap-revoke-all')?.addEventListener('click', () => {
    const list = revokeAll.map(d => `  · ${d.scopeName || d.scope}`).join('\n')
    alert(`Revoking every active grant to ${name} means revoking these ${revokeAll.length}:\n\n${list}\n\n` +
      `Each rotation is a separate signature and the Ledger walks you through them — open a grant ` +
      `and use Revoke now.\n\nIt does NOT rotate any key on the box, and it cannot remove this agent ` +
      `from an app whose roster this console never read.`)
    openDelegationInLedger(revokeAll[0].scope, revokeAll[0].agent)
  })
}

// The composers are drawers, not destinations (see main.mjs). Imported lazily to avoid a cycle.
let openComposer = () => {}
export const wireComposer = (fn) => { openComposer = fn }
