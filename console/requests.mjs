// requests.mjs — pending access requests, promoted out of a card on the Agents tab.
//
// This is a DECISION QUEUE, and it was the only one in the estate without its own surface: Nact
// has a Queue, Ngage has Drafts, waggle has "Waiting for you". Here it sat above the roster,
// unbadged, so the one place work waits was the one place you had to already be looking.
//
// It also gains the control this console lacked and waggle has had all along: the warning that
// THE KEY THAT ASKED IS NOT THE KEY BEING ADMITTED. A request is a stranger asking — anyone can
// gift-wrap one to any npub — and the purpose line is attacker-authored text. Reachability is
// not authority, so the row says who wrote the words and whose key would gain access.

import { nip19 } from 'nostr-tools'
import { saveGrantIndex } from '../lib/nipxx.mjs'
import { sourceNote } from '../lib/nave-source-note.mjs'
import { state, $, esc, short, fmtWhen, load, agentsOf, agentName, dismissRequest,
         openDrawer, refreshRequestBadge } from './main.mjs'
import { prefillDelegate } from './delegate.mjs'
import { enrol } from './registry.mjs'

function requestCard(r, i) {
  // The grantee is the credential's OWNER when the runtime named one — it proposes on the
  // owner's behalf, so the grant must land on the owner rather than on the requester.
  const grantee = r.owner || r.from
  const thirdParty = grantee !== r.from
  return `<div class="reqrow" data-i="${i}">
    <div class="reqbody">
      <b>${esc(agentName(r.from))}</b> <span class="meta">${esc(short(r.from))}</span>
      <span class="meta">· ${esc(fmtWhen(r.at))}</span>
      ${r.scope_name ? `<div class="meta">wants <code>${esc(r.scope_name)}</code>${
        r.enc_value ? ' · value carried, encrypted to you' : ' · you paste the value'}</div>` : ''}
      ${thirdParty ? `<div class="reqwarn" title="the key that asked is not the key that would gain access. Admit only if you expected someone to request on another key's behalf.">
        ⚠ asked by ${esc(short(r.from))}, not the key being admitted — the grant would land on
        <b>${esc(agentName(grantee))}</b> ${esc(short(grantee))}</div>` : ''}
      <div class="purpose">“${esc(r.purpose)}”</div>
      <div class="meta reqauth">Written by whoever is asking. Read it as a claim, not a fact.</div>
    </div>
    <div class="reqacts">
      <button class="primary req-approve">Approve…</button>
      <button class="req-deny" title="dismiss on this device — the agent is not notified, and nothing is granted or revoked">Deny</button>
    </div>
  </div>`
}

export function renderRequests() {
  const rs = state.requests
  // Unwrap failures are REPORTED, never dropped: a wrap this signer could not open is not the
  // same as a request that was not sent, and the difference decides whether you go looking.
  const note = state.unwrapWarning
    ? sourceNote({ store: 'your relays', answered: false, notSameAs: 'nobody is asking' })
    : sourceNote({ store: 'gift wraps addressed to you', count: rs.length, unit: 'request' })

  $('requests').innerHTML = `
    <div class="card">
      <div class="sect2 reqhead"><span>Waiting for you</span>
        <span class="reqstamp req-${note.state}">${esc(note.stamp)}</span></div>
      <div class="note" style="margin:2px 0 10px">Agents asking for a delegation. Approving opens the
        composer pre-filled — you still choose the data and the terms. Denying dismisses the request on
        this device only; the agent learns nothing. <b>Nothing listed here has any access yet.</b></div>
      ${state.unwrapWarning ? `<div class="msg reqsilent">⚠ ${esc(state.unwrapWarning)}</div>` : ''}
      ${rs.length ? rs.map(requestCard).join('')
        : `<div class="empty">${note.body === 'nothing here'
            ? 'No requests waiting. This is an affirmative empty — your relays answered and nobody is asking.'
            : esc(note.body || '')}</div>`}
    </div>`

  for (const row of document.querySelectorAll('#requests .reqrow')) {
    const r = rs[Number(row.dataset.i)]
    if (!r) continue
    row.querySelector('.req-approve').onclick = async () => {
      const grantee = r.owner || r.from
      const msg = row.querySelector('.reqacts')
      const enrolled = enrol(state.index, grantee, { me: state.me, now: Math.floor(Date.now() / 1000) })
      if (enrolled.added) {
        state.index.nvoy_agents = enrolled.agents
        try { await saveGrantIndex(state.relay, state.signer, state.index) }
        catch (err) { msg.insertAdjacentHTML('beforeend', `<span class="msg">${esc(err.message)}</span>`); return }
      }
      let name, payload
      if (r.scope_name) {
        name = r.scope_name
        if (r.enc_value) {
          try { payload = { value: await state.signer.nip44Decrypt(r.from, r.enc_value) } }
          catch (err) {
            msg.insertAdjacentHTML('beforeend', `<span class="msg">could not decrypt the carried value: ${esc(err.message)}</span>`)
            return
          }
        } else payload = { value: '' }
      }
      dismissRequest(r.id)
      refreshRequestBadge()
      prefillDelegate({ agent: grantee, purpose: r.purpose, name, payload })
      openDrawer('delegate', grantee)
    }
    row.querySelector('.req-deny').onclick = () => { dismissRequest(r.id); refreshRequestBadge(); renderRequests() }
  }
}
