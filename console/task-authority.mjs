// task-authority.mjs — browser-side issuance of the portable authority that
// lets one identity task a particular Nvoy runtime.  It is deliberately a
// plain public NIP-DA 440: any app may issue it, and Nvoy's universal grant
// plane is where it is subsequently inspected and revoked.

import { nip19 } from 'nostr-tools'
import { state, $, esc, parsePub, short, load } from './main.mjs'
import { buildTaskAuthority, signPublishTaskAuthority } from './task-authority-lib.mjs'

const npub = (hexPub) => nip19.npubEncode(hexPub)
const option = (agent) => `<option value="${esc(npub(agent.pub))}">${esc(agent.name || agent.display_name || short(agent.pub))}</option>`

export function renderTaskAuthority() {
  const agentOptions = (state.index.nvoy_agents || []).map(option).join('')
  $('authority').innerHTML = `
    <div class="card">
      <div class="head"><div><span class="name">Give task authority</span><div class="note">A portable, public NIP-DA grant. It authorizes one identity to wake one agent; Nvoy keeps the resulting record on the universal Access plane.</div></div></div>
      <div class="frow"><label for="ta-sender">May task</label><input id="ta-sender" autocomplete="off" placeholder="npub or 64-character public key"><datalist id="ta-known-agents">${agentOptions}</datalist></div>
      <div class="frow"><label for="ta-agent">Agent</label><input id="ta-agent" list="ta-known-agents" autocomplete="off" placeholder="agent npub or public key"></div>
      <div class="frow"><label for="ta-cap">Can do</label><select id="ta-cap"><option value="task">Task — wake and reply</option><option value="task+act">Task + act — wake, reply, and take authorized action</option></select></div>
      <div class="note">The agent identity is cryptographically bound into a salted scope hash, so this approval cannot be replayed to a different agent. Your signer creates the authority; this page never receives an nsec.</div>
      <div class="actions"><button class="primary" id="ta-issue">Review and sign authority</button><span class="msg" id="ta-msg"></span></div>
    </div>`
  $('ta-issue').onclick = issue
}

async function issue() {
  const msg = $('ta-msg'), button = $('ta-issue')
  button.disabled = true
  try {
    if (!state.signer || !state.relay) throw new Error('sign in first')
    const senderPub = parsePub($('ta-sender').value)
    const agentPub = parsePub($('ta-agent').value)
    if (senderPub === agentPub) throw new Error('the person authorizing tasks and the agent must be different identities')
    const cap = $('ta-cap').value
    const draft = await buildTaskAuthority({ senderPub, agentPub, cap })
    const label = cap === 'task+act' ? 'Task + act' : 'Task'
    if (!confirm(`Sign ${label} authority?\n\n${short(senderPub)} may task ${short(agentPub)}.\n\nThis public, revocable record will appear in Nvoy Access.`)) return
    msg.textContent = 'asking your signer…'
    const { signed, receipt } = await signPublishTaskAuthority({ signer: state.signer, relay: state.relay, draft })
    msg.textContent = `active — ${receipt.acks ?? '?'} relay acknowledgement(s), read back as ${signed.id.slice(0, 12)}…`
    await load()
  } catch (err) { msg.textContent = `nothing changed: ${err.message}` }
  finally { button.disabled = false }
}
