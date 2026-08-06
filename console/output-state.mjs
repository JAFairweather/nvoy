// One live, honest answer for every console surface that shows an agent outbox.
// A kind-1059 grant is only the capability to try the read; it is not evidence that
// output exists, is current, or says anything about runtime liveness.

import { fetchScope } from '../lib/nipxx.mjs'

export const AGENT_OUTPUT_SCOPE = 'agent output'

// The publisher alone identifies who offered a received grant, not what that grant is for.
// Keep the outbox identity canonical and exact so a newer draft, credential, or arbitrary
// data scope from the same agent can never shadow the agent's real output scope.
export const isAgentOutputGrant = (grant, agentPub) => grant?.publisher === agentPub
  && grant?.scopeName === AGENT_OUTPUT_SCOPE
  && grant?.terms?.purpose === AGENT_OUTPUT_SCOPE

const latestGrant = (grants, agentPub) => (grants || [])
  .filter(grant => isAgentOutputGrant(grant, agentPub))
  .sort((a, b) => Number(b.issuedAt || 0) - Number(a.issuedAt || 0))[0] || null

export async function loadAgentOutput({ relay, grants, agentPub, read = fetchScope }) {
  const grant = latestGrant(grants, agentPub)
  if (!grant) return { state: 'no-grant', grant: null }
  try {
    const result = await read(relay, grant)
    if (result?.status === 'ok') return { state: 'ok', grant, result, data: result.data }
    if (result?.status === 'stale') return { state: 'stale', grant, result }
    return { state: 'not-found', grant, result }
  } catch (error) {
    return { state: 'relay-error', grant, error: error instanceof Error ? error : new Error(String(error)) }
  }
}

const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char])

export function renderAgentOutput(state, { formatWhen = value => String(value) } = {}) {
  if (state.state === 'no-grant') return '<span class="msg">no output yet — no outbox grant was found</span>'
  if (state.state === 'relay-error') return `<span class="msg">output unavailable — relays did not answer: ${esc(state.error?.message || 'unknown error')}</span>`
  if (state.state === 'stale') return '<span class="msg">output scope was rotated by the agent</span>'
  if (state.state === 'not-found') return '<span class="msg">output scope was not found on the relays</span>'
  const { updated_at, ...data } = state.data || {}
  return `<pre class="outjson">${esc(JSON.stringify(data, null, 2))}</pre>
    <span class="meta">v${esc(state.result?.generation)}${updated_at ? ` · updated ${esc(formatWhen(updated_at))}` : ''} · scope ${esc(state.grant?.scopeId)}</span>`
}

export async function settleAgentOutputs(root, { relay, grants, read, formatWhen } = {}) {
  const panels = [...(root?.querySelectorAll?.('.outbox[data-agent]') || [])]
  return Promise.allSettled(panels.map(async panel => {
    const output = await loadAgentOutput({ relay, grants, agentPub: panel.dataset.agent, read })
    panel.innerHTML = renderAgentOutput(output, { formatWhen })
    panel.dataset.outputState = output.state
    return output
  }))
}
