import assert from 'node:assert/strict'
import { loadAgentOutput, renderAgentOutput, settleAgentOutputs } from '../console/output-state.mjs'

const AGENT = 'a'.repeat(64)
const grant = {
  publisher: AGENT, issuedAt: 10, scopeId: 'scope-one',
  scopeName: 'agent output', terms: { purpose: 'agent output' },
}

const noGrant = await loadAgentOutput({ relay: {}, grants: [], agentPub: AGENT, read: async () => { throw new Error('must not read') } })
assert.equal(noGrant.state, 'no-grant')

const good = await loadAgentOutput({ relay: {}, grants: [grant], agentPub: AGENT,
  read: async () => ({ status: 'ok', generation: 2, data: { fields: { answer: 42 }, updated_at: 100 } }) })
assert.equal(good.state, 'ok')
assert.match(renderAgentOutput(good, { formatWhen: () => 'then' }), /&quot;answer&quot;: 42/)
assert.match(renderAgentOutput(good, { formatWhen: () => 'then' }), /v2 · updated then/)

const mixed = await loadAgentOutput({
  relay: {}, agentPub: AGENT,
  grants: [
    grant,
    { publisher: AGENT, issuedAt: 30, scopeId: 'newer-draft', scopeName: 'draft:post', terms: { purpose: 'Draft a post' } },
    { publisher: AGENT, issuedAt: 20, scopeId: 'name-only', scopeName: 'agent output', terms: { purpose: 'something else' } },
    { publisher: AGENT, issuedAt: 15, scopeId: 'purpose-only', scopeName: 'something else', terms: { purpose: 'agent output' } },
  ],
  read: async (_relay, selected) => ({ status: 'ok', generation: 2, data: { selected: selected.scopeId } }),
})
assert.equal(mixed.state, 'ok')
assert.equal(mixed.grant.scopeId, grant.scopeId)
assert.equal(mixed.data.selected, grant.scopeId)

const stale = await loadAgentOutput({ relay: {}, grants: [grant], agentPub: AGENT, read: async () => ({ status: 'stale' }) })
assert.equal(stale.state, 'stale')
assert.match(renderAgentOutput(stale), /rotated/)

const missing = await loadAgentOutput({ relay: {}, grants: [grant], agentPub: AGENT, read: async () => ({ status: 'missing' }) })
assert.equal(missing.state, 'not-found')
assert.match(renderAgentOutput(missing), /not found/)

const failed = await loadAgentOutput({ relay: {}, grants: [grant], agentPub: AGENT, read: async () => { throw new Error('offline') } })
assert.equal(failed.state, 'relay-error')
assert.match(renderAgentOutput(failed), /relays did not answer: offline/)

const panels = [
  { dataset: { agent: AGENT }, innerHTML: '' },
  { dataset: { agent: 'b'.repeat(64) }, innerHTML: '' },
]
const settled = await settleAgentOutputs({ querySelectorAll: () => panels }, { relay: {}, grants: [grant],
  read: async (_relay, selected) => selected.publisher === AGENT
    ? { status: 'ok', generation: 1, data: { fields: { status: 'answered' } } }
    : Promise.reject(new Error('unexpected')) })
assert.deepEqual(settled.map(result => result.status), ['fulfilled', 'fulfilled'])
assert.equal(panels[0].dataset.outputState, 'ok')
assert.equal(panels[1].dataset.outputState, 'no-grant')
assert.match(panels[0].innerHTML, /answered/)
assert.doesNotMatch(panels[1].innerHTML, /answered|running/)

console.log('output-state: success, no grant, relay error, stale, not-found, and multi-panel settlement pass')
