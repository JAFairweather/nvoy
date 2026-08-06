// Authenticated client for Nact's external frozen-action queue.

import { createHash } from 'node:crypto'

const fail = message => { throw new Error(`nact external approval: ${message}`) }

function endpoint(base, path) {
  let origin
  try { origin = new URL(base) } catch { fail('invalid endpoint') }
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') fail('invalid endpoint')
  return new URL(path, origin).toString()
}

async function auth(signer, method, url, body = '') {
  const tags = [['u', url], ['method', method]]
  if (body) tags.push(['payload', createHash('sha256').update(body).digest('hex')])
  return await signer.signEvent({ kind: 27235, created_at: Math.floor(Date.now() / 1000), tags, content: '' })
}

async function call(signer, url, { method = 'GET', body = '', fetchImpl = fetch } = {}) {
  const event = await auth(signer, method, url, body)
  const headers = { authorization: `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}` }
  if (body) headers['content-type'] = 'application/json'
  const response = await fetchImpl(url, { method, headers, ...(body ? { body } : {}) })
  let out
  try { out = await response.json() } catch { fail(`endpoint returned non-JSON (${response.status})`) }
  if (!response.ok) fail(out?.error || `endpoint returned ${response.status}`)
  return out
}

export async function submitExternalProposal({ endpoint: base, signer, proposal, fetchImpl } = {}) {
  const body = JSON.stringify(proposal)
  return await call(signer, endpoint(base, '/api/propose-external'), { method: 'POST', body, fetchImpl })
}

export async function fetchExternalDecision({ endpoint: base, signer, proposalId, fetchImpl } = {}) {
  if (!/^[0-9a-f]{32}$/.test(String(proposalId || ''))) fail('invalid proposal id')
  const body = JSON.stringify({ proposal_id: proposalId })
  return await call(signer, endpoint(base, '/api/external-approval'), { method: 'POST', body, fetchImpl })
}
