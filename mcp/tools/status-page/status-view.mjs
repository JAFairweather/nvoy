// The status page's rendering (status S1), pure so a test can hold it: status.json in, HTML out.
// The page only shows what the collector already sanitised; it escapes every value regardless, and
// it has no actions. The age of the snapshot is the first thing it says: a page that stopped
// updating must never look like a fleet that is fine.

export const STALE_MS = 3 * 60 * 1000

export const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])

const COLOURS = ['green', 'amber', 'red', 'grey']
const colour = c => (COLOURS.includes(c) ? c : 'grey')
const dot = c => `<span class="dot ${colour(c)}" aria-label="${colour(c)}"></span>`
const ago = s => (s < 120 ? `${s}s` : s < 7200 ? `${Math.round(s / 60)}m` : `${Math.round(s / 3600)}h`)

// How old the snapshot is, and whether that alone makes the page red.
export function ageVerdict(generatedAt, now = Date.now(), { staleMs = STALE_MS } = {}) {
  const at = Date.parse(generatedAt || '')
  if (!Number.isFinite(at)) return { stale: true, colour: 'red', text: 'no snapshot time: the collector has not written this page' }
  const s = Math.max(0, Math.round((now - at) / 1000))
  if (now - at > staleMs) return { stale: true, colour: 'red', text: `STALE: last updated ${ago(s)} ago. The collector has stopped, so nothing below is current.` }
  return { stale: false, colour: 'green', text: `updated ${ago(s)} ago` }
}

const checkRows = checks => (checks || []).map(c =>
  `<li>${dot(c.colour)}<span class="label">${esc(c.label)}</span><span class="reason">${esc(c.reason)}</span></li>`).join('')

function agentCard(a) {
  const f = a.funnel || {}
  return `<section class="card agent ${colour(a.colour)}">
  <h3>${dot(a.colour)}${esc(a.id)} <code>${esc(a.pubkey)}</code></h3>
  <ul class="checks">${checkRows(a.checks)}</ul>
  <p class="funnel">24h: <b>${esc(f.heard ?? 0)}</b> heard · <b>${esc(f.admitted ?? 0)}</b> admitted · <b>${esc(f.data_only ?? 0)}</b> data only · <b>${esc(f.held ?? 0)}</b> held · <b>${esc(f.replies ?? 0)}</b> replies</p>
</section>`
}

const CELL = { active: 'green', revoked: 'red', expired: 'amber', none: 'grey' }
function grantsTable(g) {
  if (!g || !g.targets?.length) return '<p class="dim">grants were not read</p>'
  const who = x => `${esc(x.name || '')} <code>${esc(x.pubkey)}</code>`
  const head = g.targets.map(t => `<th scope="col">${who(t)}</th>`).join('')
  const rows = (g.rows || []).map(r => `<tr><th scope="row">${who(r)}</th>${(r.cells || []).map(c => {
    const state = CELL[c.state] ? c.state : 'none'
    const detail = state === 'active' ? `<small>${esc(c.cap)} · <code>${esc(c.grant)}</code><br>${(c.relays || []).map(esc).join(', ') || 'on no relay its broker reads'}</small>` : ''
    return `<td class="${CELL[state]}">${dot(CELL[state])}${esc(state)}${detail}</td>`
  }).join('')}</tr>`).join('')
  return `<p class="dim">Granted by ${(g.grantors || []).map(who).join(', ') || 'nobody'}. Rows may task columns. Read-only.</p>
<div class="scroll"><table class="grid"><thead><tr><th>grantee ↓ · target →</th>${head}</tr></thead><tbody>${rows || `<tr><td colspan="${g.targets.length + 1}" class="dim">no task grants found</td></tr>`}</tbody></table></div>`
}

const relayRows = rs => (rs || []).map(r =>
  `<li>${dot(r.colour)}<span class="label">${esc(r.label)}</span><span class="reason">${esc(r.reason)} · ${esc(r.events)} grant events</span></li>`).join('')

export function renderSnapshot(s, now = Date.now()) {
  const age = ageVerdict(s?.generated_at, now)
  const banner = `<div class="age ${age.colour}" role="status">${esc(age.text)}${s?.generated_at ? ` <small>(${esc(s.generated_at)})</small>` : ''}</div>`
  if (!s || s.withheld) {
    return `${banner}<div class="banner red">${dot('red')}${esc(s?.reason || 'no snapshot')}</div>`
  }
  const overall = age.stale ? 'red' : colour(s.overall)
  return `${banner}
<div class="overall ${overall}">${dot(overall)}<span>${age.stale ? 'unknown: the snapshot is stale' : `overall ${esc(overall)}`}</span>${s.release ? `<span class="dim">release <code>${esc(s.release)}</code></span>` : ''}</div>
<h2>Agents</h2><div class="cards">${(s.agents || []).map(agentCard).join('')}</div>
<h2>Grants</h2>${grantsTable(s.grants)}
<h2>Relays</h2><ul class="checks">${relayRows(s.relays)}</ul>
<h2>Platform</h2><ul class="checks">${checkRows(s.platform)}</ul>
<h2>Web</h2><ul class="checks">${checkRows(s.web)}</ul>`
}
