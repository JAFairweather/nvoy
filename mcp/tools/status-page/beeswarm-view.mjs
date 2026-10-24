// beeswarm: status.json's swarm section drawn as a graph and a grid, pure so a test can hold it.
// Like status-view.mjs it shows only what the collector already sanitised, escapes every value
// regardless, and has no actions: it reads the grants and manifests the brokers enforce, it never
// writes them. Instructs edges are live task grants; wakes edges are may_post.mention lists.

import { ageVerdict, esc } from './status-view.mjs'

export const EDGE_TYPES = ['instructs', 'wakes']
const KINDS = ['grantor', 'agent', 'named', 'unknown']
const COLOURS = ['green', 'amber', 'red', 'grey']
const kind = k => (KINDS.includes(k) ? k : 'unknown')
const colour = c => (COLOURS.includes(c) ? c : 'grey')
const label = n => n?.name || n?.id || '?'
const R = 30

// Grantors at the centre, fleet agents on the inner ring, every other key on the outer one, each
// in a gap between two agents so no outer key sits directly behind an agent and hides its arrows.
export function layout(nodes, { w = 760, h = 680 } = {}) {
  const cx = w / 2, cy = h / 2, at = new Map()
  const place = (n, r, a) => at.set(n.id, { x: Math.round(cx + r * Math.cos(a)), y: Math.round(cy + r * Math.sin(a)) })
  const grantors = nodes.filter(n => kind(n.kind) === 'grantor')
  grantors.forEach((n, i) => place(n, grantors.length === 1 ? 0 : 70, -Math.PI / 2 + (2 * Math.PI * i) / grantors.length))
  const agents = nodes.filter(n => kind(n.kind) === 'agent'), step = (2 * Math.PI) / Math.max(agents.length, 1)
  agents.forEach((n, i) => place(n, 190, -Math.PI / 2 + step * i))
  const outer = nodes.filter(n => ['named', 'unknown'].includes(kind(n.kind)))
  const gaps = Math.max(agents.length, outer.length)
  outer.forEach((n, i) => place(n, 280, -Math.PI / 2 + (2 * Math.PI / gaps) * (Math.floor((i * gaps) / outer.length) + 0.5)))
  return at
}

const hex = (x, y, r) => Array.from({ length: 6 }, (_, k) => {
  const a = Math.PI / 6 + (k * Math.PI) / 3
  return `${(x + r * Math.cos(a)).toFixed(1)},${(y + r * Math.sin(a)).toFixed(1)}`
}).join(' ')

// A curve bowed to its right, so A→B and B→A never overlap, trimmed to stop at each hexagon.
function curve(a, b) {
  const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1
  const ux = dx / len, uy = dy / len, bow = Math.min(28, len / 5)
  const c = { x: (a.x + b.x) / 2 - uy * bow, y: (a.y + b.y) / 2 + ux * bow }
  const trim = (p, q) => { const d = Math.hypot(q.x - p.x, q.y - p.y) || 1; return { x: p.x + ((q.x - p.x) * (R + 2)) / d, y: p.y + ((q.y - p.y) * (R + 2)) / d } }
  const s = trim(a, c), e = trim(b, c)
  return `M${s.x.toFixed(1)},${s.y.toFixed(1)} Q${c.x.toFixed(1)},${c.y.toFixed(1)} ${e.x.toFixed(1)},${e.y.toFixed(1)}`
}

function graph(sw, show, selected) {
  const at = layout(sw.nodes)
  const edges = sw.edges.filter(e => EDGE_TYPES.includes(e.type) && show[e.type] && at.has(e.from) && at.has(e.to))
  const touches = e => !selected || e.from === selected || e.to === selected
  const near = new Set(selected ? [selected, ...edges.filter(touches).flatMap(e => [e.from, e.to])] : sw.nodes.map(n => n.id))
  const paths = edges.map(e => `<path class="edge ${e.type}${e.voice_of ? ' voice' : ''}${touches(e) ? '' : ' cold'}" d="${curve(at.get(e.from), at.get(e.to))}" marker-end="url(#arrow-${e.type})"><title>${esc(label(sw.nodes.find(n => n.id === e.from)))} ${e.type === 'instructs' ? `may instruct (${esc(e.cap)})` : 'may wake'} ${esc(label(sw.nodes.find(n => n.id === e.to)))}</title></path>`).join('')
  const cells = sw.nodes.map(n => {
    const p = at.get(n.id)
    return `<g class="node ${kind(n.kind)} ${colour(n.colour)}${n.id === selected ? ' selected' : ''}${near.has(n.id) ? '' : ' cold'}" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(label(n))}">
  <polygon points="${hex(p.x, p.y, R)}"/><text x="${p.x}" y="${p.y + R + 16}" text-anchor="middle">${esc(label(n))}</text>
  <text class="pk" x="${p.x}" y="${p.y + 4}" text-anchor="middle">${esc(String(n.id).slice(0, 4))}</text></g>`
  }).join('')
  const marker = t => `<marker id="arrow-${t}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="tip ${t}" d="M0,0 L10,5 L0,10 z"/></marker>`
  return `<svg class="swarm" viewBox="0 0 760 680" role="img" aria-label="who may instruct and wake whom"><defs>${EDGE_TYPES.map(marker).join('')}</defs>${paths}${cells}</svg>`
}

const who = (sw, id) => { const n = sw.nodes.find(x => x.id === id); return `${esc(label(n))} <code>${esc(id)}</code>` }
const list = items => (items.length ? `<ul>${items.map(i => `<li>${i}</li>`).join('')}</ul>` : '<p class="dim">nobody</p>')

function panel(sw, id) {
  const n = sw.nodes.find(x => x.id === id)
  if (!n) {
    const unknown = sw.nodes.filter(x => kind(x.kind) === 'unknown' && sw.edges.some(e => e.type === 'instructs' && e.from === x.id))
    const count = t => sw.edges.filter(e => e.type === t).length
    return `<h3>The swarm</h3>
<p>${sw.nodes.filter(x => kind(x.kind) === 'agent').length} fleet agents, ${count('instructs')} live instruct grants, ${count('wakes')} wake rights.
Select a hexagon to see what it may do.</p>
${unknown.length ? `<div class="warn"><b>Keys nobody named hold live task grants:</b>${list(unknown.map(u => `<code>${esc(u.id)}</code> may instruct ${sw.edges.filter(e => e.type === 'instructs' && e.from === u.id).map(e => esc(label(sw.nodes.find(x => x.id === e.to)))).join(', ')}`))}Identify each one, or revoke its grants.</div>` : ''}`
  }
  const into = t => sw.edges.filter(e => e.type === t && e.to === id)
  const out = t => sw.edges.filter(e => e.type === t && e.from === id)
  const agent = kind(n.kind) === 'agent', f = n.funnel || {}
  return `<h3><span class="dot ${colour(n.colour)}"></span>${esc(label(n))} <code>${esc(n.id)}</code> <small>${esc(kind(n.kind))}</small></h3>
${kind(n.kind) === 'unknown' ? '<div class="warn">No manifest or mention list names this key. If it holds grants, find out whose it is or revoke them.</div>' : ''}
${n.voice_of ? `<p>Speaks as ${who(sw, n.voice_of)}'s voice: a shadow grant gives it that key's reach, and one revocation of grant <code>${esc(out('instructs')[0]?.grant || '')}</code> takes it all away.</p>` : ''}
<h4>Takes instructions from</h4>${agent ? list(into('instructs').map(e => `${who(sw, e.from)} <small>${esc(e.cap)}${e.voice_of ? ' as a voice' : ''} · ${esc(e.grant)}</small>`)) : '<p class="dim">not a fleet agent: its own broker, if any, is not measured here</p>'}
<h4>May instruct</h4>${list(out('instructs').map(e => `${who(sw, e.to)} <small>${esc(e.cap)}${e.voice_of ? ' as a voice' : ''}</small>`))}
${agent ? `<h4>May wake (mention)</h4>${list(out('wakes').map(e => who(sw, e.to)))}` : ''}
<h4>Woken by</h4>${list(into('wakes').map(e => who(sw, e.from)))}
${agent ? `<h4>Speaks</h4><dl>
<dt>Posts</dt><dd>${n.post ? `in ${n.post.channels.map(c => `<code>${esc(c)}</code>`).join(', ')}, up to ${esc(n.post.per_hour)} an hour` : 'may only reply'}</dd>
<dt>Profile</dt><dd>${n.profile ? `kind 0, ${esc(n.profile.per_day)} a day, pictures from ${n.profile.picture_hosts.map(esc).join(', ')}` : 'may not set it'}</dd>
<dt>Externally</dt><dd class="dim">not a capability yet</dd>
<dt>Brakes</dt><dd>${esc(n.limits?.max_hops)} hops, ${esc(n.limits?.per_sender_per_hour)} per sender an hour</dd>
<dt>Ears</dt><dd>${esc(n.delivery)}${n.door ? ' · channel door' : ''}${n.webhook ? ' · wake webhook' : ''}</dd>
<dt>Listens to</dt><dd>grants signed by ${(n.grantors || []).map(g => who(sw, g)).join(', ')}</dd>
<dt>Last 24h</dt><dd>${esc(f.heard ?? 0)} heard · ${esc(f.admitted ?? 0)} admitted · ${esc(f.replies ?? 0)} replies</dd>
<dt>Role</dt><dd class="dim">no brief issued yet</dd></dl>` : ''}`
}

function grid(sw, show) {
  const edges = sw.edges.filter(e => show[e.type])
  const from = sw.nodes.filter(n => edges.some(e => e.from === n.id)), to = sw.nodes.filter(n => edges.some(e => e.to === n.id))
  if (!from.length) return '<p class="dim">no edges of the selected kinds</p>'
  const cell = (a, b) => edges.filter(e => e.from === a.id && e.to === b.id)
    .map(e => `<span class="badge ${e.type}" title="${e.type === 'instructs' ? esc(e.cap) : 'mention'}">${e.type === 'instructs' ? 'instructs' : 'wakes'}</span>`).join('')
  return `<div class="scroll"><table class="grid"><thead><tr><th>from ↓ · to →</th>${to.map(t => `<th scope="col">${esc(label(t))}</th>`).join('')}</tr></thead>
<tbody>${from.map(f => `<tr><th scope="row">${f.name ? `${esc(f.name)} ` : ''}<code>${esc(f.id)}</code></th>${to.map(t => `<td>${f.id === t.id ? '<span class="dim">·</span>' : cell(f, t)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
}

export function renderSwarm(s, { show = { instructs: true, wakes: false }, selected = null } = {}, now = Date.now()) {
  const age = ageVerdict(s?.generated_at, now)
  const banner = `<div class="age ${age.colour}" role="status">${esc(age.text)}</div>`
  if (!s || s.withheld || !s.swarm) return `${banner}<div class="banner red">${esc(s?.reason || 'this snapshot has no swarm section')}</div>`
  const sw = { nodes: (s.swarm.nodes || []).map(n => ({ ...n, id: String(n.id) })), edges: s.swarm.edges || [] }
  const sel = sw.nodes.some(n => n.id === selected) ? selected : null
  const toggles = EDGE_TYPES.map(t => `<button type="button" class="toggle ${t}" data-toggle="${t}" aria-pressed="${show[t] ? 'true' : 'false'}">${t === 'instructs' ? 'Instructs (task grants)' : 'Wakes (mentions)'}</button>`).join('')
  return `${banner}
<div class="toolbar">${toggles}${sel ? '<button type="button" class="toggle" data-clear>Show everyone</button>' : ''}</div>
<div class="split"><div class="canvas">${graph(sw, show, sel)}</div><aside class="panel">${panel(sw, sel)}</aside></div>
<h2>The same, as a grid</h2>${grid(sw, show)}`
}
