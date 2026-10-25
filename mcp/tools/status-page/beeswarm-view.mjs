// beeswarm: status.json's swarm section as a summary, an authority drawing, a roster and a matrix,
// pure so a test can hold it. Like status-view.mjs it shows only what the collector already sanitised,
// escapes every value regardless, and has no actions: it reads the grants and manifests the brokers
// enforce, it never writes them. Instructs edges are live task grants; wakes edges are may_post.mention.

import { ageVerdict, esc } from './status-view.mjs'

export const EDGE_TYPES = ['instructs', 'wakes']
export const VIEWS = ['overview', 'agents', 'matrix']
const KINDS = ['grantor', 'agent', 'named', 'unknown']
const COLOURS = ['green', 'amber', 'red', 'grey']
const CAP_TEXT = { task: 'task', 'task+act': 'task + act', 'task-relay': 'relay' }
const kind = k => (KINDS.includes(k) ? k : 'unknown')
const colour = c => (COLOURS.includes(c) ? c : 'grey')
const label = n => n?.name || n?.id || '?'
const capText = c => CAP_TEXT[c] || String(c ?? '')
const R = 28

// A stable key per edge, so the page can say what changed since the reader last looked.
// Grants are signed in the waggle console, never here. These links open it at the grant to revoke or
// the form to issue one; the console resolves the 8-hex prefixes only against keys and grants it has
// verified for whoever signs in, and signs nothing until the owner confirms (waggle#610).
export const CONSOLE = 'https://waggle.nave.pub/console/'
const HEX = /^[0-9a-f]{8,64}$/
export const revokeHref = grant => (HEX.test(String(grant)) ? `${CONSOLE}#revoke=${grant}` : null)
export const grantHref = (to, on, cap = 'task') => (HEX.test(String(to)) && HEX.test(String(on)) ? `${CONSOLE}#grant=${to}&on=${on}&cap=${encodeURIComponent(cap)}` : null)
const act = (href, text, title) => (href ? ` <a class="act" href="${esc(href)}" target="_blank" rel="noopener" title="${esc(title)}">${text}</a>` : '')
const revokeLink = (sw, e) => act(revokeHref(e.grant), 'revoke', e.voice_of
  ? `Revoke the shadow grant ${e.grant}: ${label(sw.nodes.find(n => n.id === e.from))} loses every right it holds as ${label(sw.nodes.find(n => n.id === e.voice_of))}'s voice`
  : `Revoke grant ${e.grant} in the waggle console`)

export const edgeKey = e => `${e.type}:${e.from}>${e.to}:${e.cap || ''}:${e.voice_of || ''}`

// Authority reads top-down: grantors, then every other key that holds or is given rights (voices,
// a coordinator, strangers), then the fleet in a row. Narrow screens get two columns instead, so a
// phone draws the same tiers without shrinking the labels to nothing.
export function canvasSize(nodes, { narrow = false } = {}) {
  const agents = nodes.filter(n => kind(n.kind) === 'agent').length
  const left = nodes.length - agents
  return narrow ? { w: 360, h: Math.max(agents, left, 1) * 96 + 48 } : { w: Math.max(760, agents * 140 + 80), h: 520 }
}

export function layout(nodes, { narrow = false } = {}) {
  const { w, h } = canvasSize(nodes, { narrow }), at = new Map()
  const tiers = [nodes.filter(n => kind(n.kind) === 'grantor'), nodes.filter(n => ['named', 'unknown'].includes(kind(n.kind))), nodes.filter(n => kind(n.kind) === 'agent')]
  if (narrow) {
    const side = [...tiers[0], ...tiers[1]], col = (list, x) => list.forEach((n, i) => at.set(n.id, { x, y: Math.round((h * (i + 0.5)) / list.length) }))
    col(side, 72); col(tiers[2], 288)
    return at
  }
  const ys = [64, 210, 390]
  tiers.forEach((list, t) => list.forEach((n, i) => at.set(n.id, { x: Math.round((w * (i + 1)) / (list.length + 1)), y: ys[t] })))
  return at
}

const hex = (x, y, r) => Array.from({ length: 6 }, (_, k) => {
  const a = Math.PI / 6 + (k * Math.PI) / 3
  return `${(x + r * Math.cos(a)).toFixed(1)},${(y + r * Math.sin(a)).toFixed(1)}`
}).join(' ')

// A curve bowed to its right, so A→B and B→A never overlap, trimmed to stop at each hexagon.
function curve(a, b) {
  const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1
  const ux = dx / len, uy = dy / len, bow = Math.min(36, len / 5)
  const c = { x: (a.x + b.x) / 2 - uy * bow, y: (a.y + b.y) / 2 + ux * bow }
  const trim = (p, q) => { const d = Math.hypot(q.x - p.x, q.y - p.y) || 1; return { x: p.x + ((q.x - p.x) * (R + 3)) / d, y: p.y + ((q.y - p.y) * (R + 3)) / d } }
  const s = trim(a, c), e = trim(b, c)
  return `M${s.x.toFixed(1)},${s.y.toFixed(1)} Q${c.x.toFixed(1)},${c.y.toFixed(1)} ${e.x.toFixed(1)},${e.y.toFixed(1)}`
}

const isAgent = (sw, id) => kind(sw.nodes.find(n => n.id === id)?.kind) === 'agent'
const isPeer = (sw, e) => isAgent(sw, e.from) && isAgent(sw, e.to)

// How much of the fleet may task the rest of it: the one fact that turns twenty arrows into a sentence.
export function peerSummary(sw) {
  const agents = sw.nodes.filter(n => kind(n.kind) === 'agent'), pairs = agents.length * (agents.length - 1)
  const held = new Set(sw.edges.filter(e => e.type === 'instructs' && isPeer(sw, e) && e.from !== e.to).map(e => `${e.from}>${e.to}`)).size
  const text = !pairs ? 'one agent, no peers' : held === pairs ? 'every agent may task every other' : held === 0 ? 'no agent may task another' : `${held} of ${pairs} peer grants`
  return { pairs, held, text }
}

function graph(sw, { show, selected, narrow, added }) {
  const at = layout(sw.nodes, { narrow }), { w, h } = canvasSize(sw.nodes, { narrow })
  const touches = e => !selected || e.from === selected || e.to === selected
  // Peer edges are the bulk of the drawing and say one thing, which the fleet caption says instead.
  // They come back for the node you select, so its own peers are never hidden.
  // A voice's edges repeat its grantor's, so unless the voice is selected it is drawn once, as the
  // key it speaks for.
  const drawn = sw.edges.filter(e => EDGE_TYPES.includes(e.type) && show[e.type] && at.has(e.from) && at.has(e.to) && e.from !== e.to
    && (show.peers || !isPeer(sw, e) || (selected && touches(e))))
  const edges = drawn.filter(e => !e.voice_of || (selected && touches(e)))
  const speaks = show.instructs ? sw.nodes.filter(n => n.voice_of && at.has(n.voice_of) && drawn.some(e => e.voice_of && e.from === n.id) && !(selected && edges.some(e => e.voice_of && e.from === n.id))) : []
  const near = new Set(selected ? [selected, ...edges.filter(touches).flatMap(e => [e.from, e.to])] : sw.nodes.map(n => n.id))
  const paths = edges.map(e => `<path class="edge ${e.type}${e.voice_of ? ' voice' : ''}${touches(e) ? '' : ' cold'}${added.has(edgeKey(e)) ? ' new' : ''}" d="${curve(at.get(e.from), at.get(e.to))}" marker-end="url(#arrow-${e.type})"><title>${esc(label(sw.nodes.find(n => n.id === e.from)))} ${e.type === 'instructs' ? `may instruct (${esc(capText(e.cap))}${e.voice_of ? ', as a voice' : ''})` : 'may wake'} ${esc(label(sw.nodes.find(n => n.id === e.to)))}</title></path>`).join('')
  const voices = speaks.map(n => `<path class="edge instructs voice speaks${selected && selected !== n.id && selected !== n.voice_of ? ' cold' : ''}" d="${curve(at.get(n.id), at.get(n.voice_of))}" marker-end="url(#arrow-instructs)"><title>${esc(label(n))} speaks as ${esc(label(sw.nodes.find(x => x.id === n.voice_of)))}, with its reach</title></path>`).join('')
  const agents = sw.nodes.filter(n => kind(n.kind) === 'agent').map(n => at.get(n.id))
  let fleet = ''
  if (agents.length) {
    const xs = agents.map(p => p.x), ys = agents.map(p => p.y), pad = R + 18
    const box = { x: Math.min(...xs) - pad, y: Math.min(...ys) - pad, x2: Math.max(...xs) + pad, y2: Math.max(...ys) + pad + (narrow ? 22 : 40) }
    fleet = `<g class="fleet"><rect x="${box.x}" y="${box.y}" width="${box.x2 - box.x}" height="${box.y2 - box.y}" rx="14"/>
${narrow ? '' : `<text x="${box.x + 12}" y="${box.y2 - 10}">fleet · ${agents.length} agents · ${esc(peerSummary(sw).text)}</text>`}</g>`
  }
  const cells = sw.nodes.map(n => {
    const p = at.get(n.id)
    return `<g class="node ${kind(n.kind)} ${colour(n.colour)}${n.id === selected ? ' selected' : ''}${near.has(n.id) ? '' : ' cold'}" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(label(n))}">
  <polygon points="${hex(p.x, p.y, R)}"/><text x="${p.x}" y="${p.y + R + 16}" text-anchor="middle">${esc(label(n))}</text>
  <text class="pk" x="${p.x}" y="${p.y + 4}" text-anchor="middle">${esc(String(n.id).slice(0, 4))}</text></g>`
  }).join('')
  const marker = t => `<marker id="arrow-${t}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="tip ${t}" d="M0,0 L10,5 L0,10 z"/></marker>`
  return `<svg class="swarm" viewBox="0 0 ${w} ${h}" role="img" aria-label="who may instruct and wake whom"><defs>${EDGE_TYPES.map(marker).join('')}</defs>${fleet}${voices}${paths}${cells}</svg>`
}

const who = (sw, id) => { const n = sw.nodes.find(x => x.id === id); return `${esc(label(n))} <code>${esc(id)}</code>` }
const list = items => (items.length ? `<ul>${items.map(i => `<li>${i}</li>`).join('')}</ul>` : '<p class="dim">nobody</p>')

// Keys that hold a live grant and that no manifest, mention list or NIP-05 name identifies.
const strangers = sw => sw.nodes.filter(x => kind(x.kind) === 'unknown' && sw.edges.some(e => e.type === 'instructs' && e.from === x.id))

// The sentences a reader needs before any drawing: who the root is, who speaks for whom, who else
// holds authority, how the fleet is wired among itself, and anything that needs a decision.
function summary(sw) {
  const agents = sw.nodes.filter(n => kind(n.kind) === 'agent')
  const out = id => sw.edges.filter(e => e.type === 'instructs' && e.from === id)
  const reach = id => { const to = new Set(out(id).map(e => e.to)); return to.size === agents.length ? 'all' : `${to.size} of ${agents.length}` }
  const lines = sw.nodes.filter(n => kind(n.kind) === 'grantor').map(g => `<li><b>${esc(label(g))}</b> signs the grants and may instruct ${reach(g.id)} agents.</li>`)
  for (const v of sw.nodes.filter(n => n.voice_of)) lines.push(`<li><b>${esc(label(v))}</b> is ${esc(label(sw.nodes.find(n => n.id === v.voice_of)))}'s voice: one shadow grant gives it ${reach(v.id)} agents, and one revocation takes them all.</li>`)
  for (const k of sw.nodes.filter(n => kind(n.kind) === 'named' && !n.voice_of && out(n.id).length)) lines.push(`<li><b>${esc(label(k))}</b> may instruct ${reach(k.id)} agents on its own grants.</li>`)
  lines.push(`<li>The fleet: ${esc(peerSummary(sw).text)}.</li>`)
  const deaf = agents.filter(a => !sw.edges.some(e => e.type === 'instructs' && e.to === a.id))
  const warn = [...strangers(sw).map(u => `<li><code>${esc(u.id)}</code> holds live task grants and nobody has named it. Identify it, or revoke its grants.</li>`),
    ...deaf.map(a => `<li>Nobody may instruct <b>${esc(label(a))}</b>, so it can only be woken, never tasked.</li>`)]
  return `<ul class="facts">${lines.join('')}</ul>${warn.length ? `<div class="warn"><b>Needs a decision</b><ul>${warn.join('')}</ul></div>` : ''}`
}

function panel(sw, id) {
  const n = sw.nodes.find(x => x.id === id)
  if (!n) {
    const unknown = strangers(sw), count = t => sw.edges.filter(e => e.type === t).length
    return `<h3>The swarm</h3>
<p>${sw.nodes.filter(x => kind(x.kind) === 'agent').length} fleet agents, ${count('instructs')} live instruct grants, ${count('wakes')} wake rights.
Select a hexagon to see what it may do.</p>
${unknown.length ? `<div class="warn"><b>Keys nobody named hold live task grants:</b>${list(unknown.map(u => `<code>${esc(u.id)}</code> may instruct ${sw.edges.filter(e => e.type === 'instructs' && e.from === u.id).map(e => esc(label(sw.nodes.find(x => x.id === e.to)))).join(', ')}`))}Identify each one, or revoke its grants.</div>` : ''}`
  }
  const into = t => sw.edges.filter(e => e.type === t && e.to === id)
  const out = t => sw.edges.filter(e => e.type === t && e.from === id)
  const agent = kind(n.kind) === 'agent'
  return `<h3><span class="dot ${colour(n.colour)}"></span>${esc(label(n))} <code>${esc(n.id)}</code> <small>${esc(kind(n.kind))}</small></h3>
${kind(n.kind) === 'unknown' ? '<div class="warn">No manifest or mention list names this key. If it holds grants, find out whose it is or revoke them.</div>' : ''}
${n.voice_of ? `<p>Speaks as ${who(sw, n.voice_of)}'s voice: a shadow grant gives it that key's reach, and one revocation of grant <code>${esc(out('instructs')[0]?.grant || '')}</code> takes it all away.${out('instructs')[0] ? revokeLink(sw, out('instructs')[0]) : ''}</p>` : ''}
<h4>Takes instructions from</h4>${agent ? list(into('instructs').map(e => `${who(sw, e.from)} <small>${esc(capText(e.cap))}${e.voice_of ? ' as a voice' : ''} · ${esc(e.grant)}</small>${e.voice_of ? '' : revokeLink(sw, e)}`)) : '<p class="dim">not a fleet agent: its own broker, if any, is not measured here</p>'}
<h4>May instruct</h4>${list(out('instructs').map(e => `${who(sw, e.to)} <small>${esc(capText(e.cap))}${e.voice_of ? ' as a voice' : ''}</small>${e.voice_of ? '' : revokeLink(sw, e)}`))}
${agent ? `<h4>May wake (mention)</h4>${list(out('wakes').map(e => who(sw, e.to)))}` : ''}
<h4>Woken by</h4>${list(into('wakes').map(e => who(sw, e.from)))}
${agent ? rights(n) : ''}
<p class="manage"><a href="${CONSOLE}" target="_blank" rel="noopener">Open the waggle console →</a> <span class="dim">Revoke and grant links open it ready to sign; nothing is signed until you confirm there.</span></p>`
}

function rights(n) {
  const f = n.funnel || {}
  return `<dl class="rights">
<dt>Posts</dt><dd>${n.post ? `in ${(n.post.channels || []).map(c => `<code>${esc(c)}</code>`).join(', ')}, up to ${esc(n.post.per_hour)} an hour` : 'may only reply'}</dd>
<dt>Profile</dt><dd>${n.profile ? `kind 0, ${esc(n.profile.per_day)} a day, pictures from ${(n.profile.picture_hosts || []).map(esc).join(', ')}` : 'may not set it'}</dd>
<dt>Externally</dt><dd class="dim">not a capability yet</dd>
<dt>Brakes</dt><dd>${esc(n.limits?.max_hops)} hops, ${esc(n.limits?.per_sender_per_hour)} per sender an hour</dd>
<dt>Ears</dt><dd>${esc(n.delivery)}${n.door ? ' · channel door' : ''}${n.webhook ? ' · wake webhook' : ''}</dd>
<dt>Last 24h</dt><dd>${esc(f.heard ?? 0)} heard · ${esc(f.admitted ?? 0)} admitted · ${esc(f.replies ?? 0)} replies${f.data_only ? ` · ${esc(f.data_only)} data only` : ''}</dd>
<dt>Role</dt><dd class="dim">no brief issued yet</dd></dl>`
}

// Who may instruct one agent, in one line: every non-agent by name and capability, peers counted.
function instructors(sw, id) {
  const into = sw.edges.filter(e => e.type === 'instructs' && e.to === id)
  const rank = e => ({ grantor: 0, named: e.voice_of ? 1 : 2, unknown: 3 })[kind(sw.nodes.find(n => n.id === e.from)?.kind)] ?? 4
  const peers = into.filter(e => isAgent(sw, e.from)), others = into.filter(e => !isAgent(sw, e.from)).sort((a, b) => rank(a) - rank(b))
  const parts = others.map(e => `${esc(label(sw.nodes.find(n => n.id === e.from)))} <small>${esc(capText(e.cap))}${e.voice_of ? `, ${esc(label(sw.nodes.find(n => n.id === e.voice_of)))}'s voice` : ''}</small>`)
  if (peers.length) parts.push(`<span title="${esc(peers.map(e => label(sw.nodes.find(n => n.id === e.from))).join(', '))}">${peers.length} peer${peers.length === 1 ? '' : 's'}</span> <small>${esc([...new Set(peers.map(e => capText(e.cap)))].join(', '))}</small>`)
  return parts.length ? parts.join(' · ') : '<span class="dim">nobody</span>'
}

function roster(sw, selected) {
  const agents = sw.nodes.filter(n => kind(n.kind) === 'agent')
  if (!agents.length) return '<p class="dim">no fleet agents in this snapshot</p>'
  return `<div class="roster">${agents.map(n => {
    const wakes = sw.edges.filter(e => e.type === 'wakes' && e.from === n.id).map(e => label(sw.nodes.find(x => x.id === e.to)))
    return `<article class="card ${colour(n.colour)}${n.id === selected ? ' selected' : ''}" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(label(n))}">
<h3><span class="dot ${colour(n.colour)}"></span>${esc(label(n))} <code>${esc(n.id)}</code></h3>
<dl class="rights"><dt>Instructed by</dt><dd>${instructors(sw, n.id)}</dd>
<dt>May wake</dt><dd>${wakes.length ? esc(wakes.join(', ')) : '<span class="dim">nobody</span>'}</dd></dl>
${rights(n)}</article>`
  }).join('')}</div>`
}

// Every key that holds or is given a right, against every agent: one cell says all it may do there.
function matrix(sw, show, added) {
  const agents = sw.nodes.filter(n => kind(n.kind) === 'agent')
  const edges = sw.edges.filter(e => EDGE_TYPES.includes(e.type) && show[e.type])
  const rows = sw.nodes.filter(n => edges.some(e => e.from === n.id))
  if (!rows.length || !agents.length) return '<p class="dim">no edges of the selected kinds</p>'
  const order = { grantor: 0, named: 1, unknown: 2, agent: 3 }
  rows.sort((a, b) => order[kind(a.kind)] - order[kind(b.kind)])
  const cell = (f, t) => edges.filter(e => e.from === f.id && e.to === t.id).map(e => e.type === 'instructs'
    ? `<span class="badge instructs${e.voice_of ? ' voice' : ''}${added.has(edgeKey(e)) ? ' new' : ''}" title="${esc(capText(e.cap))}${e.voice_of ? ' as a voice' : ''} · grant ${esc(e.grant)}">${esc(capText(e.cap))}${e.voice_of ? ' ◇' : ''}</span>`
    : `<span class="badge wakes${added.has(edgeKey(e)) ? ' new' : ''}" title="may mention">wakes</span>`).join('')
  // A revoke link per held grant, and a grant link where a named key or an agent holds none. A
  // voice's cells all share one shadow grant, so its revoke is in its panel, not on every cell.
  const tools = (f, t) => {
    const held = edges.filter(e => e.type === 'instructs' && e.from === f.id && e.to === t.id)
    if (held.length) return held.filter(e => !e.voice_of).map(e => act(revokeHref(e.grant), '×', `Revoke grant ${e.grant} in the waggle console`)).join('')
    return ['named', 'agent'].includes(kind(f.kind)) && !f.voice_of && show.instructs ? act(grantHref(f.id, t.id), '+', `Grant ${label(f)} task on ${label(t)} in the waggle console`) : ''
  }
  return `<div class="scroll"><table class="grid"><thead><tr><th>from ↓ · to →</th>${agents.map(t => `<th scope="col">${esc(label(t))}</th>`).join('')}</tr></thead>
<tbody>${rows.map(f => `<tr><th scope="row">${f.name ? `${esc(f.name)} ` : ''}<code>${esc(f.id)}</code></th>${agents.map(t => `<td>${f.id === t.id ? '<span class="dim">·</span>' : cell(f, t) + tools(f, t)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>
<p class="dim legend-note">◇ held as a voice, through a shadow grant. Hover a cell for its grant. × revokes it and + grants task, in the waggle console, where you confirm and sign.</p>`
}

// What changed against the edges the reader last marked as seen. Removed edges can no longer be drawn,
// so they are listed by name.
export function changes(sw, seen) {
  if (!Array.isArray(seen)) return { added: new Set(), removed: [], fresh: true }
  const now = new Set(sw.edges.map(edgeKey)), was = new Set(seen)
  return { added: new Set([...now].filter(k => !was.has(k))), removed: [...was].filter(k => !now.has(k)), fresh: false }
}

function describeKey(sw, key) {
  const m = /^(\w+):([^>]+)>([^:]+):([^:]*):(.*)$/.exec(key)
  if (!m) return esc(key)
  const name = id => esc(label(sw.nodes.find(n => n.id === id)) === '?' ? id : label(sw.nodes.find(n => n.id === id)))
  return `${name(m[2])} ${m[1] === 'instructs' ? `may instruct (${esc(capText(m[4]))}${m[5] ? ', as a voice' : ''})` : 'may wake'} ${name(m[3])}`
}

function changeStrip(sw, ch) {
  if (ch.fresh) return ''
  if (!ch.added.size && !ch.removed.length) return ''
  const items = [...[...ch.added].map(k => `<li class="plus">+ ${describeKey(sw, k)}</li>`), ...ch.removed.map(k => `<li class="minus">− ${describeKey(sw, k)}</li>`)]
  return `<div class="changes"><b>Since you last looked</b> <button type="button" class="toggle" data-seen>Mark seen</button><ul>${items.join('')}</ul></div>`
}

export function renderSwarm(s, { show = { instructs: true, wakes: false, peers: false }, selected = null, view = 'overview', narrow = false, seen = null } = {}, now = Date.now()) {
  const age = ageVerdict(s?.generated_at, now)
  const banner = `<div class="age ${age.colour}" role="status">${esc(age.text)}</div>`
  if (!s || s.withheld || !s.swarm) return `${banner}<div class="banner red">${esc(s?.reason || 'this snapshot has no swarm section')}</div>`
  const sw = { nodes: (s.swarm.nodes || []).map(n => ({ ...n, id: String(n.id) })), edges: s.swarm.edges || [] }
  const sel = sw.nodes.some(n => n.id === selected) ? selected : null
  const v = VIEWS.includes(view) ? view : 'overview'
  const ch = changes(sw, seen)
  const tabs = VIEWS.map(t => `<button type="button" class="tab" data-view="${t}" aria-pressed="${t === v ? 'true' : 'false'}">${{ overview: 'Authority', agents: 'Agents', matrix: 'Matrix' }[t]}</button>`).join('')
  const toggles = [['instructs', 'Instructs'], ['wakes', 'Wakes'], ['peers', 'Peer grants']]
    .filter(([t]) => v !== 'agents' && !(t === 'peers' && v === 'matrix'))
    .map(([t, text]) => `<button type="button" class="toggle ${t}" data-toggle="${t}" aria-pressed="${show[t] ? 'true' : 'false'}">${text}</button>`).join('')
  const legend = v === 'overview' ? `<span class="legend"><svg width="28" height="8"><line x1="0" y1="4" x2="28" y2="4" class="edge instructs"/></svg>instructs <svg width="28" height="8"><line x1="0" y1="4" x2="28" y2="4" class="edge instructs voice"/></svg>as a voice <svg width="28" height="8"><line x1="0" y1="4" x2="28" y2="4" class="edge wakes"/></svg>wakes</span>` : ''
  const body = v === 'agents' ? roster(sw, sel)
    : v === 'matrix' ? matrix(sw, show, ch.added)
    : `<div class="split"><div class="canvas">${graph(sw, { show, selected: sel, narrow, added: ch.added })}</div><aside class="panel">${panel(sw, sel)}</aside></div>`
  return `${banner}${changeStrip(sw, ch)}
<section class="summary">${summary(sw)}</section>
<nav class="tabs" aria-label="views">${tabs}</nav>
<div class="toolbar">${toggles}${sel && v === 'overview' ? '<button type="button" class="toggle" data-clear>Show everyone</button>' : ''}${legend}</div>
${body}`
}
