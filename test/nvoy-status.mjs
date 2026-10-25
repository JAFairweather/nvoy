// Status S1: the collector's judgements, the grant grid, the §5 sanitiser, the page's age verdict,
// and one whole collector run against fixture facts, fixture manifests and two local relays.
import { WebSocketServer } from 'ws'
import { createServer } from 'node:http'
import { spawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { agentChecks, funnel, grantCheck, grantGrid, gridColumn, parseLog, platformChecks, relayChecks, sanitiserFindings, swarmView, webCheck, worst } from '../mcp/tools/status_snapshot.mjs'
import { ageVerdict, renderSnapshot } from '../mcp/tools/status-page/status-view.mjs'
import { canvasSize, changes, edgeKey, layout, peerSummary, renderSwarm } from '../mcp/tools/status-page/beeswarm-view.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const now = Date.now(), MIN = 60000
const iso = ms => new Date(ms).toISOString().replace('Z', '123456Z')
const log = lines => lines.map(([ago, msg]) => `${iso(now - ago)} ${msg}`).join('\n')
const hex = n => randomBytes(n).toString('hex')

// --- 1. colours and the funnel ---
ok('worst ignores grey and keeps red', worst(['grey', 'green', 'red', 'amber']) === 'red')
ok('all grey stays grey, never green', worst(['grey', 'grey']) === 'grey')
const parsed = parseLog('2026-10-20T20:45:01.123456789Z buzz-wake: hello\nnot a docker line')
ok('parseLog reads docker --timestamps and skips the rest', parsed.length === 1 && parsed[0].at === Date.parse('2026-10-20T20:45:01.123Z') && parsed[0].msg === 'buzz-wake: hello')

const m1 = hex(6), m2 = hex(6), m3 = hex(6)
const heard = parseLog(log([[20 * MIN, `buzz-wake: mention ${m1}… in abcd0123 marked`], [15 * MIN, `buzz-wake: mention ${m2}… in abcd0123 marked`], [10 * MIN, `buzz-wake: mention ${m3}… in abcd0123 marked`]]))
const verdicts = parseLog(log([
  [19 * MIN, `instance-broker-daemon: instance-broker-native: ${m1}… admitted from 4010ac43 (task)`],
  [14 * MIN, `instance-broker-daemon: instance-broker-native: ${m2}… author 4010ac43 holds no live task grant; heard as data only [no-grant-suspect: 0 of 2 relays]`],
  [13 * MIN, `instance-broker-daemon: ${m3}… held for retry: relays did not answer`],
  [12 * MIN, 'instance-broker-post: posted'],
]))
const f = funnel({ watcher: heard, broker: verdicts, now })
ok('funnel counts heard, admitted, data only, suspect, held and replies', f.heard === 3 && f.admitted === 1 && f.data_only === 1 && f.suspect === 1 && f.held === 1 && f.pending === 1 && f.replies === 1)
const manifest = { id: 'alpha', pubkey: 'a'.repeat(64), buzz: { statusReactions: true } }
const up = [{ role: 'watcher', running: true, startedAt: iso(now - 3 * 60 * MIN) }, { role: 'broker', running: true, startedAt: iso(now - 3 * 60 * MIN) }, { role: 'adapter', running: true, startedAt: iso(now - 3 * 60 * MIN) }]
const listening = parseLog(log([[2 * 60 * MIN, 'buzz-wake: listening on 2 channel(s) as abcdef012345…']]))
const byKey = r => Object.fromEntries(r.checks.map(c => [c.key, c]))
const suspectRun = byKey(agentChecks({ manifest, watcher: [...listening, ...heard], broker: verdicts, containers: up, now }))
ok('a no-grant-suspect verdict newer than the last admit turns the funnel red', suspectRun.funnel.colour === 'red' && /evicted/.test(suspectRun.funnel.reason))
const stuck = byKey(agentChecks({ manifest, watcher: [...listening, ...heard], broker: verdicts.filter(l => !/no-grant-suspect/.test(l.msg)), containers: up, now }))
ok('a mention heard 15 minutes ago with no verdict is red', stuck.funnel.colour === 'red' && /no verdict/.test(stuck.funnel.reason))
const m4 = hex(6)
const held = byKey(agentChecks({ manifest, watcher: [...listening, ...parseLog(log([[2 * MIN, `buzz-wake: mention ${m4}… in abcd0123 marked`]]))],
  broker: parseLog(log([[MIN, `instance-broker-daemon: ${m4}… held for retry: relays did not answer`]])), containers: up, now }))
ok('a mention held for retry under five minutes is amber', held.funnel.colour === 'amber')

// --- 2. ears, containers, platform, web ---
const failing = byKey(agentChecks({ manifest, watcher: parseLog(log([[2 * 60 * MIN, 'buzz-wake: listening on 2 channel(s) as abcdef012345…'], [MIN, 'buzz-wake: relay.example login failed (AUTH oracle unavailable) — retrying in 5000ms']])), containers: up, now }))
ok('a login that failed signing after the last listen turns ears and signing red', failing.ears.colour === 'red' && failing.signing.colour === 'red')
const down = byKey(agentChecks({ manifest, watcher: listening, containers: up.map(c => c.role === 'broker' ? { ...c, running: false } : c), now }))
ok('a stopped broker turns containers red', down.containers.colour === 'red' && /broker/.test(down.containers.reason))
ok('reactions are red until the status keeper logs that it started', down.reactions.colour === 'red')
const plat = platformChecks({ host: { uptimeSec: 600, diskPct: 91, memAvailPct: 40 }, deploy: { timerActive: true, deployedSha: 'b'.repeat(40), remoteHead: 'c'.repeat(40), settled: true }, prev: { bootAt: now - 5 * 24 * 60 * MIN }, now })
const pk = Object.fromEntries(plat.checks.map(c => [c.key, c.colour]))
ok('a reboot is amber, disk at 91% is red, a settled main ahead of the release is amber', pk.uptime === 'amber' && pk.disk === 'red' && pk.deploy === 'amber' && plat.state.rebootAt)
ok('a stopped deploy timer is red', platformChecks({ deploy: { timerActive: false } }).checks.find(c => c.key === 'deploy').colour === 'red')
ok('web: an expiring certificate is amber, an unreachable site red', webCheck('x', { status: 200, tlsDays: 10 }).colour === 'amber' && webCheck('x', { error: 'refused' }).colour === 'red')

// --- 3. the grant grid, from signed events ---
const sk = { director: generateSecretKey(), stranger: generateSecretKey() }
const pub = { director: getPublicKey(sk.director), alpha: getPublicKey(generateSecretKey()), beta: getPublicKey(generateSecretKey()), x: getPublicKey(sk.stranger) }
// waggle's scope construction (src/scope_hash.mjs), computed here independently of the module under test.
const scope = target => { const salt = hex(16); return ['da-scope', createHash('sha256').update(Buffer.concat([Buffer.from('waggle/da-scope/v1'), Buffer.from([0]), Buffer.from(target), Buffer.from(salt, 'hex')])).digest('hex'), salt] }
let t = Math.floor(now / 1000) - 3600
const grant = (by, grantee, target, cap, extra = []) => finalizeEvent({ kind: 440, created_at: t++, content: '', tags: [['p', grantee], scope(target), ['da-cap', cap], ...extra] }, sk[by])
const g1 = grant('director', pub.beta, pub.alpha, 'task')
const g2 = grant('director', pub.alpha, pub.beta, 'task')
const g3 = grant('director', pub.x, pub.alpha, 'task+act')
const r3 = finalizeEvent({ kind: 441, created_at: t++, content: '', tags: [['e', g3.id]] }, sk.director)
const gx = grant('director', pub.x, pub.beta, 'task', [['expiration', String(Math.floor(now / 1000) - 60)]])
// A copy, not a spread: nostr-tools caches a verified mark on the signed object, and a spread keeps it.
const forged = { ...JSON.parse(JSON.stringify(grant('director', pub.x, pub.alpha, 'task'))), content: 'tampered' }
const rogue = grant('stranger', pub.x, pub.beta, 'task')
const targets = [{ id: 'alpha', pubkey: pub.alpha, grantors: [pub.director], relays: ['relay#1', 'relay#2'] }, { id: 'beta', pubkey: pub.beta, grantors: [pub.director], relays: ['relay#1', 'relay#2'] }]
const heldBy = new Map([[g1.id, new Set(['relay#1', 'relay#2'])], [g2.id, new Set(['relay#1', 'elsewhere'])]])
const names = new Map([[pub.alpha, 'alpha'], [pub.beta, 'beta'], [pub.director, 'director']])
const grid = grantGrid({ events: [g1, g2, g3, r3, gx, forged, rogue], heldBy, targets, names })
const cell = (row, col) => grid.rows.find(r => r.pubkey === row.slice(0, 8)).cells[col]
ok('a live grant shows its cap, its 8-hex id and the relays of that broker that hold it', cell(pub.beta, 0).state === 'active' && cell(pub.beta, 0).cap === 'task' && cell(pub.beta, 0).grant === g1.id.slice(0, 8) && cell(pub.beta, 0).relays.join() === 'relay#1,relay#2')
ok('a relay the target broker does not read is not counted', cell(pub.alpha, 1).relays.join() === 'relay#1')
ok('a revoked grant is revoked, an expired one expired', cell(pub.x, 0).state === 'revoked' && cell(pub.x, 1).state === 'expired')
ok('a grant scoped to another target is none there', cell(pub.beta, 1).state === 'none' && cell(pub.alpha, 0).state === 'none')
ok('a forged event and a non-grantor\'s grant grant nothing', grid.rows.length === 3 && cell(pub.x, 1).state !== 'active')
ok('the grid names grantors, rows and columns by name and 8-hex only', grid.grantors[0].name === 'director' && grid.grantors[0].pubkey.length === 8 && grid.targets.map(x => x.name).join() === 'alpha,beta')
ok('a grant held on two relays is green', grantCheck(gridColumn(grid, 0)).colour === 'green')
ok('a grant held on one relay is amber', grantCheck(gridColumn(grid, 1)).colour === 'amber')
ok('no live grant is red', grantCheck(gridColumn(grantGrid({ events: [g3, r3], heldBy, targets, names }), 0)).colour === 'red')
const rc = relayChecks([{ label: 'relay#1', answered: true, ms: 40, ids: new Set([g1.id, g2.id]) }, { label: 'relay#2', answered: true, ms: 50, ids: new Set([g1.id]) }, { label: 'relay#3', answered: false, ms: 0, ids: new Set() }], g2.id)
ok('the retention canary: a relay that dropped the newest grant is amber, a silent one red', rc.map(r => r.colour).join() === 'green,amber,red')

// --- 4. the sanitiser: §5, what may leave the box ---
const leaks = {
  'an IPv4 address': 'wss://203.0.113.9/', 'an IPv6 address': 'wss://[2001:db8::1]/', 'an nsec': 'nsec1qqqq', 'a bunker URI': 'bunker://x?relay=y',
  'a nostrconnect URI': 'nostrconnect://x', 'a credential path': '/etc/nvoy/credentials/agent.nsec', 'a secret parameter': 'x?secret=abc',
  'a box hostname': 'ssh nvoy-fleet', 'a full 64-hex key or id': pub.alpha,
  // The token shapes an agent may never post (outbound_secrets.mjs), built at run time.
  'a GitHub token': 'token ' + 'gh' + 'p_' + 'Z8x6C4v2B0n8M6l4K2j0H8g6F4d2S0a8P6o4', 'an AWS access key': 'AK' + 'IA' + 'Q3ZT7RW2YX8V5N4M',
}
for (const [what, value] of Object.entries(leaks)) ok(`the sanitiser refuses ${what}`, sanitiserFindings({ a: [{ b: value }] }).some(x => x.what === what && x.path === '$.a[0].b'))
ok('the sanitiser reads keys as well as values', sanitiserFindings({ [pub.beta]: 1 }).length === 1)
ok('an allowlisted 64-hex passes', sanitiserFindings({ a: pub.alpha }, { allow64: [pub.alpha] }).length === 0)
ok('times, 8-hex prefixes, relay labels and versions pass', sanitiserFindings({ at: new Date(now).toISOString(), clock: '20:45Z', pk: pub.alpha.slice(0, 8), relay: 'relay#2', host: 'relay.ditto.pub', sha: 'd'.repeat(40), v: 'node 22.11.0' }).length === 0)

// --- 5. the page: age first, escaping always ---
ok('a snapshot a minute old is fresh', !ageVerdict(new Date(now - MIN).toISOString(), now).stale)
ok('a snapshot four minutes old is stale and red', ageVerdict(new Date(now - 4 * MIN).toISOString(), now).stale && ageVerdict(new Date(now - 4 * MIN).toISOString(), now).colour === 'red')
ok('a snapshot without a time is stale', ageVerdict(undefined, now).stale)
const staleHtml = renderSnapshot({ generated_at: new Date(now - 10 * MIN).toISOString(), overall: 'green', agents: [] }, now)
ok('a stale snapshot never shows its green overall', /STALE/.test(staleHtml) && !/overall green/.test(staleHtml) && /class="overall red"/.test(staleHtml))
const evil = renderSnapshot({ generated_at: new Date(now).toISOString(), overall: 'green', agents: [{ id: '<script>x</script>', pubkey: 'abcd0123', colour: 'green" onload="x', checks: [{ label: '<b>', colour: 'green', reason: '"><img src=x>' }], funnel: {} }] }, now)
ok('every value is escaped and colours are a closed set', !/<script>|<img/.test(evil) && /&lt;script&gt;/.test(evil) && /&lt;b&gt;/.test(evil) && !/onload/.test(evil))
ok('a withheld snapshot shows only its reason', /failed its own sanitiser/.test(renderSnapshot({ generated_at: new Date(now).toISOString(), withheld: true, overall: 'red', reason: 'this snapshot failed its own sanitiser (1 finding(s))' }, now)))

// --- 6. the swarm: instructs edges from live grants only, wakes edges from mention lists, strangers marked ---
const swarm = swarmView({
  manifests: [
    { id: 'alpha', pubkey: pub.alpha, grantors: [pub.director], deliveryMode: 'notify_only', mayPost: { channels: ['3f1c2a4b-x'], perHour: 5, mention: [{ name: 'director', pubkey: pub.director }] }, agentLimits: { maxHops: 3, perSenderPerHour: 10 } },
    { id: 'beta', pubkey: pub.beta, grantors: [pub.director], deliveryMode: 'notify_only', mayPost: null, agentLimits: { maxHops: 3, perSenderPerHour: 10 } }],
  grid, agents: [{ id: 'alpha', colour: 'green', funnel: { heard: 1 } }], names })
const kindOf = Object.fromEntries(swarm.nodes.map(n => [n.id, n.kind]))
const instructs = swarm.edges.filter(e => e.type === 'instructs').map(e => `${e.from}>${e.to}:${e.cap}`)
ok('the grantor, both agents and nobody else are nodes when every live grant holder is named', kindOf[pub.director.slice(0, 8)] === 'grantor' && kindOf[pub.alpha.slice(0, 8)] === 'agent' && kindOf[pub.beta.slice(0, 8)] === 'agent')
ok('only live grants become instructs edges: a revoked, expired, forged or rogue one does not',
  instructs.sort().join() === [`${pub.alpha.slice(0, 8)}>${pub.beta.slice(0, 8)}:task`, `${pub.beta.slice(0, 8)}>${pub.alpha.slice(0, 8)}:task`].sort().join() && !(pub.x.slice(0, 8) in kindOf))
ok('a mention right is a wakes edge', swarm.edges.some(e => e.type === 'wakes' && e.from === pub.alpha.slice(0, 8) && e.to === pub.director.slice(0, 8)))
ok('a fleet agent carries its speaking rights and brakes', swarm.nodes.find(n => n.name === 'alpha').post.per_hour === 5 && swarm.nodes.find(n => n.name === 'beta').post === null && swarm.nodes.find(n => n.name === 'alpha').limits.max_hops === 3)
const live = { ...grid, rows: [...grid.rows, { name: null, pubkey: 'f00dcafe', cells: [{ state: 'active', cap: 'task', grant: 'abcd1234' }, { state: 'none' }] }] }
const stranger = swarmView({ manifests: [], grid: live, names })
ok('a live grant held by a key nobody named is an unknown node, drawn and warned about', stranger.nodes.find(n => n.id === 'f00dcafe')?.kind === 'unknown'
  && /Keys nobody named hold live task grants/.test(renderSwarm({ generated_at: new Date(now).toISOString(), swarm: stranger }, {}, now)))
// A voice: the director holds a grant on alpha and shadows a key, which then reaches alpha as the director's voice.
const voicePk = getPublicKey(generateSecretKey())
const own = grant('director', pub.director, pub.alpha, 'task+act'), shadowed = grant('director', voicePk, pub.director, 'shadow')
const voiced = grantGrid({ events: [own, shadowed], heldBy: new Map([[shadowed.id, new Set(['relay#1', 'relay#2'])]]), targets, names: new Map([...names, [voicePk, 'voice']]) })
const vCell = voiced.rows.find(r => r.pubkey === voicePk.slice(0, 8))?.cells
ok('a voice holds the grantor\'s grant under the shadow grant, on the relays that hold the shadow', vCell?.[0].state === 'active' && vCell[0].cap === 'task+act' && vCell[0].grant === shadowed.id.slice(0, 8) && vCell[0].voice_of === pub.director.slice(0, 8) && vCell[0].relays.length === 2)
ok('and nothing where the grantor holds nothing', vCell?.[1].state === 'none')
const vSwarm = swarmView({ manifests: [{ id: 'alpha', pubkey: pub.alpha, grantors: [pub.director], deliveryMode: 'notify_only', mayPost: null, agentLimits: { maxHops: 3, perSenderPerHour: 10 } }], grid: voiced, names: new Map([...names, [voicePk, 'voice']]) })
const vEdge = vSwarm.edges.find(e => e.type === 'instructs' && e.from === voicePk.slice(0, 8))
ok('the swarm draws the voice\'s edge as a voice of the grantor', vEdge?.voice_of === pub.director.slice(0, 8) && vSwarm.nodes.find(n => n.id === voicePk.slice(0, 8))?.voice_of === pub.director.slice(0, 8))
const vPage = renderSwarm({ generated_at: new Date(now).toISOString(), swarm: vSwarm }, { selected: voicePk.slice(0, 8) }, now)
ok('the panel says whose voice it is and which one grant to revoke', /Speaks as director/.test(vPage) && vPage.includes(shadowed.id.slice(0, 8)) && /class="edge instructs voice/.test(vPage))
const spots = [...layout(swarm.nodes).values()]
ok('the layout gives every node its own place inside the drawing', spots.length === swarm.nodes.length && new Set(spots.map(p => `${p.x},${p.y}`)).size === spots.length && spots.every(p => p.x > 40 && p.x < 720 && p.y > 40 && p.y < 640))
const narrowAt = layout(swarm.nodes, { narrow: true }), narrowBox = canvasSize(swarm.nodes, { narrow: true })
ok('a phone draws the same nodes in two columns inside its narrower canvas', [...narrowAt.values()].every(p => p.x > 0 && p.x < narrowBox.w && p.y > 0 && p.y < narrowBox.h)
  && narrowAt.get(pub.alpha.slice(0, 8)).x === narrowAt.get(pub.beta.slice(0, 8)).x && narrowAt.get(pub.director.slice(0, 8)).x < narrowAt.get(pub.alpha.slice(0, 8)).x)
ok('authority reads top-down: grantors above the fleet', layout(swarm.nodes).get(pub.director.slice(0, 8)).y < layout(swarm.nodes).get(pub.alpha.slice(0, 8)).y)
const swSnap = sw => ({ generated_at: new Date(now).toISOString(), swarm: sw })
const peerPaths = page => (page.match(/<path class="edge instructs[ "]/g) || []).length
ok('peer grants become one caption, not a hairball', peerSummary(swarm).text === 'every agent may task every other' && peerPaths(renderSwarm(swSnap(swarm), {}, now)) === 0
  && /fleet · 2 agents · every agent may task every other/.test(renderSwarm(swSnap(swarm), {}, now)))
ok('peer edges come back when asked for, or for the node you select', peerPaths(renderSwarm(swSnap(swarm), { show: { instructs: true, peers: true } }, now)) === 2
  && peerPaths(renderSwarm(swSnap(swarm), { selected: pub.alpha.slice(0, 8) }, now)) === 2)
const vQuiet = renderSwarm(swSnap(vSwarm), {}, now)
ok('an unselected voice is drawn once, as speaking for its grantor', (vQuiet.match(/class="edge instructs voice speaks/g) || []).length === 1 && !/<path class="edge instructs voice(?! speaks)/.test(vQuiet))
ok('the matrix names each cap and marks a voice', /<span class="badge instructs voice[^>]*>task \+ act ◇<\/span>/.test(renderSwarm(swSnap(vSwarm), { view: 'matrix' }, now)))
ok('the agents view is one card per agent', (renderSwarm(swSnap(swarm), { view: 'agents' }, now).match(/<article class="card/g) || []).length === 2)
ok('the selected panel links to where grants are signed', /class="manage"><a href="https:\/\/waggle\.nave\.pub\/console\/"/.test(renderSwarm(swSnap(swarm), { selected: pub.alpha.slice(0, 8) }, now)))
const keys = swarm.edges.map(edgeKey)
ok('a first visit is the baseline and shows no changes', changes(swarm, null).fresh && !/Since you last looked/.test(renderSwarm(swSnap(swarm), {}, now)))
ok('nothing new since last look shows nothing', !/Since you last looked/.test(renderSwarm(swSnap(swarm), { seen: keys }, now)))
const moved = renderSwarm(swSnap(swarm), { seen: [...keys.slice(1), 'instructs:f00dcafe>beta0000:task:'], show: { instructs: true, wakes: true, peers: true } }, now)
ok('a change since last look is listed and highlighted, and a vanished grant is named', /Since you last looked/.test(moved) && /<li class="plus">/.test(moved) && /<li class="minus">− f00dcafe may instruct/.test(moved) && /class="edge [^"]* new"/.test(moved))
const evilSwarm = renderSwarm({ generated_at: new Date(now).toISOString(), swarm: { nodes: [{ id: 'aaaa0000', name: '<script>x</script>', kind: 'agent" onclick="x', colour: 'red" onload="x', grantors: [], limits: {} }], edges: [{ type: 'instructs', from: 'aaaa0000', to: 'aaaa0000', cap: '<img src=x>' }] } }, { selected: 'aaaa0000' }, now)
ok('the swarm page escapes every value and keeps kinds and colours to closed sets', !/<script>|<img|onclick|onload/.test(evilSwarm) && /&lt;script&gt;/.test(evilSwarm))
ok('a stale snapshot says so on the swarm page too', /class="age red"/.test(renderSwarm({ generated_at: new Date(now - 10 * MIN).toISOString(), swarm: swarm }, {}, now)))
ok('a withheld snapshot draws no swarm', /failed its own sanitiser/.test(renderSwarm({ generated_at: new Date(now).toISOString(), withheld: true, reason: 'this snapshot failed its own sanitiser (1 finding(s))' }, {}, now)) && !/<svg/.test(renderSwarm({ withheld: true, reason: 'x' }, {}, now)))

// --- 7. one collector run: fixture facts, fixture manifests, two local relays ---
const relay = held => new Promise(done => {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 }, () => done({ wss, url: `ws://127.0.0.1:${wss.address().port}` }))
  wss.on('connection', ws => ws.on('message', raw => {
    const [type, sub, filter] = JSON.parse(raw)
    if (type !== 'REQ') return
    for (const ev of held) if (filter.kinds.includes(ev.kind) && filter.authors.includes(ev.pubkey)) ws.send(JSON.stringify(['EVENT', sub, ev]))
    ws.send(JSON.stringify(['EOSE', sub]))
  }))
})
// Dead Rabbit's shape: a voice no manifest names, holding a live grant, named only by the published NIP-05 list.
pub.rabbit = getPublicKey(generateSecretKey())
const g4 = grant('director', pub.rabbit, pub.beta, 'task')
const relayA = await relay([g1, g2, g3, r3, g4]), relayB = await relay([g1, g3, r3])
const nip05 = await new Promise(done => {
  const srv = createServer((_, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ names: { _: pub.alpha, rabbit: pub.rabbit, impostor: pub.alpha, junk: 'nope' } })) })
  srv.listen(0, '127.0.0.1', () => done({ srv, url: `http://127.0.0.1:${srv.address().port}/.well-known/nostr.json` }))
})
const root = mkdtempSync(join(tmpdir(), 'nvoy-status-'))
const dirs = { instances: join(root, 'instances'), facts: join(root, 'facts'), state: join(root, 'state'), out: join(root, 'out') }
for (const d of [dirs.instances, join(dirs.facts, 'logs'), join(dirs.facts, 'deploy')]) mkdirSync(d, { recursive: true })
const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607'
const uid = process.getuid(), gid = process.getgid()
const fixture = (id, pubkey, n, extra = {}) => writeFileSync(join(dirs.instances, `${id}.json`), JSON.stringify({
  version: 1, id, pubkey, broker_mode: 'local', key_ref: '/etc/nvoy/credentials/agent.nsec', worker_enabled: false, delivery_mode: 'notify_only',
  state_dir: join(root, id, 'state'), runtime_dir: join(root, id, 'run'), spool_dir: join(root, id, 'spool'),
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + n, broker_uid: uid + n + 1, adapter_uid: uid + n + 2, worker_uid: uid + n + 3,
  grantors: [pub.director], relays: ['wss://198.51.100.7', 'wss://relay.example'], buzz: { relay: 'wss://buzz.example', channels: [CH] }, ...extra }))
fixture('alpha', pub.alpha, 10, { may_post: { channels: [CH], per_hour: 5, mention: [{ name: 'director', pubkey: pub.director }] } })
fixture('beta', pub.beta, 20)
writeFileSync(join(dirs.instances, 'alpha.json.bak'), '{}')
const started = iso(now - 3 * 60 * MIN)
writeFileSync(join(dirs.facts, 'containers.txt'), ['alpha-watcher', 'alpha-broker', 'alpha-adapter', 'beta-broker', 'beta-adapter'].map(c => `/nvoy-${c}-1|true|${started}|0`).concat(`/nvoy-beta-watcher-1|false|${started}|3`).join('\n') + '\n')
// Log text the page must never carry: an address, a full key, a message id.
writeFileSync(join(dirs.facts, 'logs', 'nvoy-alpha-watcher-1.log'), log([
  [3 * 60 * MIN, 'buzz-wake: wss://198.51.100.7 login failed (connect ECONNREFUSED 198.51.100.7:443) — retrying in 5000ms'],
  [2 * 60 * MIN, `buzz-wake: listening on 1 channel(s) as ${pub.alpha.slice(0, 12)}…`],
  [30 * MIN, `buzz-wake: mention ${m1}… in ${pub.director.slice(0, 8)} marked`]]) + '\n')
writeFileSync(join(dirs.facts, 'logs', 'nvoy-alpha-broker-1.log'), log([
  [2 * 60 * MIN, 'instance-broker-status: keeping status reactions for alpha'],
  [29 * MIN, `instance-broker-daemon: instance-broker-native: ${m1}… admitted from ${pub.director.slice(0, 8)} (task) event ${g1.id} nsec1secretsecret`]]) + '\n')
writeFileSync(join(dirs.facts, 'channels.txt'), '      1 claude-channel.mjs --instance alpha\n')
writeFileSync(join(dirs.facts, 'host.txt'), 'uptime_sec=360000\ndisk_pct=42\nmem_avail_pct=55\n')
const sha = 'e'.repeat(40)
writeFileSync(join(dirs.facts, 'deploy', 'DEPLOYED_SHA'), sha + '\n')
writeFileSync(join(dirs.facts, 'deploy', 'LAST_OUTCOME'), `current ${sha}\n`)
writeFileSync(join(dirs.facts, 'deploy', 'REMOTE_HEAD.json'), JSON.stringify({ head: sha, settled: true }))
writeFileSync(join(dirs.facts, 'deploy', 'timer'), 'active\n')

const collect = (web = '', names = nip05.url) => new Promise(done => {
  const p = spawn(process.execPath, ['mcp/tools/nvoy-status.mjs', '--facts', dirs.facts, '--state', dirs.state, '--out', dirs.out, '--instances', dirs.instances, '--web', web, '--names', names, '--timeout-ms', '3000'],
    { env: { ...process.env, NVOY_STATUS_RELAYS: `${relayA.url},${relayB.url}` }, stdio: ['ignore', 'pipe', 'pipe'] })
  let out = '', err = ''
  p.stdout.on('data', d => { out += d }); p.stderr.on('data', d => { err += d })
  p.on('exit', code => done({ code, out, err }))
})
const run = await collect()
const text = existsSync(join(dirs.out, 'status.json')) ? readFileSync(join(dirs.out, 'status.json'), 'utf8') : '{}'
const snap = JSON.parse(text)
ok('the collector exits 0 and writes status.json beside both pages', run.code === 0 && ['index.html', 'status-view.mjs', 'beeswarm.html', 'beeswarm-view.mjs'].every(f => existsSync(join(dirs.out, f))))
ok('the snapshot passes its own sanitiser and was not withheld', !snap.withheld && sanitiserFindings(snap).length === 0)
ok('no address, full key, event id, nsec or message id from the logs or manifests leaves', !/198\.51|127\.0\.0\.1|nsec1|credentials/.test(text) && !text.includes(pub.alpha) && !text.includes(g1.id) && !text.includes(m1) && !/[0-9a-f]{64}/.test(text))
ok('only exact <id>.json manifests are read', snap.agents?.map(a => a.id).join() === 'alpha,beta')
const alpha = Object.fromEntries((snap.agents?.[0]?.checks || []).map(c => [c.key, c.colour]))
ok('alpha is green on every function: ears, signing, grants on both relays, funnel, harness, reactions',
  snap.agents?.[0]?.colour === 'green' && alpha.ears === 'green' && alpha.signing === 'green' && alpha.grants === 'green' && alpha.funnel === 'green' && alpha.harness === 'green' && alpha.reactions === 'green')
ok('beta, whose watcher is down and whose grant one relay dropped, is red with grants amber',
  snap.agents?.[1]?.colour === 'red' && snap.agents[1].checks.find(c => c.key === 'grants').colour === 'amber')
ok('relays are labelled, never addressed, and the one missing the newest grant is amber', snap.relays?.map(r => `${r.label}:${r.colour}`).join() === 'relay#1:green,relay#2:amber')
const rows = Object.fromEntries((snap.grants?.rows || []).map(r => [r.name || r.pubkey, r.cells.map(c => c.state).join('/')]))
ok('the grid has the director as grantor and its rows by name', snap.grants?.grantors?.[0]?.name === 'director' && rows.beta === 'active/none' && rows.alpha === 'none/active' && rows[pub.x.slice(0, 8)] === 'revoked/none')
const swarmed = Object.fromEntries((snap.swarm?.nodes || []).map(n => [n.id, n]))
ok('the swarm names a voice from the published list, and a manifest id beats a published name',
  swarmed[pub.rabbit.slice(0, 8)]?.name === 'rabbit' && swarmed[pub.rabbit.slice(0, 8)]?.kind === 'named' && swarmed[pub.alpha.slice(0, 8)]?.name === 'alpha')
ok('the voice\'s live grant is an instructs edge to beta', snap.swarm?.edges?.some(e => e.type === 'instructs' && e.from === pub.rabbit.slice(0, 8) && e.to === pub.beta.slice(0, 8)))
ok('the release and overall are carried, and reboot state is kept', snap.release === sha.slice(0, 12) && snap.overall === 'red' && existsSync(join(dirs.state, 'collector-state.json')))

// A snapshot that would leak is never written: an endpoint named with an address withholds it all.
const leak = await collect('192.0.2.1=https://127.0.0.1:9/', '')
const withheld = readFileSync(join(dirs.out, 'status.json'), 'utf8')
ok('a leaking snapshot is replaced by a red withheld notice', JSON.parse(withheld).withheld === true && JSON.parse(withheld).overall === 'red' && !('agents' in JSON.parse(withheld)))
ok('the withheld notice carries neither the value nor its path', !/192\.0\.2|127\.0\.0/.test(withheld) && !/\$\./.test(withheld))
ok('the journal names where it was found, never what', leak.code === 0 && /withheld: an IPv4 address at \$\.web/.test(leak.err) && !/192\.0\.2/.test(leak.err))

relayA.wss.close(); relayB.wss.close(); nip05.srv.close()
process.exit(fails ? 1 : 0)
