// principal_family.mjs — which SSH principals a harness needs, and the one place each is written.
//
// The hosted onboarding route (waggle #721) seats an agent's channel key from a signed bind. Until now
// every key was seated as the Claude channel (participant_unit.mjs → claude-channel.mjs). Pi and Codex
// harnesses reach the fleet differently: two keys, each forced to exactly one program (docs/HARNESS_PLACEMENT.md,
// pi_harness_extension.mjs: "the channel and feed keys must be two keys").
//
//   claude family  one key   channel → claude-channel.mjs       comment nvoy-claude-channel-<id>   (unchanged)
//   codex family   two keys  channel → codex-channel-mcp.mjs    comment nvoy-codex-channel-<id>
//                            feed    → codex-channel-feed.mjs    comment nvoy-codex-feed-<id>
//
// The codex lines are what instance-codex-channel-authorized-key.mjs prints; that script now calls the
// builder here, so the generator, the verifier and the hosted route cannot drift apart.

import { parsePrincipal } from './participant_unit.mjs'

const NODE = '/usr/local/bin/node'
const DOCKER = '/usr/bin/docker'
const TOOLS = Object.freeze({ channel: ['codex-channel-mcp.mjs', 'nvoy-codex-channel'], feed: ['codex-channel-feed.mjs', 'nvoy-codex-feed'] })
const CONTAINER = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/

export const FAMILIES = Object.freeze({ claude: Object.freeze({ keys: ['channel'] }), codex: Object.freeze({ keys: ['channel', 'feed'] }) })
// Harnesses not listed here keep the Claude channel, as they did before this table existed.
const CODEX_FAMILY = new Set(['pi', 'codex'])
export const familyOf = harness => (CODEX_FAMILY.has(String(harness || '')) ? 'codex' : 'claude')
export const keysFor = harness => FAMILIES[familyOf(harness)].keys

export const codexComment = (manifest, role) => `${TOOLS[role][1]}-${manifest.id}`

export function codexForcedCommand(manifest, role, container = manifest.adapterContainer) {
  if (!TOOLS[role]) throw new Error('role must be channel or feed')
  if (!CONTAINER.test(String(container || ''))) throw new Error('the adapter container name is not valid')
  return `${DOCKER} exec -i --user ${manifest.workerUid}:${manifest.workerHandoffGid} ${container} ${NODE} /srv/nvoy/mcp/tools/${TOOLS[role][0]} --instance ${manifest.id}`
}

// restrict is first, as in participant_unit.principalLine: a later option cannot be read as part of the command.
export const codexPrincipalLine = (manifest, role, keyType, keyBody, container) =>
  `restrict,command="${codexForcedCommand(manifest, role, container)}" ${keyType} ${keyBody} ${codexComment(manifest, role)}`

// What a codex-family manifest must be for these principals to be safe to seat.
export function codexManifestRefusal(manifest) {
  if (manifest.brokerMode !== 'local' || manifest.deliveryMode !== 'notify_only' || manifest.workerEnabled)
    return 'a Codex or Pi channel principal requires a local-broker, worker-disabled notify_only instance'
  return null
}

// The channel and feed keys must be two keys: each forced command admits exactly one program.
export function distinctKeys(channelKey, feedKey) {
  return Boolean(channelKey && feedKey) && channelKey.keyBody !== feedKey.keyBody
}

// What to do to authorized_keys for one codex-family role, matched on its own comment so a line whose
// command has drifted is found and refused, never duplicated (the same rule as instance_apply.principalPlan).
export function codexPrincipalPlan(text, manifest, role, { keyType, keyBody }, container) {
  const want = codexPrincipalLine(manifest, role, keyType, keyBody, container)
  const comment = codexComment(manifest, role)
  const ours = String(text || '').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    .filter(l => { const p = parsePrincipal(l); return p ? p.comment === comment : l.includes(comment) })
  if (!ours.length) return { role, action: 'append', line: want }
  if (ours.length === 1 && ours[0] === want) return { role, action: 'present', line: want }
  return { role, action: 'refuse', line: want,
    why: `${ours.length} line(s) already carry ${comment} and ${ours.length > 1 ? 'which one authorises is ambiguous' : 'it is not the line this key and manifest produce'}; resolve by hand` }
}

// Every check is returned, passes included, as participant_unit.verifyPrincipal does.
export function verifyCodexPrincipal(manifest, role, line, container = manifest.adapterContainer) {
  const parsed = parsePrincipal(line)
  if (!parsed) return null
  const findings = []
  const check = (ok, label, detail = '') => findings.push({ ok, label, detail })
  check(parsed.options.includes('restrict'), 'restrict is intact', parsed.options.includes('restrict') ? '' : `options are ${parsed.options.join(',') || '(none)'}`)
  const reEnabled = parsed.options.filter(o => /^(?:pty|(?:agent|port|X11|user-rc)-forwarding)$/.test(o))
  check(!reEnabled.length, 'no restricted capability is re-enabled', reEnabled.join(','))
  const expected = codexForcedCommand(manifest, role, container)
  check(parsed.command === expected, `forced command is the ${role} program for this manifest`, parsed.command === expected ? '' : `installed: ${parsed.command}`)
  check(parsed.comment === codexComment(manifest, role), 'carries the expected principal comment', parsed.comment)
  const otherRole = role === 'feed' ? 'channel' : 'feed'
  check(!parsed.command.includes(`/${TOOLS[otherRole][0]} `), `does not run the ${otherRole} program`)
  check(!parsed.command.includes('claude-channel.mjs'), 'does not run the Claude channel')
  return { parsed, findings, ok: findings.every(f => f.ok) }
}
