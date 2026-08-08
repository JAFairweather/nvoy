// participant_unit.mjs — the access surface of a participant identity, derived from its manifest.
//
// A participant used to be a rendered Compose file plus a step someone had to remember: the SSH
// principal that exposes its channel MCP was generated once and hand-installed, and nothing ever
// checked that what was installed still matched the manifest it came from (#154).
//
// Two rules follow from that, and this module exists to hold both:
//
//   1. The forced command is written in ONE place. It was previously a template literal inside the
//      key generator; a verifier with its own copy of that string would drift from the generator
//      exactly as the generator drifted from Compose. So the generator and the verifier call the
//      same function here.
//   2. The container is named from the manifest, never from Compose's project/service/index rule.
//
// Nothing in this module signs, reads a credential, or talks to Docker. It renders text and
// compares text.

const NODE = '/usr/local/bin/node'
const DOCKER = '/usr/bin/docker'
const TOOL = '/srv/nvoy/mcp/tools/claude-channel.mjs'

// The exact remote process an inbound channel connection is allowed to become. It runs as
// workerUid:workerHandoffGid — admitted tasks read-only, only the bounded channel cursor and reply
// queue writable — and it takes no argument from the caller.
export function forcedCommand(manifest) {
  return `${DOCKER} exec -i --user ${manifest.workerUid}:${manifest.workerHandoffGid} ${manifest.adapterContainer} ${NODE} ${TOOL} --instance ${manifest.id}`
}

export function principalComment(manifest) {
  return `nvoy-claude-channel-${manifest.id}`
}

// `restrict` is the load-bearing prefix: no shell, no agent/port/X11 forwarding, no PTY. It is
// written first so that a later option cannot be read as part of the command string.
export function principalLine(manifest, keyType, keyBody) {
  return `restrict,command="${forcedCommand(manifest)}" ${keyType} ${keyBody} ${principalComment(manifest)}`
}

// Pull apart an installed authorized_keys line without trusting its shape. Returns null when the
// line is not one of ours, so a file holding unrelated principals verifies cleanly.
export function parsePrincipal(line) {
  const text = String(line || '').trim()
  if (!text || text.startsWith('#')) return null
  const match = /^(.*?)command="([^"]*)"(.*?)\s+(ssh-ed25519|ecdsa-sha2-nistp256)\s+([A-Za-z0-9+/]+={0,2})(?:\s+(\S+))?\s*$/.exec(text)
  if (!match) return null
  const [, before, command, after, keyType, keyBody, comment] = match
  const options = `${before}${after}`.split(',').map(v => v.trim()).filter(Boolean)
  return { options, command, keyType, keyBody, comment: comment || '' }
}

// Every check is returned, passes included, so a caller can print what was proven rather than only
// what failed — and so a verifier that silently checks nothing is visible as an empty list.
export function verifyPrincipal(manifest, line) {
  const parsed = parsePrincipal(line)
  if (!parsed) return null
  const expected = forcedCommand(manifest)
  const findings = []
  const check = (ok, label, detail = '') => findings.push({ ok, label, detail })

  check(parsed.options.includes('restrict'), 'restrict is intact',
    parsed.options.includes('restrict') ? '' : `options are ${parsed.options.join(',') || '(none)'}`)
  // restrict disables these, but an explicit re-enable after it wins, and that is the shape an
  // apparently-harmless hand edit takes.
  const reEnabled = parsed.options.filter(o => /^(?:pty|(?:agent|port|X11|user-rc)-forwarding)$/.test(o))
  check(!reEnabled.length, 'no restricted capability is re-enabled', reEnabled.join(','))
  check(parsed.command === expected, 'forced command matches the manifest', parsed.command === expected ? '' : `installed: ${parsed.command}`)
  check(parsed.command.includes(` --user ${manifest.workerUid}:${manifest.workerHandoffGid} `), 'runs as the manifest worker uid:gid')
  check(parsed.command.includes(` ${manifest.adapterContainer} `), 'targets the manifest adapter container')
  check(parsed.command.endsWith(` --instance ${manifest.id}`), 'is bound to this instance')
  check(parsed.command.includes(TOOL), 'invokes the channel tool and nothing else')
  check(parsed.comment === principalComment(manifest), 'carries the expected principal comment', parsed.comment)
  return { parsed, findings, ok: findings.every(f => f.ok) }
}
