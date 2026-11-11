// presence.mjs — is this agent's key connected? The pure parts: count, judge, decide, template.
//
// The proof the page wants (waggle #721 step 4) is a signed kind 30078 `nvoy-channel-presence` from the
// agent's own key, saying a channel process opened by THAT key is running. The evidence is the process
// itself: the SSH forced command puts the line's key fingerprint in the channel child's argv
// (participant_unit.mjs), so `claude-channel.mjs --instance <id> --key-fp <fp>` names its key.
//
// Only the host sees those processes, and only the broker may sign. So a root host collector counts
// and writes a snapshot, and the broker reads it. Nothing here touches /proc, Docker, a relay or a key.
//
// Three rules keep the claim honest:
//   - A process counts only when its cgroup is the manifest's adapter container, its real uid is the
//     manifest's worker uid, and its COMPLETE argv is exactly the channel command. A host process that
//     only prints the same words does not count.
//   - Silence is not a drop. A snapshot that is missing, stale, for another key, or that holds only older
//     untagged sessions yields `unproven`, and nothing is published. Only a fresh snapshot that finds no
//     bound session at all says `disconnected`.
//   - One record, replaced before it is sent. A retry sends the newest decision only, so an older
//     `connected: true` can never follow a newer disconnect.

import { channelArgv } from './participant_unit.mjs'
import { codexArgv } from './principal_family.mjs'

export const PRESENCE_KIND = 30078
export const PRESENCE_D = 'nvoy-channel-presence'
export const PRESENCE_TTL_SEC = 2 * 60 * 60        // NIP-40 expiration on the signed event
export const PRESENCE_REFRESH_SEC = 30 * 60        // re-sign an unchanged state this often, well inside the TTL
export const SNAPSHOT_MAX_AGE_SEC = 90             // the collector runs every 30 s
const FP = /^SHA256:[A-Za-z0-9+/]{43}$/

// The cgroup file's paths (v2: one `0::/path` line; v1: `N:controllers:/path` lines), as component lists.
const cgroupPaths = text => String(text || '').split('\n').map(l => l.split(':').slice(2).join(':')).filter(Boolean).map(p => p.split('/').filter(Boolean))

// True only when the adapter container's id is a whole Docker cgroup component: systemd's
// `docker-<id>.scope`, or `<id>` directly under `docker`. A path that merely contains the id as part of
// another name (`not-docker-<id>-other.scope`) is not the container.
export function inContainer(cgroup, containerId) {
  if (!/^[0-9a-f]{64}$/.test(String(containerId || ''))) return false
  return cgroupPaths(cgroup).some(parts => parts.some((c, i) => c === `docker-${containerId}.scope` || (c === 'docker' && parts[i + 1] === containerId)))
}

const sameArgv = (a, b) => a.length === b.length && a.every((v, i) => v === b[i])

// null when the argv is not exactly this instance's channel command; otherwise the fingerprint it
// names ('' for an older, untagged session).
export function parseChannelArgv(argv, manifest) {
  if (!Array.isArray(argv) || argv.some(v => typeof v !== 'string')) return null
  // The Claude channel, or the Pi/Codex channel program (principal_family.mjs): an agent has exactly one
  // channel principal, so whichever of the two exact argvs it runs is its channel. The feed program is
  // never a channel session.
  for (const base of [channelArgv(manifest), codexArgv(manifest, 'channel')]) {
    if (sameArgv(argv, base)) return { fp: '' }
    if (argv.length === base.length + 2 && sameArgv(argv.slice(0, base.length), base) && argv[base.length] === '--key-fp' && FP.test(argv[base.length + 1])) {
      return { fp: argv[base.length + 1] }
    }
  }
  return null
}

// procs: [{ pid, uid, cgroup, argv }] as read from /proc. containerId: the manifest's adapter
// container id, from Docker. Returns counts by fingerprint plus the older untagged sessions.
export function countSessions(procs, manifest, containerId) {
  const byFp = {}
  let untagged = 0
  if (!/^[0-9a-f]{64}$/.test(String(containerId || ''))) return { byFp, untagged, counted: 0 }
  for (const p of procs || []) {
    if (p?.uid !== manifest.workerUid) continue
    if (!inContainer(p.cgroup, containerId)) continue
    const parsed = parseChannelArgv(p.argv, manifest)
    if (!parsed) continue
    if (parsed.fp) byFp[parsed.fp] = (byFp[parsed.fp] || 0) + 1
    else untagged++
  }
  return { byFp, untagged, counted: untagged + Object.values(byFp).reduce((a, b) => a + b, 0) }
}

// What the collector writes for one instance. `keyFp` is the fingerprint of the key on the instance's
// installed authorized_keys line ('' when the line is absent or an older untagged one).
export function buildSnapshot({ manifest, procs, containerId, keyFp, now }) {
  const found = countSessions(procs, manifest, containerId)
  return {
    version: 1, instance: manifest.id, collected_at: Math.floor(now / 1000),
    adapter_found: /^[0-9a-f]{64}$/.test(String(containerId || '')),
    key_fp: FP.test(keyFp || '') ? keyFp : '',
    bound: keyFp && FP.test(keyFp) ? (found.byFp[keyFp] || 0) : 0,
    other_key: Object.entries(found.byFp).filter(([fp]) => fp !== keyFp).reduce((n, [, c]) => n + c, 0),
    untagged: found.untagged,
  }
}

// The judgment. `state` is connected | disconnected | unproven; `why` says what stopped a proof.
export function presenceVerdict(snapshot, { instance, fp, now, maxAgeSec = SNAPSHOT_MAX_AGE_SEC }) {
  const unproven = why => ({ state: 'unproven', why })
  if (!snapshot || snapshot.version !== 1) return unproven('no usable snapshot')
  if (snapshot.instance !== instance) return unproven('snapshot is for another instance')
  if (!FP.test(fp || '')) return unproven('this seat has no key fingerprint')
  if (snapshot.key_fp !== fp) return unproven('snapshot names a different key')
  const age = Math.floor(now / 1000) - snapshot.collected_at
  if (!Number.isFinite(age) || age < -30 || age > maxAgeSec) return unproven(`snapshot is ${age} s old`)
  if (!snapshot.adapter_found) return unproven('the collector could not find the adapter container')
  if (snapshot.bound > 0) return { state: 'connected', sessions: snapshot.bound }
  if (snapshot.untagged > 0) return unproven('only older untagged sessions are running; their key is unknown')
  return { state: 'disconnected', sessions: 0 }
}

// The next signed event owed, or null. `last` is the stored record ({ connected, since, event_at,
// event }). The new record replaces `last` before anything is sent.
export function nextPresence(last, verdict, now) {
  if (verdict.state === 'unproven') return null
  const sec = Math.floor(now / 1000)
  const connected = verdict.state === 'connected'
  const changed = !last || last.connected !== connected
  if (!changed && sec - last.event_at < PRESENCE_REFRESH_SEC) return null
  return { connected, since: changed ? sec : last.since, seen_at: sec }
}

export function presenceTemplate({ instance, fp, connected, since, seenAt }, now, after = 0) {
  const sec = Math.floor(now / 1000)
  // NIP-01 timestamps are seconds: stay strictly after the last event so a newer state always wins.
  const createdAt = Math.max(sec, (Number.isSafeInteger(after) ? after : 0) + 1)
  return {
    kind: PRESENCE_KIND, created_at: createdAt,
    tags: [['d', PRESENCE_D], ['expiration', String(createdAt + PRESENCE_TTL_SEC)]],
    content: JSON.stringify({ instance, key: fp, connected, since, seen_at: seenAt }),
  }
}
