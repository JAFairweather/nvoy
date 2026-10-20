// agent_post.mjs — nvoy_channel_post: an agent starting a conversation rather than answering one.
//
// The keyless channel MCP can only ask. It resolves the manifest's default channel and any mention
// names to keys, refuses what the manifest does not allow so the agent hears why at once, and
// appends one bounded `post-request`. The broker (instance-broker-post.mjs) re-validates every
// field against the manifest, enforces the hourly cap on its own durable counter, and signs. The
// advisory cap here counts the queue's own timestamps; it only spares the agent a silent refusal.

import { appendFileSync, existsSync, lstatSync, readFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { resolve } from 'node:path'
import { HOUR_MS } from './agent_limits.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const MAX_BYTES = 4000
export const POST_ONLY_REPLY = 'this identity may only reply'
export const postQueuePath = manifest => resolve(manifest.runtimeDir, 'post-requests.jsonl')

export function postToolSpec(manifest) {
  const m = manifest.mayPost
  const scope = m ? ` Channels: ${m.channels.join(', ')} (default ${m.channels[0]}). Mentionable: ${
    m.mention.map(e => e.name || e.pubkey).join(', ') || 'nobody'}. At most ${m.perHour} an hour.` : ` ${POST_ONLY_REPLY[0].toUpperCase()}${POST_ONLY_REPLY.slice(1)}.`
  return {
    name: 'nvoy_channel_post',
    description: `Start a new top-level message in a Buzz channel, optionally mentioning allowed participants by name or hex key. The broker checks the manifest's may_post block, signs and publishes.${scope}`,
    inputSchema: { type: 'object', properties: {
      text: { type: 'string', minLength: 1, maxLength: MAX_BYTES },
      channel: { type: 'string', pattern: UUID.source },
      mention: { type: 'array', items: { type: 'string', minLength: 1, maxLength: 64 }, maxItems: 16 },
    }, required: ['text'], additionalProperties: false },
  }
}

// Pure: tool arguments to the exact channel and keys, or the refusal the agent is shown.
export function resolvePost(manifest, args = {}) {
  const m = manifest.mayPost
  if (!m) return { code: 'NVOY_POST_NOT_PERMITTED', message: POST_ONLY_REPLY }
  const content = String(args.text || '').trim()
  if (!content || Buffer.byteLength(content) > MAX_BYTES) return { code: 'NVOY_BAD_POST', message: `text must be 1..${MAX_BYTES} bytes` }
  const channel = args.channel == null ? m.channels[0] : String(args.channel).toLowerCase()
  if (!m.channels.includes(channel)) return { code: 'NVOY_POST_CHANNEL_REFUSED', message: `channel is not in may_post.channels (${m.channels.join(', ')})` }
  if (args.mention != null && !Array.isArray(args.mention)) return { code: 'NVOY_BAD_POST', message: 'mention must be a list' }
  const mention = []
  for (const raw of args.mention || []) {
    const value = String(raw).trim().toLowerCase()
    const entry = m.mention.find(e => e.pubkey === value || e.name?.toLowerCase() === value)
    if (!entry) return { code: 'NVOY_POST_MENTION_REFUSED', message: `${HEX64.test(value) ? value.slice(0, 8) : value} is not on may_post.mention` }
    if (!mention.includes(entry.pubkey)) mention.push(entry.pubkey)
  }
  return { channel, mention, content }
}

// Broker side: the one shape a post request may have, re-checked against the manifest. The
// keyless writer may have put anything in the queue, so nothing it resolved is trusted.
export function validatePostRequest(row, manifest) {
  const keys = ['version', 'type', 'id', 'instance', 'channel', 'mention', 'content', 'requested_at']
  if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).some(k => !keys.includes(k)) ||
      row.version !== 1 || row.type !== 'post-request' || row.instance !== manifest.id || !/^[0-9a-f]{32}$/.test(String(row.id || '')) ||
      typeof row.content !== 'string' || !row.content.trim() || Buffer.byteLength(row.content) > MAX_BYTES ||
      !Array.isArray(row.mention) || !Number.isFinite(row.requested_at)) throw new Error('post request has an invalid or overbroad shape')
  if (!manifest.mayPost) throw new Error(`post refused: ${POST_ONLY_REPLY}`)
  if (!manifest.mayPost.channels.includes(row.channel)) throw new Error('post refused: channel is not in may_post.channels')
  const allowed = manifest.mayPost.mention.map(e => e.pubkey)
  if (new Set(row.mention).size !== row.mention.length) throw new Error('post request has an invalid or overbroad shape')
  const off = row.mention.find(p => !allowed.includes(p))
  if (off !== undefined) throw new Error(`post refused: ${String(off).slice(0, 8)} is not on may_post.mention`)
  return row
}

function queueRows(path) {
  const st = lstatSync(path)
  if (!st.isFile() || st.isSymbolicLink()) throw new Error('post request queue must be a regular non-symlink file')
  if (st.size > 64 * 1024 * 1024) throw new Error('post request queue exceeds its 64 MiB bound')
  return readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => { try { return JSON.parse(line) } catch { return null } })
}

// The keyless tool: resolve, advise on the cap, append. Returns the tool's JSON answer.
export function queuePost(manifest, args, now = Date.now()) {
  const resolved = resolvePost(manifest, args)
  if (resolved.code) return { error: resolved }
  const path = postQueuePath(manifest)
  // Provisioned by instance-runtime-init for a may_post manifest; the reader never creates it.
  if (!existsSync(path)) return { error: { code: 'NVOY_POST_QUEUE_FAILED', message: 'post request queue is not provisioned; re-run the runtime init' } }
  try {
    const recent = queueRows(path).filter(r => r?.type === 'post-request' && Number.isFinite(r.requested_at) && now - r.requested_at < HOUR_MS).length
    if (recent >= manifest.mayPost.perHour) return { error: { code: 'NVOY_POST_RATE_LIMITED', message: `over the hourly cap: ${recent}/${manifest.mayPost.perHour} posts in the last hour` } }
    const row = { version: 1, type: 'post-request', id: randomBytes(16).toString('hex'), instance: manifest.id,
      channel: resolved.channel, mention: resolved.mention, content: resolved.content, requested_at: now }
    appendFileSync(path, JSON.stringify(row) + '\n')
    return { ok: { queued: true, request: row.id, channel: row.channel, mention: row.mention } }
  } catch (error) { return { error: { code: 'NVOY_POST_QUEUE_FAILED', message: error.message } } }
}
