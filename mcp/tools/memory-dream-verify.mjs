// mcp/tools/memory-dream-verify.mjs — Deterministic structural verifier and canonical record assembler
// for post-cycle AI Dream Narratives.
//
// Security & Trust Boundary:
//   - `memory-curate.mjs` writes `/var/lib/hive-memory-curator/packets/dream-<write_seq>.json` (mode 0640,
//     filtered strictly to the global room scope).
//   - `@curator` (`agent-curator`) reads the packet (treating all packet text as untrusted data, never
//     instructions) and drafts ONLY `{ title, dream, referenced_change_ids }`.
//   - This verifier checks that:
//       1. `title` is plain text (1..140 chars, no markup, no raw hex IDs, no @mentions).
//       2. `dream` is plain, voice-friendly prose (1..300 words, no markdown fences/headers/bullets,
//          no HTML tags, no raw 16+ hex IDs, no URLs, no @mentions that could wake agents).
//       3. `referenced_change_ids` is a non-empty array and every ID exists in `packet.changes`.
//   - On pass, THIS script copies `id`, `at`, `ledger_ref`, and EVERY item in `packet.changes`
//     (`[{ kind, claim_event_id, summary }]`) verbatim from the packet, sets `checked: true` and
//     `validation: "structural"`, and emits the canonical JSON record for:
//       - Buzz `#dream-journal`
//       - The Illustrated Primer dream page
//       - R1's "tell me the latest dream" voice command

import { chmodSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { basename, dirname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

export const DEFAULT_CURATOR_PACKET_DIR = '/var/lib/hive-memory-curator/packets'

const HEX16_RE = /\b[0-9a-fA-F]{16,64}\b/
const HTML_TAG_RE = /<\/?[a-zA-Z][^>]*>/
const MD_FENCE_RE = /```/
const MD_HEADER_RE = /(?:^|\n)\s*#{1,6}\s+/
const URL_RE = /\b(?:https?|file):\/\/\S+/i
const AT_MENTION_RE = /(?:^|[\s(])@[a-zA-Z0-9_-]+/

export function countWords(text) {
  const trimmed = String(text || '').trim()
  if (!trimmed) return 0
  return trimmed.split(/\s+/).filter(Boolean).length
}

export function verifyAndAssembleDreamRecord({ packet, draft } = {}) {
  const errors = []

  if (!packet || typeof packet !== 'object' || Array.isArray(packet)) {
    return { ok: false, errors: ['packet must be a JSON object'], record: null }
  }
  if (typeof packet.id !== 'string' || !/^dream-\d+$/.test(packet.id)) {
    errors.push('packet.id must match "dream-<write_seq>"')
  }
  if (typeof packet.at !== 'string' || !packet.at.trim()) {
    errors.push('packet.at must be a non-empty ISO timestamp string')
  }
  if (typeof packet.ledger_ref !== 'string' || !packet.ledger_ref.trim()) {
    errors.push('packet.ledger_ref must be a non-empty string')
  }
  if (!Array.isArray(packet.changes) || packet.changes.length === 0) {
    errors.push('packet.changes must be a non-empty array')
  }

  if (!draft || typeof draft !== 'object' || Array.isArray(draft)) {
    return { ok: false, errors: [...errors, 'draft must be a JSON object'], record: null }
  }

  const title = typeof draft.title === 'string' ? draft.title.trim() : ''
  if (!title) {
    errors.push('draft.title must be a non-empty string')
  } else {
    if (title.length > 140) errors.push(`draft.title exceeds 140 chars (${title.length})`)
    if (HEX16_RE.test(title)) errors.push('draft.title must not contain raw 16+ hex IDs')
    if (HTML_TAG_RE.test(title) || MD_FENCE_RE.test(title) || MD_HEADER_RE.test(title)) {
      errors.push('draft.title must be plain text without markdown headers/fences or HTML tags')
    }
    if (AT_MENTION_RE.test(title)) {
      errors.push('draft.title must not contain @mentions')
    }
  }

  const dream = typeof draft.dream === 'string' ? draft.dream.trim() : ''
  const wordCount = countWords(dream)
  if (!dream) {
    errors.push('draft.dream must be a non-empty string')
  } else {
    if (wordCount < 1 || wordCount > 300) {
      errors.push(`draft.dream word count must be between 1 and 300 words (got ${wordCount})`)
    }
    if (dream.length > 2400) {
      errors.push(`draft.dream exceeds 2400 chars (${dream.length})`)
    }
    if (MD_FENCE_RE.test(dream) || MD_HEADER_RE.test(dream)) {
      errors.push('draft.dream must be plain prose without markdown code fences or headers')
    }
    if (HTML_TAG_RE.test(dream)) {
      errors.push('draft.dream must not contain HTML tags')
    }
    if (HEX16_RE.test(dream)) {
      errors.push('draft.dream must not contain raw 16+ hex IDs (not voice-safe for R1)')
    }
    if (URL_RE.test(dream)) {
      errors.push('draft.dream must not contain raw URLs (not voice-safe for R1)')
    }
    if (AT_MENTION_RE.test(dream)) {
      errors.push('draft.dream must not contain @mentions')
    }
  }

  const validIds = new Set()
  const rawChanges = Array.isArray(packet.changes) ? packet.changes : []
  for (let i = 0; i < rawChanges.length; i++) {
    const ch = rawChanges[i]
    if (!ch || typeof ch !== 'object' || Array.isArray(ch)) {
      errors.push(`packet.changes[${i}] must be an object`)
      continue
    }
    if (typeof ch.change_id === 'string' && ch.change_id) validIds.add(ch.change_id)
    if (typeof ch.claim_event_id === 'string' && ch.claim_event_id) validIds.add(ch.claim_event_id)
    const summary = typeof ch.summary === 'string' ? ch.summary.trim() : ''
    if (!summary) {
      errors.push(`packet.changes[${i}].summary must be a non-empty string`)
    } else {
      if (AT_MENTION_RE.test(summary)) {
        errors.push(`packet.changes[${i}].summary must not contain @mentions`)
      }
      if (URL_RE.test(summary)) {
        errors.push(`packet.changes[${i}].summary must not contain raw URLs`)
      }
      if (HTML_TAG_RE.test(summary)) {
        errors.push(`packet.changes[${i}].summary must not contain HTML tags`)
      }
      if (HEX16_RE.test(summary)) {
        errors.push(`packet.changes[${i}].summary must not contain raw 16+ hex IDs`)
      }
    }
  }

  if (!Array.isArray(draft.referenced_change_ids) || draft.referenced_change_ids.length === 0) {
    errors.push('draft.referenced_change_ids must be a non-empty array of packet change IDs')
  } else {
    for (const refId of draft.referenced_change_ids) {
      if (typeof refId !== 'string' || !refId.trim()) {
        errors.push('draft.referenced_change_ids must contain only non-empty strings')
        break
      }
      if (!validIds.has(refId.trim())) {
        errors.push(`draft.referenced_change_ids contains unknown ID not in packet.changes: ${refId}`)
      }
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors, record: null }
  }

  const canonicalChanges = packet.changes.map(ch => ({ ...ch }))

  const record = {
    id: packet.id,
    title,
    at: packet.at,
    ledger_ref: packet.ledger_ref,
    dream: dream.replace(/\s+/g, ' '),
    referenced_change_ids: [...new Set(draft.referenced_change_ids.map(id => id.trim()))],
    changes: canonicalChanges,
    checked: true,
    validation: 'structural',
  }

  return {
    ok: true,
    errors: [],
    word_count: wordCount,
    record,
  }
}

export function formatDreamBuzzPost(record) {
  if (!record || !record.checked) {
    throw new Error('cannot format unchecked dream record for Buzz')
  }
  const changeLines = (record.changes || []).slice(0, 8).map(
    c => `- [${c.kind}] ${c.summary} (claim ${String(c.claim_event_id).slice(0, 8)})`
  )
  const moreCount = Math.max(0, (record.changes || []).length - changeLines.length)
  if (moreCount > 0) {
    changeLines.push(`- (+${moreCount} more consolidated changes in ${record.id})`)
  }
  return [
    `🌙 **${record.title}** (\`${record.id}\`, validation: \`${record.validation}\`)`,
    '',
    record.dream,
    '',
    '**Consolidated Changes:**',
    ...changeLines,
  ].join('\n')
}

export function dreamVerifyToolSpec() {
  return {
    name: 'memory_dream_verify',
    description: 'Structurally verify a post-cycle Merkle Dreaming draft ({ title, dream, referenced_change_ids }) against its cycle packet (dream-<write_seq>.json in /var/lib/hive-memory-curator/packets/) and return the checked canonical dream record and formatted Buzz post, without needing shell access.',
    inputSchema: {
      type: 'object',
      properties: {
        packet_path: {
          type: 'string',
          description: 'Path to the cycle dream packet JSON file inside /var/lib/hive-memory-curator/packets/ (e.g. /var/lib/hive-memory-curator/packets/dream-1142.json).',
          minLength: 1,
          maxLength: 512,
        },
        title: {
          type: 'string',
          description: 'Plain-text dream title (1..140 chars, no markdown/HTML/hex IDs/@mentions).',
          minLength: 1,
          maxLength: 140,
        },
        dream: {
          type: 'string',
          description: 'Plain, voice-friendly dream prose (1..300 words, <=2400 chars, no markdown fences/headers, HTML tags, URLs, raw 16+ hex IDs, or @mentions).',
          minLength: 1,
          maxLength: 2400,
        },
        referenced_change_ids: {
          type: 'array',
          description: 'Non-empty array of change_id or claim_event_id strings from packet.changes referenced by this dream.',
          items: { type: 'string', minLength: 1, maxLength: 128 },
          minItems: 1,
          maxItems: 64,
        },
      },
      required: ['packet_path', 'title', 'dream', 'referenced_change_ids'],
      additionalProperties: false,
    },
  }
}

export function runDreamVerifyTool(args = {}, { packetDir } = {}) {
  const allowedDir = resolve(packetDir || process.env.HIVE_MEMORY_CURATOR_PACKET_DIR || DEFAULT_CURATOR_PACKET_DIR)
  const rawPath = typeof args.packet_path === 'string' ? args.packet_path.trim() : ''
  if (!rawPath) {
    return { error: { code: 'NVOY_BAD_DREAM_PACKET', message: 'packet_path is required' } }
  }
  const resolvedPacket = resolve(rawPath)
  const fileBase = basename(resolvedPacket)
  if (
    dirname(resolvedPacket) !== allowedDir ||
    !resolvedPacket.startsWith(allowedDir + sep) ||
    !/^(?:dream-\d+|latest)\.json$/.test(fileBase)
  ) {
    return {
      error: {
        code: 'NVOY_BAD_DREAM_PACKET',
        message: `packet_path must be dream-<write_seq>.json or latest.json inside ${allowedDir}`,
      },
    }
  }
  let stat
  try {
    stat = lstatSync(resolvedPacket)
  } catch (err) {
    return { error: { code: 'NVOY_DREAM_PACKET_UNREADABLE', message: err.message } }
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    return { error: { code: 'NVOY_BAD_DREAM_PACKET', message: 'packet_path must be a regular non-symlink file' } }
  }
  if (stat.size > 4 * 1024 * 1024) {
    return { error: { code: 'NVOY_BAD_DREAM_PACKET', message: 'packet file exceeds 4 MiB limit' } }
  }
  let packet
  try {
    packet = JSON.parse(readFileSync(resolvedPacket, 'utf8'))
  } catch (err) {
    return { error: { code: 'NVOY_BAD_DREAM_PACKET', message: `failed to parse packet JSON: ${err.message}` } }
  }

  const res = verifyAndAssembleDreamRecord({
    packet,
    draft: {
      title: args.title,
      dream: args.dream,
      referenced_change_ids: args.referenced_change_ids,
    },
  })
  if (!res.ok) {
    return {
      error: {
        code: 'NVOY_DREAM_VERIFY_FAILED',
        errors: res.errors,
      },
    }
  }
  return {
    ok: {
      ok: true,
      word_count: res.word_count,
      record: res.record,
      buzz_post: formatDreamBuzzPost(res.record),
    },
  }
}

export function parseDreamVerifyFlags(argv = []) {
  let packetPath = null
  let draftPath = null
  let outPath = null
  let formatBuzz = false

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--packet' && argv[i + 1]) {
      packetPath = argv[++i]
    } else if (arg === '--draft' && argv[i + 1]) {
      draftPath = argv[++i]
    } else if (arg === '--out' && argv[i + 1]) {
      outPath = argv[++i]
    } else if (arg === '--format-buzz') {
      formatBuzz = true
    } else {
      throw new Error(`unknown argument: ${arg}`)
    }
  }
  if (!packetPath || !draftPath) {
    throw new Error('usage: memory-dream-verify.mjs --packet <packet.json> --draft <draft.json> [--out <out.json>] [--format-buzz]')
  }
  return { packetPath, draftPath, outPath, formatBuzz }
}

function main() {
  let flags
  try {
    flags = parseDreamVerifyFlags(process.argv.slice(2))
  } catch (err) {
    console.error(`memory-dream-verify: ${err.message}`)
    process.exit(1)
  }

  let packet
  let draft
  try {
    packet = JSON.parse(readFileSync(resolve(flags.packetPath), 'utf8'))
  } catch (err) {
    console.error(`memory-dream-verify: failed to read packet (${flags.packetPath}): ${err.message}`)
    process.exit(1)
  }
  try {
    draft = JSON.parse(readFileSync(resolve(flags.draftPath), 'utf8'))
  } catch (err) {
    console.error(`memory-dream-verify: failed to read draft (${flags.draftPath}): ${err.message}`)
    process.exit(1)
  }

  const res = verifyAndAssembleDreamRecord({ packet, draft })
  if (!res.ok) {
    console.error(JSON.stringify({ ok: false, errors: res.errors }, null, 2))
    process.exit(1)
  }

  if (flags.outPath) {
    const resolvedOut = resolve(flags.outPath)
    mkdirSync(dirname(resolvedOut), { recursive: true, mode: 0o755 })
    const tmpOut = `${resolvedOut}.tmp.${process.pid}.${Date.now()}`
    writeFileSync(tmpOut, JSON.stringify(res.record, null, 2) + '\n', { encoding: 'utf8', mode: 0o644 })
    chmodSync(tmpOut, 0o644)
    renameSync(tmpOut, resolvedOut)
  }

  if (flags.formatBuzz) {
    console.log(formatDreamBuzzPost(res.record))
  } else {
    console.log(JSON.stringify(res.record, null, 2))
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main()
}
