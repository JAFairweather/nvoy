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

import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HEX16_RE = /\b[0-9a-fA-F]{16,64}\b/
const HTML_TAG_RE = /<\/?[a-zA-Z][^>]*>/
const MD_FENCE_RE = /```/
const MD_HEADER_RE = /(?:^|\n)\s*#{1,6}\s+/
const URL_RE = /\bhttps?:\/\/\S+/i
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
  for (const ch of Array.isArray(packet.changes) ? packet.changes : []) {
    if (ch && typeof ch.change_id === 'string' && ch.change_id) validIds.add(ch.change_id)
    if (ch && typeof ch.claim_event_id === 'string' && ch.claim_event_id) validIds.add(ch.claim_event_id)
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

  const canonicalChanges = packet.changes.map(ch => ({
    kind: String(ch.kind || 'distillation'),
    claim_event_id: String(ch.claim_event_id || ch.change_id || ''),
    summary: String(ch.summary || ''),
  }))

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
