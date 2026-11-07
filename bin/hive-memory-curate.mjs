#!/usr/bin/env node
// bin/hive-memory-curate.mjs — CLI runner for the Phase 2 Merkle Dreaming & Curation Engine.

import { readFileSync } from 'node:fs'
import { hexToBytes } from '@noble/hashes/utils'
import { runCuratorCycle } from '../mcp/tools/memory-curate.mjs'

function parseArgs(argv) {
  const out = {
    readerSocket: null,
    writerSocket: null,
    keyFile: null,
    globalChannelId: '',
    force: false,
    dryRun: false,
    dreamIntervalSec: 6 * 3600,
    writeDeltaThreshold: 20,
    topicPressureThreshold: 8,
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--reader-socket') out.readerSocket = argv[++i]
    else if (a === '--writer-socket') out.writerSocket = argv[++i]
    else if (a === '--key-file') out.keyFile = argv[++i]
    else if (a === '--global-channel-id') out.globalChannelId = argv[++i]
    else if (a === '--force') out.force = true
    else if (a === '--dry-run') out.dryRun = true
    else if (a === '--dream-interval-sec') out.dreamIntervalSec = Number(argv[++i])
    else if (a === '--write-delta') out.writeDeltaThreshold = Number(argv[++i])
    else if (a === '--topic-pressure') out.topicPressureThreshold = Number(argv[++i])
  }
  return out
}

async function main() {
  const opts = parseArgs(process.argv.slice(2))
  if (!opts.readerSocket) {
    console.error('Usage: hive-memory-curate --reader-socket <path> [--writer-socket <path>] [--key-file <hex-file>] [--global-channel-id <uuid>] [--force] [--dry-run]')
    process.exit(2)
  }
  let sk = null
  if (opts.keyFile) {
    const raw = readFileSync(opts.keyFile, 'utf8').trim()
    sk = hexToBytes(raw)
  }
  const result = await runCuratorCycle({
    readerSocket: opts.readerSocket,
    writerSocket: opts.writerSocket,
    curatorSecretKey: sk,
    memoryGlobalChannelId: opts.globalChannelId,
    force: opts.force,
    dryRun: opts.dryRun,
    dreamIntervalSec: opts.dreamIntervalSec,
    writeDeltaThreshold: opts.writeDeltaThreshold,
    topicPressureThreshold: opts.topicPressureThreshold,
  })
  console.log(JSON.stringify(result, null, 2))
}

main().catch(err => {
  console.error(err?.stack || err?.message || String(err))
  process.exit(1)
})
