#!/usr/bin/env node
// bin/hive-memory-curate.mjs — CLI runner for the Phase 2 Merkle Dreaming & Curation Engine.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { nsecEncode } from 'nostr-tools/nip19'
import { runCuratorCycle } from '../mcp/tools/memory-curate.mjs'
import { makeBunkerSigner } from '../mcp/tools/nip46-signer.mjs'
import { readManifest, instanceId } from '../mcp/tools/runtime_manifest.mjs'

function parseArgs(argv) {
  const out = {
    readerSocket: null,
    writerSocket: null,
    keyFile: null,
    instance: null,
    instanceRoot: process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances',
    bunkerUriFile: null,
    bunkerClientFile: null,
    stateFile: undefined,
    lastCuratedAt: null,
    lastCuratedWriteSeq: null,
    coherenceScore: null,
    nowSec: null,
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
    else if (a === '--instance') out.instance = argv[++i]
    else if (a === '--instance-root') out.instanceRoot = argv[++i]
    else if (a === '--bunker-uri-file') out.bunkerUriFile = argv[++i]
    else if (a === '--bunker-client-file') out.bunkerClientFile = argv[++i]
    else if (a === '--state-file') out.stateFile = argv[++i]
    else if (a === '--last-curated-at') out.lastCuratedAt = Number(argv[++i])
    else if (a === '--last-curated-write-seq') out.lastCuratedWriteSeq = Number(argv[++i])
    else if (a === '--coherence-score') out.coherenceScore = Number(argv[++i])
    else if (a === '--now-sec') out.nowSec = Number(argv[++i])
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
    console.error('Usage: hive-memory-curate --reader-socket <path> [--writer-socket <path>] [--instance <id> | --bunker-uri-file <path> --bunker-client-file <path> | --key-file <hex-file>] [--state-file <path>] [--global-channel-id <uuid>] [--force] [--dry-run]')
    process.exit(2)
  }
  let sk = null
  let signer = null
  let manifestPubkey = null
  if (opts.instance) {
    const manifest = readManifest(resolve(opts.instanceRoot), instanceId(opts.instance))
    manifestPubkey = manifest.pubkey
    const uri = readFileSync(manifest.bunkerUriRef, 'utf8').trim()
    const rawClient = readFileSync(manifest.bunkerClientRef, 'utf8').trim()
    const client = rawClient.startsWith('nsec1') ? rawClient : nsecEncode(Uint8Array.from(Buffer.from(rawClient, 'hex')))
    signer = makeBunkerSigner(uri, client, { idleMs: 30000 })
  } else if (opts.bunkerUriFile && opts.bunkerClientFile) {
    const uri = readFileSync(opts.bunkerUriFile, 'utf8').trim()
    const rawClient = readFileSync(opts.bunkerClientFile, 'utf8').trim()
    const client = rawClient.startsWith('nsec1') ? rawClient : nsecEncode(Uint8Array.from(Buffer.from(rawClient, 'hex')))
    signer = makeBunkerSigner(uri, client, { idleMs: 30000 })
  } else if (opts.keyFile) {
    const raw = readFileSync(opts.keyFile, 'utf8').trim()
    sk = new Uint8Array(Buffer.from(raw, 'hex'))
  }
  try {
    const result = await runCuratorCycle({
      readerSocket: opts.readerSocket,
      writerSocket: opts.writerSocket,
      curatorSecretKey: sk,
      curatorSigner: signer,
      curatorPubkey: manifestPubkey,
      memoryGlobalChannelId: opts.globalChannelId,
      force: opts.force,
      dryRun: opts.dryRun,
      stateFile: opts.stateFile,
      lastCuratedAt: opts.lastCuratedAt,
      lastCuratedWriteSeq: opts.lastCuratedWriteSeq,
      coherence: opts.coherenceScore !== null ? { score: opts.coherenceScore } : null,
      dreamIntervalSec: opts.dreamIntervalSec,
      writeDeltaThreshold: opts.writeDeltaThreshold,
      topicPressureThreshold: opts.topicPressureThreshold,
      ...(opts.nowSec !== null && Number.isFinite(opts.nowSec) ? { nowSec: opts.nowSec } : {}),
    })
    console.log(JSON.stringify(result, null, 2))
    if (!result.ok) process.exit(1)
  } finally {
    try { signer?.close?.() } catch {}
  }
}

main().catch(err => {
  console.error(err?.stack || err?.message || String(err))
  process.exit(1)
})
