#!/usr/bin/env node
// hive-memory-restore.mjs — install a decrypted snapshot only after it reconciles with the authoritative ledger.
//
//   Full-host loss (no local ledger):
//   node bin/hive-memory-restore.mjs --snapshot <memory.sqlite> --db <memory.sqlite> --ledger <accepted-ledger.jsonl> \
//     --config /etc/hive-memory/config.json --with-ledger <head dir> [--purge-authority <dir>]… \
//     [--reapply-purges] [--acknowledge-gap <ledgerMaxSeq>]
//   Same host (the local ledger survives): as above with --authority <head dir> in place of --with-ledger.
//
// <head dir> holds accepted-ledger.jsonl and SHA256SUMS dumped from the newest verified --tag hive-memory
// snapshot; each --purge-authority dir holds the same from a --tag hive-memory-purge snapshot. herd-infra
// fetches them from restic; this tool runs no restic. The candidate snapshot's own ledger is never trusted.
// A missing or unverifiable authority fails closed (HIVE_MEMORY_RESTORE_AUTHORITY_UNAVAILABLE).
// --with-ledger installs the head ledger first and never overwrites a different local ledger. A local ledger
// behind the head is refused (HIVE_MEMORY_RESTORE_AUTHORITY_STALE).
//
// Stop hive-memory.service first; the restore takes the store lock and refuses while the daemon holds it.
// A snapshot with unrecorded events is refused. A snapshot holding purged events, or rows past the 90-day
// retention window, is refused unless --reapply-purges deletes them. A snapshot missing accepted writes is
// refused unless the operator names the ledger's last seq with --acknowledge-gap, which records the loss.

import { loadConfigFile, restoreSnapshot } from '../mcp/tools/hive_memory_store.mjs'

const args = process.argv.slice(2)
const flag = name => {
  const i = args.indexOf(name)
  return i < 0 ? '' : args[i + 1] || ''
}
const flags = name => args.flatMap((a, i) => (a === name ? [args[i + 1] || ''] : []))
const fail = (msg, code = 1) => { console.error(`hive-memory-restore: ${msg}`); process.exit(code) }
const snapshotPath = flag('--snapshot')
const dbPath = flag('--db')
const ledgerPath = flag('--ledger')
const configPath = flag('--config')
if (!snapshotPath || !dbPath || !ledgerPath || !configPath) fail('--snapshot, --db, --ledger and --config are required', 2)
const ack = flag('--acknowledge-gap')
if (ack && !/^[1-9][0-9]*$/.test(ack)) fail('--acknowledge-gap takes the ledger max seq', 2)
const withLedger = args.includes('--with-ledger')
if (withLedger && args.includes('--authority')) fail('name the head snapshot with --with-ledger or --authority, not both', 2)
const headDir = flag(withLedger ? '--with-ledger' : '--authority')
const purgeDirs = flags('--purge-authority')
if (purgeDirs.includes('')) fail('--purge-authority takes a directory', 2)

try {
  const out = restoreSnapshot({
    snapshotPath, dbPath, ledgerPath,
    config: loadConfigFile(configPath),
    authority: { headDir, purgeDirs },
    withLedger,
    reapplyPurges: args.includes('--reapply-purges'),
    acknowledgeGap: ack ? Number(ack) : null,
  })
  console.log(JSON.stringify({
    installed: out.installed, write_seq: out.writeSeq, reapplied_purges: out.reappliedPurges,
    acknowledged_gap: out.acknowledgedGap.length, retention_purged: out.retentionPurged.length,
  }))
} catch (e) {
  fail(`${e.code ? `${e.code}: ` : ''}${e.message}`)
}
