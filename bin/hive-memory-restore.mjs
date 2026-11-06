#!/usr/bin/env node
// hive-memory-restore.mjs — install a decrypted snapshot only after it reconciles with the authoritative ledger.
//
//   node bin/hive-memory-restore.mjs --snapshot <memory.sqlite> --db <memory.sqlite> --ledger <accepted-ledger.jsonl> \
//     --config /etc/hive-memory/config.json --authority-ledger <file> --purge-records <dir> \
//     [--with-ledger] [--reapply-purges] [--acknowledge-gap <ledgerMaxSeq>]
//
// --authority-ledger is the accepted-ledger.jsonl of the newest verified --tag hive-memory snapshot; --purge-records
// holds <snapshot_id>/accepted-ledger.jsonl for every --tag hive-memory-purge snapshot. herd-infra fetches them from
// restic and checks them against each snapshot's SHA256SUMS; this tool runs no restic. The candidate snapshot's own
// ledger is never trusted. A missing or unreadable authority fails closed (HIVE_MEMORY_RESTORE_AUTHORITY_UNAVAILABLE),
// and a local ledger behind it is refused (HIVE_MEMORY_RESTORE_AUTHORITY_STALE). --with-ledger, after full-host loss,
// installs the authority ledger first and never overwrites a different local one. Unknown flags are refused.
//
// Stop hive-memory.service first; the restore takes the store lock and refuses while the daemon holds it.
// A snapshot with unrecorded events is refused. A snapshot holding purged events, or rows past the 90-day
// retention window, is refused unless --reapply-purges deletes them. A snapshot missing accepted writes is
// refused unless the operator names the ledger's last seq with --acknowledge-gap, which records the loss.

import { loadConfigFile, restoreSnapshot } from '../mcp/tools/hive_memory_store.mjs'

const args = process.argv.slice(2)
const VALUED = ['--snapshot', '--db', '--ledger', '--config', '--authority-ledger', '--purge-records', '--acknowledge-gap']
const BARE = ['--with-ledger', '--reapply-purges']
const fail = (msg, code = 1) => { console.error(`hive-memory-restore: ${msg}`); process.exit(code) }
const given = {}
for (let i = 0; i < args.length; i++) {
  const a = args[i]
  if (!BARE.includes(a) && !VALUED.includes(a)) fail(`unknown argument ${a}`, 2)
  if (Object.hasOwn(given, a)) fail(`${a} is given twice`, 2)
  if (BARE.includes(a)) { given[a] = true; continue }
  const v = args[++i]
  if (!v || v.startsWith('--')) fail(`${a} takes a value`, 2)
  given[a] = v
}
const flag = name => given[name] || ''
const snapshotPath = flag('--snapshot')
const dbPath = flag('--db')
const ledgerPath = flag('--ledger')
const configPath = flag('--config')
if (!snapshotPath || !dbPath || !ledgerPath || !configPath) fail('--snapshot, --db, --ledger and --config are required', 2)
const ack = flag('--acknowledge-gap')
if (ack && !/^[1-9][0-9]*$/.test(ack)) fail('--acknowledge-gap takes the ledger max seq', 2)

try {
  const out = restoreSnapshot({
    snapshotPath, dbPath, ledgerPath,
    config: loadConfigFile(configPath),
    authority: { ledger: flag('--authority-ledger'), purgeRecords: flag('--purge-records') },
    withLedger: Boolean(given['--with-ledger']),
    reapplyPurges: Boolean(given['--reapply-purges']),
    acknowledgeGap: ack ? Number(ack) : null,
  })
  console.log(JSON.stringify({
    installed: out.installed, write_seq: out.writeSeq, reapplied_purges: out.reappliedPurges,
    acknowledged_gap: out.acknowledgedGap.length, retention_purged: out.retentionPurged.length,
  }))
} catch (e) {
  fail(`${e.code ? `${e.code}: ` : ''}${e.message}`)
}
