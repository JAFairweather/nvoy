#!/usr/bin/env node
// hive-memory-restore.mjs — install a decrypted snapshot only after it reconciles with the ledger.
//
//   node bin/hive-memory-restore.mjs --snapshot <memory.sqlite> --db <memory.sqlite> --ledger <accepted-ledger.jsonl> \
//     --config /etc/hive-memory/config.json [--reapply-purges] [--acknowledge-gap <ledgerMaxSeq>]
//
// Stop hive-memory.service first; the restore takes the store lock and refuses while the daemon holds it.
// A snapshot with unrecorded events is refused. A snapshot holding events the ledger purged is refused
// unless --reapply-purges deletes them. A snapshot missing accepted writes is refused unless the operator
// names the ledger's last seq with --acknowledge-gap, which records the loss in the ledger.

import { loadConfigFile, restoreSnapshot } from '../mcp/tools/hive_memory_store.mjs'

const args = process.argv.slice(2)
const flag = name => {
  const i = args.indexOf(name)
  return i < 0 ? '' : args[i + 1] || ''
}
const fail = (msg, code = 1) => { console.error(`hive-memory-restore: ${msg}`); process.exit(code) }
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
    reapplyPurges: args.includes('--reapply-purges'),
    acknowledgeGap: ack ? Number(ack) : null,
  })
  console.log(JSON.stringify({ installed: out.installed, write_seq: out.writeSeq, reapplied_purges: out.reappliedPurges, acknowledged_gap: out.acknowledgedGap.length }))
} catch (e) {
  fail(`${e.code ? `${e.code}: ` : ''}${e.message}`)
}
