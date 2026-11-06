#!/usr/bin/env node
// hive-memory-backup.mjs — the two halves of the hourly backup the service's write fence depends on.
//
//   node bin/hive-memory-backup.mjs snapshot --db … --ledger … --out-db <snapshot.sqlite> --out-ledger <ledger-cut.jsonl>
//     A hot SQLite backup() plus the ledger cut at the snapshot's write_seq. Prints { write_seq, snapshot_at }.
//   node bin/hive-memory-backup.mjs record-verified --backup-receipt … --write-seq <n> --snapshot-id <restic id> [--at <snapshot_at>]
//     Run only after restic dump <snapshot_id> has verified the pair; writes { at, write_seq, snapshot_id } atomically.
//     --snapshot-id is the full 64-hex id from restic's summary line. --at is the snapshot's time (unix seconds),
//     which the write fence measures from; it defaults to now.

import { recordVerifiedBackup, snapshotStore } from '../mcp/tools/hive_memory_store.mjs'

const [mode, ...args] = process.argv.slice(2)
const flag = name => {
  const i = args.indexOf(name)
  return i < 0 ? '' : args[i + 1] || ''
}
const fail = (msg, code = 1) => { console.error(`hive-memory-backup: ${msg}`); process.exit(code) }

try {
  if (mode === 'snapshot') {
    const [dbPath, ledgerPath, snapshotPath, ledgerCutPath] = ['--db', '--ledger', '--out-db', '--out-ledger'].map(flag)
    if (!dbPath || !ledgerPath || !snapshotPath || !ledgerCutPath) fail('snapshot needs --db, --ledger, --out-db and --out-ledger', 2)
    const out = await snapshotStore({ dbPath, ledgerPath, snapshotPath, ledgerCutPath })
    console.log(JSON.stringify({ write_seq: out.snapshotSeq, snapshot_at: out.snapshotAt }))
  } else if (mode === 'record-verified') {
    const receiptPath = flag('--backup-receipt')
    const seq = flag('--write-seq')
    const at = flag('--at')
    const snapshotId = flag('--snapshot-id')
    if (!receiptPath || !/^[1-9][0-9]*$/.test(seq)) fail('record-verified needs --backup-receipt and --write-seq <n>', 2)
    if (!/^[0-9a-f]{64}$/.test(snapshotId)) fail('record-verified needs --snapshot-id <the 64-hex restic snapshot id>', 2)
    if (args.includes('--at') && !/^[1-9][0-9]*$/.test(at)) fail('--at takes the snapshot time in unix seconds', 2)
    console.log(JSON.stringify(recordVerifiedBackup({ receiptPath, writeSeq: Number(seq), snapshotId, ...(at ? { at: Number(at) } : {}) })))
  } else {
    fail('usage: hive-memory-backup.mjs snapshot|record-verified …', 2)
  }
} catch (e) {
  fail(`${e.code ? `${e.code}: ` : ''}${e.message}`)
}
