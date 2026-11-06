#!/usr/bin/env node
// hive-memory-purge.mjs — owner hard delete, or a retention purge, recorded as a ledger purge.
//
//   node bin/hive-memory-purge.mjs --db … --ledger … --backup-receipt … --config … (--d <fact key> | --id <event id>)
//   node bin/hive-memory-purge.mjs --db … --ledger … --backup-receipt … --config … --retention
//
// --retention is the daily 90-day pass; with nothing past the window it writes no op purge.
// Stop hive-memory.service first; the purge takes the store lock and refuses while the daemon holds it.
// The store must reconcile to READY. A hard delete removes every version at that fact key (or the one
// event); every purge then checkpoints and VACUUMs so the rows leave the SQLite pages.
// No purge is complete until a verified backup covers its write_seq: until then `hive-memory-backup.mjs
// gate` exits with HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE and memory_submit refuses with the same code.

import { HiveMemoryStore, loadConfigFile } from '../mcp/tools/hive_memory_store.mjs'

const args = process.argv.slice(2)
const flag = name => {
  const i = args.indexOf(name)
  return i < 0 ? null : args[i + 1] ?? ''
}
const fail = (msg, code = 1) => { console.error(`hive-memory-purge: ${msg}`); process.exit(code) }
const dbPath = flag('--db')
const ledgerPath = flag('--ledger')
const receiptPath = flag('--backup-receipt')
const configPath = flag('--config')
if (!dbPath || !ledgerPath || !receiptPath || !configPath) fail('--db, --ledger, --backup-receipt and --config are required', 2)
const retention = args.includes('--retention')
const d = flag('--d')
const id = flag('--id')
if (retention ? d !== null || id !== null : (d === null) === (id === null)) fail('name exactly one of --d, --id or --retention', 2)

let store
let error = null
try {
  store = new HiveMemoryStore({ dbPath, ledgerPath, receiptPath, config: loadConfigFile(configPath), log: m => console.error(m) })
  store.start()
  const out = retention ? store.purgeRetention() : store.hardDelete({ d, id })
  console.log(JSON.stringify({ purged: out.purged.length, write_seq: out.seq ?? null }))
} catch (e) {
  error = e
} finally {
  store?.close()
}
if (error) fail(`${error.code ? `${error.code}: ` : ''}${error.message}`)
