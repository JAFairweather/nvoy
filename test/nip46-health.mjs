import { check } from '../mcp/tools/nip46-health.mjs'
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

let failed = 0
const ok = (name, condition) => { console.log(condition ? '  ok' : 'FAIL', name); if (!condition) failed++ }
const dir = mkdtempSync(join(tmpdir(), 'nvoy-health-'))
const uri = join(dir, 'bunker-uri'), client = join(dir, 'client')
writeFileSync(uri, 'test-uri', { mode: 0o600 })
writeFileSync(client, 'test-client', { mode: 0o600 })
const env = { NVOY_BUNKER_URI_FILE: uri, NVOY_BROKER_CREDENTIAL: client }
let closed = 0
const healthy = await check({ env, open: () => ({ ping: async () => true, close: () => { closed++ } }), now: () => 100 })
ok('a matching ping produces a bounded success verdict and closes the connection',
  healthy.verdict === 'ok' && healthy.latency_ms === 0 && closed === 1)
for (const [message, expected] of [['nip46 ping timed out', 'timeout'], ['nip46 ping invalid response', 'invalid_response'], ['secret-bearing failure', 'unavailable']]) {
  const result = await check({ env, open: () => ({ ping: async () => { throw new Error(message) }, close: () => {} }) })
  ok(`${expected} is categorized without quoting Bunker output`, result.verdict === expected && !JSON.stringify(result).includes(message))
}
ok('missing credential path fails closed', (await check({ env: {}, open: () => { throw new Error('called') } })).verdict === 'unavailable')
chmodSync(client, 0o644)
ok('group-readable client key fails closed', (await check({ env, open: () => { throw new Error('called') } })).verdict === 'unavailable')
chmodSync(client, 0o600)
const link = join(dir, 'link')
symlinkSync(client, link)
ok('symlinked client key fails closed', (await check({ env: { ...env, NVOY_BROKER_CREDENTIAL: link }, open: () => { throw new Error('called') } })).verdict === 'unavailable')
rmSync(dir, { recursive: true, force: true })
if (failed) process.exit(1)
console.log('nip46-health: all checks passed')
