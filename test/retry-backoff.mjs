// The broker daemon's retry wait for held work (retry_backoff.mjs): 5 s after a first failure, doubling
// to a cap, reset by a success. Before, every held item retried every 5 s for as long as it failed, and
// each retry opened a fresh Bunker session.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createBackoff, RETRY_BASE_MS, RETRY_MAX_MS } from '../mcp/tools/retry_backoff.mjs'

let clock = 1_000_000
const b = createBackoff({ now: () => clock })
assert.equal(b.ready('x'), true, 'a key with no failure is ready')
const waits = []
for (let i = 0; i < 8; i++) waits.push(b.fail('x'))
assert.deepEqual(waits, [5000, 10000, 20000, 40000, 80000, 120000, 120000, 120000], 'waits double from 5 s and stop at the 120 s cap')
assert.equal(RETRY_BASE_MS, 5000)
assert.equal(RETRY_MAX_MS, 120000)
assert.equal(b.ready('x'), false, 'a key is not ready during its wait')
clock += 119_999
assert.equal(b.ready('x'), false)
clock += 1
assert.equal(b.ready('x'), true, 'a key is ready once its wait has passed')
assert.equal(b.ready('y'), true, 'keys are independent')
b.ok('x')
assert.equal(b.failures('x'), 0)
assert.equal(b.fail('x'), 5000, 'a success resets the wait to the base')
for (let i = 0; i < 60; i++) b.fail('z')
assert.equal(b.fail('z'), 120000, 'many failures never overflow past the cap')

// An hour of a dead signer: about 720 attempts per held item before, about 35 now.
let attempts = 0
const h = createBackoff({ now: () => clock })
const end = clock + 3600_000
while (clock < end) { if (h.ready('held')) { attempts++; h.fail('held') } clock += 1000 }
assert(attempts <= 40, `a held item retries at most about 35 times an hour (got ${attempts})`)

// The daemon uses it for every held-work retry and keeps no fixed 5 s retry.
const daemon = readFileSync(new URL('../mcp/tools/instance-broker-daemon.mjs', import.meta.url), 'utf8')
assert(/const retryAfter = createBackoff\(\)/.test(daemon) && /const proposalRetryAfter = createBackoff\(\)/.test(daemon))
assert(!/Date\.now\(\) \+ 5000/.test(daemon), 'no fixed 5 s retry remains in the daemon')
assert(!/\b(retryAfter|proposalRetryAfter)\.(get|set|delete)\(/.test(daemon), 'the held-work retries use only ready/fail/ok')
assert(/profileRetryAfter\.set\(request, Date\.now\(\) \+ profileBackoff\.fail\(request\)\)/.test(daemon), 'a failed profile publish backs off too')
console.log('retry-backoff: all checks passed')
