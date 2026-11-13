import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { claimPidLock } from '../mcp/tools/pid_lock.mjs'

if (process.platform !== 'linux') {
  console.log('pid-lock: Linux process-start regression skipped')
  process.exit(0)
}

const root = mkdtempSync(join(tmpdir(), 'nvoy-pid-lock-'))
const lock = join(root, 'channel.lock')
const instance = 'recycled-pid-test'
// Occupy the old lock's PID with a process that looks exactly like this channel.
const occupant = spawn(process.execPath, ['-e', 'process.stdout.write("ready\\n"); setInterval(() => {}, 1000)',
  'claude-channel.mjs', '--instance', instance], { stdio: ['ignore', 'pipe', 'ignore'] })
try {
  await once(occupant.stdout, 'data')
  const record = started_at => JSON.stringify({ version: 1, instance, pid: occupant.pid, started_at })
  writeFileSync(lock, record(Date.now() - 60_000))
  const release = claimPidLock(lock, instance, 'Claude channel', { program: 'claude-channel.mjs' })
  const owned = JSON.parse(readFileSync(lock, 'utf8'))
  assert.match(owned.process_identity?.boot || '', /^[0-9a-f-]{36}$/, 'new locks record the Linux boot identity')
  assert.match(owned.process_identity?.ticks || '', /^\d+$/, 'new locks record the holder start ticks')
  release()
  assert.equal(existsSync(lock), false, 'a recycled PID running the same channel must not hold an old lock')
  writeFileSync(lock, JSON.stringify({ ...owned, nonce: 'f'.repeat(32) }))
  release()
  assert.equal(existsSync(lock), true, 'release cannot remove a replacement lock with the same PID')

  writeFileSync(lock, JSON.stringify({ ...JSON.parse(record(Date.now())), process_identity: owned.process_identity }))
  claimPidLock(lock, instance, 'Claude channel', { program: 'claude-channel.mjs' })()
  assert.equal(existsSync(lock), false, 'an exact start identity distinguishes a recycled PID even after a rapid restart')

  const occupantStat = readFileSync(`/proc/${occupant.pid}/stat`, 'utf8')
  const occupantTicks = occupantStat.slice(occupantStat.lastIndexOf(')') + 2).trim().split(/\s+/)[19]
  writeFileSync(lock, JSON.stringify({ ...JSON.parse(record(Date.now() - 60_000)),
    process_identity: { boot: owned.process_identity.boot, ticks: occupantTicks } }))
  assert.throws(() => claimPidLock(lock, instance, 'Claude channel', { program: 'claude-channel.mjs' }),
    /already runs as pid/, 'an exact matching process identity protects a live holder despite an old timestamp')

  writeFileSync(lock, record(Date.now()))
  assert.throws(() => claimPidLock(lock, instance, 'Claude channel', { program: 'claude-channel.mjs' }),
    /already runs as pid/, 'a channel that predates its own lock still holds it')

  writeFileSync(lock, record(Date.now() - 60_000))
  assert.throws(() => claimPidLock(lock, instance, 'Claude channel', { program: 'claude-channel.mjs', procRoot: join(root, 'missing-proc') }),
    /already runs as pid/, 'unreadable process-start evidence must fail closed')

  writeFileSync(lock, JSON.stringify({ ...JSON.parse(record(Date.now() - 60_000)), process_identity: { boot: 'bad', ticks: '1' } }))
  assert.throws(() => claimPidLock(lock, instance, 'Claude channel', { program: 'claude-channel.mjs' }),
    /invalid process identity/, 'malformed process identity must fail closed')
  console.log('pid-lock: legacy and exact recycled PID, live holder, and unreadable evidence pass')
} finally {
  occupant.kill()
  rmSync(root, { recursive: true, force: true })
}
