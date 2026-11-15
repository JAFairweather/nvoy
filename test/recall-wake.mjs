// Focused boundary regressions for per-session Hive memory startup wake (q-197):
// 1. TERM-ignoring reader + descendant process group is escalated to SIGKILL and reaped on timeout.
// 2. FIFO / non-regular recall log path never blocks appendRecallLog or the Claude SessionStart hook.
// 3. Pending Pi beforeAgentStart wake callback is fenced to its session generation across shutdown/restart.
// 4. Truncated, empty, legacy-unverified, or error-shaped payloads fail loudly and never log ready.

import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { homedir, tmpdir } from 'node:os'
import { dirname, join, parse, resolve } from 'node:path'
import { appendRecallLog, callMcpEntryOnce, CLAUDE_SESSION_START_MATCHER, CLAUDE_WAKE_SOURCES, MAX_WAKE_DIGEST_CHARS, parseWakeToolText, shouldWakeClaudeSessionStart } from '../mcp/tools/recall-wake.mjs'
import { seedSettings } from '../mcp/tools/harness_session.mjs'
import { channelProxy, createPiHarness } from '../mcp/tools/pi_harness_extension.mjs'

let fails = 0
const ok = (name, cond) => { console.log(`${cond ? 'ok  ' : 'FAIL'} — ${name}`); if (!cond) fails++ }
const wait = ms => new Promise(done => setTimeout(done, ms))
const pidAlive = pid => { try { process.kill(pid, 0); return true } catch { return false } }

function chainPassesFixedPath(candidate) {
  try {
    if (!candidate) return false
    const supplied = lstatSync(candidate)
    if (supplied.isSymbolicLink() || !supplied.isDirectory()) return false
    let dir = realpathSync(candidate)
    const rootDir = parse(dir).root
    const allowedOwners = new Set([0, typeof process.getuid === 'function' ? process.getuid() : 0])
    for (;;) {
      const parent = lstatSync(dir)
      const stickyRoot = parent.uid === 0 && (parent.mode & 0o1000) !== 0
      if (!parent.isDirectory() || parent.isSymbolicLink() || !allowedOwners.has(parent.uid) ||
          ((parent.mode & 0o022) !== 0 && !stickyRoot)) {
        return false
      }
      if (dir === rootDir) return true
      dir = dirname(dir)
    }
  } catch {
    return false
  }
}

function safeParentBase() {
  for (const candidate of [tmpdir(), '/tmp', homedir(), resolve('.')]) {
    if (chainPassesFixedPath(candidate)) return realpathSync(candidate)
  }
  return tmpdir()
}

const root = mkdtempSync(join(safeParentBase(), '.nvoy-recall-wake-test-'))
chmodSync(root, 0o700)

try {
  // 1. TERM-ignoring reader + child process group is SIGKILLed and reaped before callMcpEntryOnce settles.
  const pidsFile = join(root, 'term-ignore.pids')
  const termIgnoreReader = join(root, 'term-ignore-reader.sh')
  writeFileSync(termIgnoreReader, `#!/bin/sh
trap '' TERM
sleep 30 &
sub=$!
printf '{"reader":%s,"sub":%s}\\n' "$$" "$sub" > ${JSON.stringify(pidsFile)}
wait "$sub"
`, { mode: 0o700 })
  chmodSync(termIgnoreReader, 0o700)

  let timeoutErr = ''
  try {
    await callMcpEntryOnce({ command: '/bin/sh', args: [termIgnoreReader] }, 'memory_wake', { max_chars: 3500 }, { timeoutMs: 600, killGraceMs: 80 })
  } catch (err) {
    timeoutErr = err.message
  }
  const recordedPids = existsSync(pidsFile) ? JSON.parse(readFileSync(pidsFile, 'utf8')) : { reader: 0, sub: 0 }
  await wait(50)
  const stillAliveAfter = (recordedPids.reader && pidAlive(recordedPids.reader)) || (recordedPids.sub && pidAlive(recordedPids.sub))
  if (stillAliveAfter) {
    try { process.kill(-recordedPids.reader, 'SIGKILL') } catch {}
    try { process.kill(recordedPids.reader, 'SIGKILL') } catch {}
    try { process.kill(recordedPids.sub, 'SIGKILL') } catch {}
  }
  ok('TERM-ignoring reader and its child are escalated to SIGKILL and reaped before timeout rejection settles',
    /did not answer within 1s/.test(timeoutErr) && recordedPids.reader > 0 && recordedPids.sub > 0 && !stillAliveAfter)

  // 1b. Leader exits promptly on SIGTERM (or before timeout / on normal completion) while a TERM-ignoring descendant
  //     with stdio ignored remains in the process group: callMcpEntryOnce still SIGKILLs and reaps the descendant.
  const killPair = pair => {
    if (!pair) return
    if (pair.reader > 1) { try { process.kill(-pair.reader, 'SIGKILL') } catch {}; try { process.kill(pair.reader, 'SIGKILL') } catch {} }
    if (pair.sub > 1) { try { process.kill(pair.sub, 'SIGKILL') } catch {} }
  }
  const leaderExitPidsFile = join(root, 'leader-exit-descendant.pids')
  const leaderExitReader = join(root, 'leader-exit-reader.cjs')
  writeFileSync(leaderExitReader, `
const { spawn } = require('node:child_process')
const { writeFileSync } = require('node:fs')
const mode = process.argv[2] || 'hang-leader-dies-on-term'
const sub = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000)'], { stdio: 'ignore' })
sub.unref()
writeFileSync(${JSON.stringify(leaderExitPidsFile)}, JSON.stringify({ reader: process.pid, sub: sub.pid }))
if (mode === 'exit-early') process.exit(1)
let buf = ''
process.stdin.on('data', chunk => {
  buf += chunk
  let nl
  while ((nl = buf.indexOf('\\n')) >= 0) {
    const m = JSON.parse(buf.slice(0, nl)); buf = buf.slice(nl + 1)
    if (m.id === undefined) continue
    if (m.method === 'initialize') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'stub', version: '1' } } }) + '\\n')
      continue
    }
    if (mode === 'complete-with-orphan') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: '{"ok":true}' }] } }) + '\\n', () => process.exit(0))
      return
    }
  }
})
setInterval(() => {}, 1000)
`, { mode: 0o700 })

  // Variant A: timeout where leader accepts default SIGTERM and exits immediately, leaving TERM-ignoring descendant.
  rmSync(leaderExitPidsFile, { force: true })
  let leaderTermErr = ''
  try {
    await callMcpEntryOnce({ command: process.execPath, args: [leaderExitReader, 'hang-leader-dies-on-term'] }, 'memory_wake', { max_chars: 3500 }, { timeoutMs: 700, killGraceMs: 80 })
  } catch (err) {
    leaderTermErr = err.message
  }
  const pairA = existsSync(leaderExitPidsFile) ? JSON.parse(readFileSync(leaderExitPidsFile, 'utf8')) : { reader: 0, sub: 0 }
  const aliveA = (pairA.reader > 0 && pidAlive(pairA.reader)) || (pairA.sub > 0 && pidAlive(pairA.sub))
  if (aliveA) killPair(pairA)
  ok('callMcpEntryOnce escalates process-group SIGKILL even when leader exits on SIGTERM and descendant ignores SIGTERM',
    /did not answer within 1s/.test(leaderTermErr) && pairA.reader > 0 && pairA.sub > 0 && !aliveA)

  // Variant B: leader exits early (exit 1) leaving TERM-ignoring descendant with stdio ignored.
  rmSync(leaderExitPidsFile, { force: true })
  let earlyExitErr = ''
  try {
    await callMcpEntryOnce({ command: process.execPath, args: [leaderExitReader, 'exit-early'] }, 'memory_wake', { max_chars: 3500 }, { timeoutMs: 2000, killGraceMs: 80 })
  } catch (err) {
    earlyExitErr = err.message
  }
  const pairB = existsSync(leaderExitPidsFile) ? JSON.parse(readFileSync(leaderExitPidsFile, 'utf8')) : { reader: 0, sub: 0 }
  const aliveB = (pairB.reader > 0 && pidAlive(pairB.reader)) || (pairB.sub > 0 && pidAlive(pairB.sub))
  if (aliveB) killPair(pairB)
  ok('callMcpEntryOnce reaps TERM-ignoring descendant when leader exits early before answering',
    /closed \(1\)/.test(earlyExitErr) && pairB.reader > 0 && pairB.sub > 0 && !aliveB)

  // Variant C: normal completion where leader answers tools/call and exits 0 leaving TERM-ignoring descendant.
  rmSync(leaderExitPidsFile, { force: true })
  const completedRes = await callMcpEntryOnce({ command: process.execPath, args: [leaderExitReader, 'complete-with-orphan'] }, 'memory_wake', { max_chars: 3500 }, { timeoutMs: 2000, killGraceMs: 80 })
  const pairC = existsSync(leaderExitPidsFile) ? JSON.parse(readFileSync(leaderExitPidsFile, 'utf8')) : { reader: 0, sub: 0 }
  const aliveC = (pairC.reader > 0 && pidAlive(pairC.reader)) || (pairC.sub > 0 && pidAlive(pairC.sub))
  if (aliveC) killPair(pairC)
  ok('callMcpEntryOnce reaps TERM-ignoring descendant on normal tools/call completion before resolving',
    completedRes?.content?.[0]?.text === '{"ok":true}' && pairC.reader > 0 && pairC.sub > 0 && !aliveC)

  // 2. FIFO recall log path is rejected without blocking appendRecallLog or the Claude SessionStart CLI hook.
  const fifoPath = join(root, 'recall.fifo')
  const mkfifo = spawnSync('mkfifo', [fifoPath], { encoding: 'utf8' })
  if (mkfifo.status === 0) {
    const t0 = Date.now()
    const wroteFifo = appendRecallLog(fifoPath, 'memory wake FAILED: test')
    const fifoElapsed = Date.now() - t0
    ok('appendRecallLog refuses a readerless FIFO immediately without blocking', wroteFifo === false && fifoElapsed < 500)

    const badMcp = join(root, 'missing-server-mcp.json')
    writeFileSync(badMcp, JSON.stringify({ mcpServers: {} }), { mode: 0o600 })
    chmodSync(badMcp, 0o600)
    const hookRes = spawnSync(process.execPath, ['mcp/tools/recall-wake.mjs', '--claude-hook', badMcp, '--log', fifoPath],
      { cwd: resolve('.'), encoding: 'utf8', input: '{"session_id":"fifo-check"}\n', timeout: 2500 })
    const hookJson = JSON.parse(hookRes.stdout || '{}')
    ok('Claude SessionStart hook with a FIFO --log path exits 0 promptly and still returns failure additionalContext',
      hookRes.status === 0 && /Hive memory wake FAILED at session start[\s\S]*no hive-memory server entry/.test(hookJson.hookSpecificOutput?.additionalContext || ''))
  } else {
    ok('mkfifo unavailable on platform (skipped FIFO special-file check)', true)
  }

  // 3. Pending Pi beforeAgentStart wake callback is fenced to its session generation across stop() + new start().
  const piModeFile = join(root, 'pi-mode')
  const piReader = join(root, 'pi-delay-reader.cjs')
  writeFileSync(piReader, `
const { readFileSync } = require('node:fs')
let buf = ''
process.stdin.on('data', chunk => {
  buf += chunk
  let nl
  while ((nl = buf.indexOf('\\n')) >= 0) {
    const m = JSON.parse(buf.slice(0, nl)); buf = buf.slice(nl + 1)
    if (m.id === undefined) continue
    if (m.method === 'initialize') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'stub', version: '1' } } }) + '\\n')
      continue
    }
    const mode = readFileSync(${JSON.stringify(piModeFile)}, 'utf8').trim()
    const reply = tag => process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: m.id,
      result: { content: [{ type: 'text', text: JSON.stringify({
        record_type: 'memory-wake-digest',
        store_state: { state: 'READY' },
        counts: { canon_shown: 3, ops_shown: 1 },
        digest: '=== HIVE WAKE DIGEST ===\\n- [canon] ' + tag,
      }) }] },
    }) + '\\n')
    if (mode === 'slow-a') setTimeout(() => reply('session-A-stale'), 250)
    else reply('session-B-fresh')
  }
})
`, { mode: 0o700 })
  const dummyFeedSsh = join(root, 'dummy-ssh.cjs')
  writeFileSync(dummyFeedSsh, `setInterval(() => {}, 1000)\n`, { mode: 0o700 })
  const dummyKey = join(root, 'dummy-key')
  writeFileSync(dummyKey, 'k\n', { mode: 0o600 })
  const dummyKnown = join(root, 'known_hosts')
  writeFileSync(dummyKnown, 'broker.example ssh-ed25519 AAAAC3NzaTest\n', { mode: 0o600 })
  const piStub = { registerTool() {}, sendUserMessage() {} }
  const piCfg = {
    id: 'pd-gen',
    target: 'nvoy-pi@broker.example',
    identity: dummyKey,
    feedIdentity: dummyKey,
    knownHosts: dummyKnown,
    stateDir: join(root, 'pi-state'),
    recall: { local: true, bridge: process.execPath },
  }
  // Point local bridge at a small executable wrapper around piReader.
  const piBridge = join(root, 'pi-bridge')
  writeFileSync(piBridge, `#!${process.execPath}\nrequire(${JSON.stringify(piReader)})\n`, { mode: 0o700 })
  chmodSync(piBridge, 0o700)
  piCfg.recall.bridge = piBridge

  const fakeSshExec = join(root, 'fake-ssh')
  writeFileSync(fakeSshExec, `#!${process.execPath}\nrequire(${JSON.stringify(dummyFeedSsh)})\n`, { mode: 0o700 })
  chmodSync(fakeSshExec, 0o700)

  const harness = createPiHarness({ pi: piStub, config: piCfg, ssh: fakeSshExec, log: () => {} })
  writeFileSync(piModeFile, 'slow-a')
  harness.start({ hasUI: false })
  const pendingA = harness.beforeAgentStart({ type: 'before_agent_start' })
  await wait(50)
  harness.stop()
  writeFileSync(piModeFile, 'fast-b')
  harness.start({ hasUI: false })
  const resolvedA = await pendingA
  const resolvedB = await harness.beforeAgentStart({ type: 'before_agent_start' })
  harness.stop()
  ok('pending session-A beforeAgentStart callback resolves undefined after stop/restart while session B receives its own fresh digest',
    resolvedA === undefined &&
    /session-B-fresh/.test(resolvedB?.message?.content || '') &&
    !/session-A-stale/.test(JSON.stringify(resolvedB)))

  // 4. Malformed, truncated, empty, unverified plain-text, and error-shaped wake payloads fail loudly.
  for (const [label, sample, expected] of [
    ['truncated JSON', '{"record_type":"memory-wake', /invalid JSON/],
    ['empty object', '{}', /store_state=missing/],
    ['string error field', JSON.stringify({ error: 'reader unavailable' }), /reader unavailable/],
    ['plain text non-JSON', 'unverified legacy text', /invalid JSON/],
    ['missing canon_shown', JSON.stringify({ record_type: 'memory-wake-digest', store_state: { state: 'READY' }, counts: { ops_shown: 1 }, digest: 'x' }), /canon_shown/],
    ['empty digest', JSON.stringify({ record_type: 'memory-wake-digest', store_state: { state: 'READY' }, counts: { canon_shown: 1, ops_shown: 0 }, digest: '   ' }), /empty digest/],
  ]) {
    const res = parseWakeToolText(sample)
    ok(`parseWakeToolText rejects ${label} and formats @Neil failure notice`,
      res.ok === false && expected.test(res.error) && /Hive memory wake FAILED at session start[\s\S]*mentioning @Neil/.test(res.context))
  }

  const validRes = parseWakeToolText(JSON.stringify({
    record_type: 'memory-wake-digest',
    store_state: { state: 'READY' },
    counts: { canon_shown: 14, ops_shown: 3 },
    digest: '=== HIVE WAKE DIGEST ===\nstore_state: READY\n## Rank 2: hive:canon\n- [canon] rule',
  }))
  ok('parseWakeToolText accepts a verified READY memory-wake-digest with positive canon count',
    validRes.ok === true && validRes.summary === 'canon=14, ops=3' && /Hive memory wake digest/.test(validRes.context))

  // hive:canon sits outside max_chars by store contract (non_canon_bytes <= max_chars), while both non_canon_bytes
  // and total digest size remain locally bounded.
  const largeCanonRes = parseWakeToolText(JSON.stringify({
    record_type: 'memory-wake-digest',
    store_state: { state: 'READY' },
    counts: { canon_shown: 20, ops_shown: 5 },
    non_canon_bytes: 2800,
    digest: 'c'.repeat(12000),
  }), { maxChars: 3500 })
  const overNonCanon = parseWakeToolText(JSON.stringify({
    record_type: 'memory-wake-digest',
    store_state: { state: 'READY' },
    counts: { canon_shown: 1, ops_shown: 5 },
    non_canon_bytes: 4200,
    digest: 'x'.repeat(500),
  }), { maxChars: 3500 })
  const overHardCap = parseWakeToolText(JSON.stringify({
    record_type: 'memory-wake-digest',
    store_state: { state: 'READY' },
    counts: { canon_shown: 1, ops_shown: 0 },
    digest: 'x'.repeat(MAX_WAKE_DIGEST_CHARS + 10),
  }))
  ok('parseWakeToolText allows full hive:canon outside maxChars while enforcing non_canon_bytes and hard digest bounds',
    largeCanonRes.ok === true &&
    overNonCanon.ok === false && /non_canon_bytes exceeded max_chars/.test(overNonCanon.error) &&
    overHardCap.ok === false && /exceeded local bound/.test(overHardCap.error))

  // 5. Claude SessionStart cadence contract: startup, resume (--continue), and clear wake once; compact and fork skip.
  const seededGroup = seedSettings({}, 'nvoy-mc-test', { recall: true, mcpConfigPath: '/m/mcp.json', recallLogPath: '/m/recall.log' }).hooks.SessionStart[0]
  const matcherRe = new RegExp(`^(?:${seededGroup.matcher})$`)
  ok('seedSettings installs explicit startup|resume|clear SessionStart matcher and excludes compact and fork',
    seededGroup.matcher === CLAUDE_SESSION_START_MATCHER &&
    CLAUDE_WAKE_SOURCES.join(',') === 'startup,resume,clear' &&
    ['startup', 'resume', 'clear'].every(s => matcherRe.test(s) && shouldWakeClaudeSessionStart({ source: s })) &&
    ['compact', 'fork'].every(s => !matcherRe.test(s) && !shouldWakeClaudeSessionStart({ source: s })))

  const cadenceCallsFile = join(root, 'cadence-calls.jsonl')
  const cadenceLogFile = join(root, 'cadence-recall.log')
  const cadenceReader = join(root, 'cadence-reader.cjs')
  writeFileSync(cadenceReader, `
const { appendFileSync } = require('node:fs')
let buf = ''
process.stdin.on('data', chunk => {
  buf += chunk
  let nl
  while ((nl = buf.indexOf('\\n')) >= 0) {
    const m = JSON.parse(buf.slice(0, nl)); buf = buf.slice(nl + 1)
    if (m.id === undefined) continue
    if (m.method === 'initialize') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'stub', version: '1' } } }) + '\\n')
      continue
    }
    appendFileSync(${JSON.stringify(cadenceCallsFile)}, JSON.stringify({ op: m.params.name }) + '\\n')
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: JSON.stringify({
      record_type: 'memory-wake-digest',
      store_state: { state: 'READY' },
      counts: { canon_shown: 2, ops_shown: 1 },
      digest: '=== HIVE WAKE DIGEST ===\\n- [canon] cadence check',
    }) }] } }) + '\\n')
  }
})
`, { mode: 0o700 })
  const cadenceMcp = join(root, 'cadence-mcp.json')
  writeFileSync(cadenceMcp, JSON.stringify({ mcpServers: { 'hive-memory': { command: process.execPath, args: [cadenceReader] } } }), { mode: 0o600 })
  chmodSync(cadenceMcp, 0o600)
  const runCadenceHook = source => spawnSync(process.execPath, ['mcp/tools/recall-wake.mjs', '--claude-hook', cadenceMcp, '--log', cadenceLogFile],
    { cwd: resolve('.'), encoding: 'utf8', input: JSON.stringify({ session_id: 's-cadence', hook_event_name: 'SessionStart', source }) + '\n', timeout: 4000 })
  const cadenceResults = Object.fromEntries(['startup', 'resume', 'clear', 'compact', 'fork'].map(s => {
    const r = runCadenceHook(s)
    return [s, { status: r.status, json: JSON.parse(r.stdout || '{}') }]
  }))
  const cadenceCallCount = existsSync(cadenceCallsFile) ? readFileSync(cadenceCallsFile, 'utf8').trim().split('\n').filter(Boolean).length : 0
  const cadenceLogLines = existsSync(cadenceLogFile) ? readFileSync(cadenceLogFile, 'utf8').trim().split('\n').filter(Boolean) : []
  ok('Claude hook runs memory_wake on startup, resume, and clear (3 reader calls) and skips compact and fork (0 reader calls)',
    ['startup', 'resume', 'clear'].every(s => cadenceResults[s].status === 0 && /cadence check/.test(cadenceResults[s].json.hookSpecificOutput?.additionalContext || '')) &&
    ['compact', 'fork'].every(s => cadenceResults[s].status === 0 && JSON.stringify(cadenceResults[s].json) === '{}') &&
    cadenceCallCount === 3 && cadenceLogLines.length === 3)

  // 6. Pi end-to-end startup wake timeout bounds BOTH initialize and post-initialize tools/call within HARNESS_WAKE_TIMEOUT_MS
  //    (instead of stacking two 30s channelProxy stages), reaps hung readers, and resets the reader for subsequent calls.
  const piHangStageFile = join(root, 'pi-hang-stage')
  const piHangPidFile = join(root, 'pi-hang.pid')
  const piHangReader = join(root, 'pi-hang-reader.cjs')
  writeFileSync(piHangReader, `
const { readFileSync, writeFileSync } = require('node:fs')
process.on('SIGTERM', () => {})
writeFileSync(${JSON.stringify(piHangPidFile)}, String(process.pid))
const stage = readFileSync(${JSON.stringify(piHangStageFile)}, 'utf8').trim()
if (stage === 'hang-init') { setInterval(() => {}, 1000); return }
let buf = ''
process.stdin.on('data', chunk => {
  buf += chunk
  let nl
  while ((nl = buf.indexOf('\\n')) >= 0) {
    const m = JSON.parse(buf.slice(0, nl)); buf = buf.slice(nl + 1)
    if (m.id === undefined) continue
    if (m.method === 'initialize') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'stub', version: '1' } } }) + '\\n')
      continue
    }
    if (stage === 'hang-call') { setInterval(() => {}, 1000); return }
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: JSON.stringify({ answer: 'found', records: [] }) }] } }) + '\\n')
  }
})
`, { mode: 0o700 })
  const piHangBridge = join(root, 'pi-hang-bridge')
  writeFileSync(piHangBridge, `#!${process.execPath}\nrequire(${JSON.stringify(piHangReader)})\n`, { mode: 0o700 })
  chmodSync(piHangBridge, 0o700)

  const prevWakeTimeout = process.env.HARNESS_WAKE_TIMEOUT_MS
  const prevChanTimeout = process.env.HARNESS_CHANNEL_CALL_MS
  process.env.HARNESS_WAKE_TIMEOUT_MS = '800'
  process.env.HARNESS_CHANNEL_CALL_MS = '30000'
  try {
    const registeredTools = new Map()
    const piTimeoutStub = { registerTool(t) { registeredTools.set(t.name, t) }, sendUserMessage() {} }
    const piTimeoutLogs = []
    const piTimeoutHarness = createPiHarness({
      pi: piTimeoutStub,
      config: { ...piCfg, stateDir: join(root, 'pi-timeout-state'), recall: { local: true, bridge: piHangBridge } },
      ssh: fakeSshExec,
      log: line => piTimeoutLogs.push(line),
    })
    for (const stage of ['hang-init', 'hang-call']) {
      writeFileSync(piHangStageFile, stage)
      const startedAt = Date.now()
      piTimeoutHarness.start({ hasUI: false })
      const turn = await piTimeoutHarness.beforeAgentStart({ type: 'before_agent_start' })
      const elapsed = Date.now() - startedAt
      await wait(280)
      const hungPid = Number(readFileSync(piHangPidFile, 'utf8').trim())
      const hungDead = hungPid > 0 && !pidAlive(hungPid)
      if (!hungDead && hungPid > 0) try { process.kill(-hungPid, 'SIGKILL') } catch {}
      piTimeoutHarness.stop()
      ok(`Pi startup wake bounds ${stage} within HARNESS_WAKE_TIMEOUT_MS (not 30s/60s), injects @Neil failure notice, and reaps TERM-ignoring reader`,
        elapsed < 3000 && hungDead &&
        /Hive memory wake FAILED at session start[\s\S]*did not answer within 1s[\s\S]*mentioning @Neil/.test(turn?.message?.content || '') &&
        piTimeoutLogs.some(l => /memory wake FAILED: the Hive memory reader did not answer within 1s/.test(l)))
    }
    writeFileSync(piHangStageFile, 'ok')
    const queryAfterTimeout = await registeredTools.get('memory_query').execute('q1', { topic: 'nvoy' })
    piTimeoutHarness.stop()
    ok('after a Pi startup wake timeout resets the reader, subsequent memory_query spawns a fresh reader and succeeds',
      JSON.parse(queryAfterTimeout.content[0].text).answer === 'found' && piTimeoutHarness.reader.spawned() === 3)
  } finally {
    if (prevWakeTimeout === undefined) delete process.env.HARNESS_WAKE_TIMEOUT_MS
    else process.env.HARNESS_WAKE_TIMEOUT_MS = prevWakeTimeout
    if (prevChanTimeout === undefined) delete process.env.HARNESS_CHANNEL_CALL_MS
    else process.env.HARNESS_CHANNEL_CALL_MS = prevChanTimeout
  }

  // 7. Pi channelProxy + startup wake: when leader exits on SIGTERM (or early) leaving a TERM-ignoring descendant
  //    with stdio ignored, process-group cleanup still SIGKILLs and reaps the descendant across timeout, reset, and close.
  const piOrphanPidsFile = join(root, 'pi-orphan.pids')
  const piOrphanModeFile = join(root, 'pi-orphan.mode')
  const piOrphanReader = join(root, 'pi-orphan-reader.cjs')
  writeFileSync(piOrphanReader, `
const { spawn } = require('node:child_process')
const { readFileSync, writeFileSync } = require('node:fs')
const mode = readFileSync(${JSON.stringify(piOrphanModeFile)}, 'utf8').trim()
const sub = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000)'], { stdio: 'ignore' })
sub.unref()
writeFileSync(${JSON.stringify(piOrphanPidsFile)}, JSON.stringify({ reader: process.pid, sub: sub.pid }))
if (mode === 'exit-early') process.exit(1)
let buf = ''
process.stdin.on('data', chunk => {
  buf += chunk
  let nl
  while ((nl = buf.indexOf('\\n')) >= 0) {
    const m = JSON.parse(buf.slice(0, nl)); buf = buf.slice(nl + 1)
    if (m.id === undefined) continue
    if (m.method === 'initialize') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'stub', version: '1' } } }) + '\\n')
      continue
    }
    if (mode === 'hang-call') return
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: '{"answer":"found"}' }] } }) + '\\n')
  }
})
setInterval(() => {}, 1000)
`, { mode: 0o700 })

  const prevCallMs = process.env.HARNESS_CHANNEL_CALL_MS
  process.env.HARNESS_CHANNEL_CALL_MS = '700'
  try {
    const proxy = channelProxy({
      config: piCfg,
      env: { PATH: process.env.PATH || '/usr/bin:/bin', HOME: root },
      entry: { command: process.execPath, args: [piOrphanReader] },
      what: 'the Hive memory reader',
    })

    // 7a. Direct channelProxy call timeout (700ms): leader dies on SIGTERM, TERM-ignoring descendant is SIGKILLed.
    writeFileSync(piOrphanModeFile, 'hang-call')
    rmSync(piOrphanPidsFile, { force: true })
    const proxyTimeoutErr = await proxy.call('memory_wake', { max_chars: 3500 }).then(() => '', err => err.message)
    const pPair1 = existsSync(piOrphanPidsFile) ? JSON.parse(readFileSync(piOrphanPidsFile, 'utf8')) : { reader: 0, sub: 0 }
    const pAlive1 = (pPair1.reader > 0 && pidAlive(pPair1.reader)) || (pPair1.sub > 0 && pidAlive(pPair1.sub))
    if (pAlive1) killPair(pPair1)
    ok('Pi channelProxy timeout reaps TERM-ignoring descendant even when leader exits on SIGTERM',
      /did not answer within 1s/.test(proxyTimeoutErr) && pPair1.reader > 0 && pPair1.sub > 0 && !pAlive1)

    // 7b. Leader exits early (exit 1) leaving TERM-ignoring descendant: channelProxy close handler reaps descendant.
    writeFileSync(piOrphanModeFile, 'exit-early')
    rmSync(piOrphanPidsFile, { force: true })
    const proxyEarlyErr = await proxy.call('memory_wake', { max_chars: 3500 }).then(() => '', err => err.message)
    const pPair2 = existsSync(piOrphanPidsFile) ? JSON.parse(readFileSync(piOrphanPidsFile, 'utf8')) : { reader: 0, sub: 0 }
    const pAlive2 = (pPair2.reader > 0 && pidAlive(pPair2.reader)) || (pPair2.sub > 0 && pidAlive(pPair2.sub))
    if (pAlive2) killPair(pPair2)
    ok('Pi channelProxy reaps TERM-ignoring descendant when leader exits early',
      /closed \(1\)/.test(proxyEarlyErr) && pPair2.reader > 0 && pPair2.sub > 0 && !pAlive2)

    // 7c. Healthy call followed by reset() and close(): TERM-ignoring descendant spawned by live leader is reaped.
    writeFileSync(piOrphanModeFile, 'ok')
    rmSync(piOrphanPidsFile, { force: true })
    await proxy.call('memory_query', { topic: 'nvoy' })
    await proxy.reset('test-reset')
    const pPair3 = existsSync(piOrphanPidsFile) ? JSON.parse(readFileSync(piOrphanPidsFile, 'utf8')) : { reader: 0, sub: 0 }
    const pAlive3 = (pPair3.reader > 0 && pidAlive(pPair3.reader)) || (pPair3.sub > 0 && pidAlive(pPair3.sub))
    if (pAlive3) killPair(pPair3)
    ok('Pi channelProxy reset() reaps TERM-ignoring descendant after leader exits on SIGTERM',
      pPair3.reader > 0 && pPair3.sub > 0 && !pAlive3)

    rmSync(piOrphanPidsFile, { force: true })
    await proxy.call('memory_query', { topic: 'nvoy' })
    await proxy.close()
    const pPair4 = existsSync(piOrphanPidsFile) ? JSON.parse(readFileSync(piOrphanPidsFile, 'utf8')) : { reader: 0, sub: 0 }
    const pAlive4 = (pPair4.reader > 0 && pidAlive(pPair4.reader)) || (pPair4.sub > 0 && pidAlive(pPair4.sub))
    if (pAlive4) killPair(pPair4)
    ok('Pi channelProxy close() reaps TERM-ignoring descendant after leader exits on SIGTERM',
      pPair4.reader > 0 && pPair4.sub > 0 && !pAlive4)
  } finally {
    if (prevCallMs === undefined) delete process.env.HARNESS_CHANNEL_CALL_MS
    else process.env.HARNESS_CHANNEL_CALL_MS = prevCallMs
  }
} finally {
  rmSync(root, { recursive: true, force: true })
}

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
