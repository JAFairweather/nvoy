// The client end of codex-channel-feed.mjs, shared by the portable Codex and Pi harnesses: one
// long-lived ssh on the feed key, an envelope cursor in an owner-only file, and a reconnect from
// that cursor with backoff whenever the fleet recreates the adapter container the feed runs in.
// It sees envelope ids and types only; the message stays on the fleet.

import { chmodSync, readFileSync, writeFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { sshChannelEntry, SSH } from './channel_client.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const sleep = ms => new Promise(done => setTimeout(done, ms))

// The feed's ssh: the hardened channel entry on the feed key, plus keepalives so a dead carrier
// ends the process instead of leaving it waiting.
export function sshFeedArgs(config, aliveSeconds = 15) {
  const entry = sshChannelEntry({ identity: config.feedIdentity, knownHosts: config.knownHosts, target: config.target })
  return [...entry.args.slice(0, -1), '-o', `ServerAliveInterval=${aliveSeconds}`, '-o', 'ServerAliveCountMax=3', entry.args.at(-1)]
}

// undefined: never baselined. null: baselined on an empty queue, so everything it holds is new.
export function feedCursor(path, instance) {
  let cursor
  try { const saved = JSON.parse(readFileSync(path, 'utf8')); if (saved.instance === instance && (saved.cursor === null || HEX64.test(saved.cursor))) cursor = saved.cursor } catch {}
  return {
    get: () => cursor,
    save: value => { cursor = value; writeFileSync(path, JSON.stringify({ version: 1, instance, cursor: value }) + '\n', { mode: 0o600 }); chmodSync(path, 0o600) },
  }
}

// Follows the feed until stopping(). Each hello calls onConnected(n), n counting connections, so
// n > 1 is a reconnect; each admitted envelope after it calls onAdmitted({ envelope, type }). The
// caller saves the cursor once it has taken an envelope, so an envelope it never took is replayed.
export async function followWakeFeed({ config, cursor, ssh = SSH, env, children = new Set(), log, stopping, onAdmitted, onConnected = () => {} }) {
  const KEEPALIVE_MS = Number(process.env.HARNESS_FEED_KEEPALIVE_MS || 20000)
  const SILENCE_MS = Number(process.env.HARNESS_FEED_SILENCE_MS || 90000)
  const FEED_RETRY_MAX_MS = Number(process.env.HARNESS_FEED_RETRY_MAX_MS || 60000)
  let feeds = 0

  async function feedOnce() {
    const since = cursor.get() === undefined ? null : cursor.get() === null ? 'start' : cursor.get()
    const child = spawn(ssh, sshFeedArgs(config), { stdio: ['pipe', 'pipe', 'pipe'], env })
    children.add(child)
    let stderr = '', out = '', healthy = false, lastLine = Date.now(), reason = ''
    const stop = why => { if (!reason) reason = why; try { child.kill('SIGTERM') } catch {} }
    const exited = new Promise(done => child.on('close', code => done(code)))
    child.on('error', error => stop(error.code || error.message))
    child.stdin.on('error', () => {})
    child.stderr.on('data', data => { stderr = (stderr + String(data)).slice(-600) })
    child.stdin.write(JSON.stringify({ since }) + '\n')
    const keepalive = setInterval(() => child.stdin.write('{"ping":1}\n'), KEEPALIVE_MS)
    const watchdog = setInterval(() => { if (Date.now() - lastLine > SILENCE_MS) stop(`silent for ${SILENCE_MS}ms`) }, Math.min(SILENCE_MS, 1000))
    child.stdout.on('data', data => {
      out += data
      if (out.length > 4096 && out.indexOf('\n') < 0) return stop('feed line exceeds its bound')
      let at
      while ((at = out.indexOf('\n')) >= 0) {
        const line = out.slice(0, at); out = out.slice(at + 1); lastLine = Date.now()
        let event
        try { event = JSON.parse(line) } catch { return stop('feed sent malformed JSON') }
        if (event.event === 'hello') {
          if (event.instance !== config.id) return stop('feed answered for another instance')
          healthy = true
          onConnected(++feeds)
          const placed = event.cursor === null || HEX64.test(String(event.cursor)) ? event.cursor : null
          if (cursor.get() === undefined) { cursor.save(placed); log(`first start: baselined the ${config.id} queue; later arrivals are live`) }
          else if (event.since_found === false) { cursor.save(placed); log(`the fleet queue no longer holds the saved cursor; resuming from now`) }
          log('wake feed connected')
        } else if (event.event === 'admitted' && healthy && HEX64.test(String(event.envelope))) {
          onAdmitted({ envelope: event.envelope, type: event.type === 'verified-notification' ? 'verified-notification' : 'admitted-task' })
        }
      }
    })
    const code = await exited
    clearInterval(keepalive); clearInterval(watchdog); children.delete(child)
    return { healthy, reason: reason || `exited (${code})${stderr.trim() ? `: ${stderr.trim().split('\n').at(-1).slice(0, 300)}` : ''}` }
  }

  let delay = 1000
  while (!stopping()) {
    const { healthy, reason } = await feedOnce()
    if (stopping()) break
    if (healthy) delay = 1000
    log(`wake feed ${reason}; reconnecting in ${Math.round(delay / 1000)}s`)
    await sleep(delay)
    delay = Math.min(delay * 2, FEED_RETRY_MAX_MS)
  }
}
