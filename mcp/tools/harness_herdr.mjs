// A harness session hosted in herdr instead of tmux, on a box where the owner runs herdr. Each
// identity gets its own workspace, labelled with its name, holding the one pane its agent runs in.
// herdr recognises the agent there (claude, codex, pi) and tracks its state itself; the supervisor
// only starts it, answers its startup screens, names it, and restarts it. herdr is never told how
// to resume a harness session: a herdr restart must not reopen one under the owner's own login.

import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const sleep = ms => new Promise(done => setTimeout(done, ms))

// The identity's name in herdr, for its workspace and its agent alike: lowercase letters and digits
// only (mc-claude is mcclaude), the way the owner names agents and calls them by voice. herdr
// allows '-' and '_' too, starting with a letter, at most 32.
export function herdrAgentName(id) {
  const name = String(id || '').toLowerCase().replace(/[^a-z0-9]/g, '')
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(name)) throw new Error(`${id} cannot be a herdr agent name`)
  return name
}

export function herdrClient({ bin = process.env.HARNESS_HERDR_BIN || 'herdr', env = process.env } = {}) {
  const call = (args, { json = true } = {}) => {
    const r = spawnSync(bin, args, { encoding: 'utf8', env, timeout: 15000 })
    if (r.error) throw new Error(`herdr ${args[0]} ${args[1] || ''}: ${r.error.code || r.error.message}`)
    if (!json) { if (r.status !== 0) throw new Error(`herdr ${args.slice(0, 2).join(' ')} failed: ${(r.stderr || r.stdout || '').trim().slice(0, 200)}`); return r.stdout || '' }
    let out
    try { out = JSON.parse(r.stdout || '{}') } catch { throw new Error(`herdr ${args.slice(0, 2).join(' ')} answered: ${(r.stderr || r.stdout || '').trim().slice(0, 200)}`) }
    if (out.error) throw new Error(`herdr ${args.slice(0, 2).join(' ')}: ${out.error.message || out.error.code}`)
    return out.result || {}
  }
  const client = {
    available() { try { call(['workspace', 'list']); return true } catch { return false } },
    // The identity's workspace and its first pane, created when missing.
    pane({ label, cwd }) {
      const found = (call(['workspace', 'list']).workspaces || []).find(w => w.label === label)
      if (found) {
        const panes = call(['pane', 'list', '--workspace', found.workspace_id]).panes || []
        if (panes[0]?.pane_id) return panes[0].pane_id
        throw new Error(`herdr workspace ${label} has no pane`)
      }
      const created = call(['workspace', 'create', '--label', label, '--cwd', cwd, '--no-focus'])
      const pane = JSON.stringify(created).match(/"pane_id":"([^"]+)"/)?.[1]
      if (!pane) throw new Error(`herdr created workspace ${label} but named no pane`)
      return pane
    },
    run(pane, command) { call(['pane', 'run', pane, command]) },
    // The screen as it stands, like tmux capture-pane: scrollback from an earlier run can hold a ready
    // prompt or a startup screen that is no longer there.
    read(pane) { return call(['pane', 'read', pane, '--source', 'visible'], { json: false }) },
    keys(pane, ...keys) { call(['pane', 'send-keys', pane, ...keys]) },
    agent(pane) { return (call(['agent', 'list']).agents || []).find(a => a.pane_id === pane) || null },
    name(pane, name) { call(['agent', 'rename', pane, name]) },
  }
  return client
}

// The launcher a pane runs, as a file the supervisor writes owner-only. Typed into the pane's shell
// it re-executes itself under a built environment (an owner's CLAUDE_CONFIG_DIR or API key never
// reaches the session; herdr's pane variables do), records its pid, reads the credential from its
// file only after that, so the secret is never in a command line or on the screen, and records
// the session's exit status for the supervisor. Echo is off while the session starts: herdr's
// terminal answers the queries an agent sends at startup, and an echoed answer is drawn over its
// screen (it hid the development-channels prompt the supervisor answers; mc-claude, 2026-10-19).
export function launcherScript({ env, cwd, command, pidFile, statusFile, credential = null }) {
  const q = value => `'${String(value).replace(/'/g, `'\\''`)}'`
  // herdr's terminal variables too: without COLORTERM an agent falls back to 256 colours, and Codex's
  // composer shading then all but hides its text (dj-codex, 2026-10-19).
  const kept = ['HERDR_ENV', 'HERDR_PANE_ID', 'HERDR_BIN_PATH', 'HERDR_SOCKET_PATH', 'COLORTERM', 'TERM_PROGRAM', 'TERM_PROGRAM_VERSION']
  return [
    '#!/bin/sh',
    '# Written by the Nvoy harness supervisor; rewritten at each start.',
    'if [ -z "${NVOY_HARNESS_CLEAN:-}" ]; then',
    `  exec env -i NVOY_HARNESS_CLEAN=1 ${Object.entries(env).map(([k, v]) => `${k}=${q(v)}`).join(' ')} \\`,
    `    ${kept.map(k => `${k}="\${${k}:-}"`).join(' ')} /bin/sh "$0"`,
    'fi',
    'unset NVOY_HARNESS_CLEAN',
    `echo $$ > ${q(pidFile)}`,
    `rm -f ${q(statusFile)}`,
    ...(credential ? [`${credential.env}=$(cat ${q(credential.file)}) || exit 1`, `export ${credential.env}`] : []),
    `cd ${q(cwd)} || exit 1`,
    'stty -echo 2>/dev/null',
    command.map(q).join(' '),
    'status=$?',
    'stty echo 2>/dev/null',
    `echo $status > ${q(statusFile)}`,
    '',
  ].join('\n')
}

// One process in an identity's pane, run through an owner-only launcher in `dir`: started, watched
// through its pid and exit-status files, named, and stopped with its process group (an interactive
// shell runs the launcher as a job, so it leads its own group). A recorded pid is signalled only
// while it is still that launcher, never a process that has since reused the number.
export function herdrSession({ herdr, name, dir, cwd, file = 'session', log = () => {} }) {
  const launcher = resolve(dir, `${file}.sh`), pidFile = resolve(dir, `${file}.pid`), statusFile = resolve(dir, `${file}.status`)
  const readPid = () => { try { const pid = readFileSync(pidFile, 'utf8').trim(); return /^\d+$/.test(pid) ? pid : '' } catch { return '' } }
  const ours = pid => !!pid && (spawnSync('ps', ['-o', 'args=', '-p', pid], { encoding: 'utf8' }).stdout || '').includes(launcher)
  const signal = (pid, sig) => { try { process.kill(-Number(pid), sig) } catch { try { process.kill(Number(pid), sig) } catch {} } }
  let pane = ''
  const session = {
    started: () => !!pane,
    async start({ command, env, credential = null }) {
      pane = herdr.pane({ label: name, cwd })
      await session.stop()
      rmSync(pidFile, { force: true }); rmSync(statusFile, { force: true })
      writeFileSync(launcher, launcherScript({ env, cwd, command, pidFile, statusFile, credential }), { mode: 0o700 })
      chmodSync(launcher, 0o700)
      herdr.run(pane, `'${launcher.replace(/'/g, `'\\''`)}'`)
    },
    screen: () => herdr.read(pane),
    keys: key => herdr.keys(pane, key),
    dead() {
      if (existsSync(statusFile)) return { dead: true, status: readFileSync(statusFile, 'utf8').trim() }
      const pid = readPid()
      return pid && !ours(pid) ? { dead: true, status: 'gone' } : { dead: false, status: '' }
    },
    pid: readPid,
    // herdr names an agent only once it has recognised one, and forgets the name when it goes.
    named() {
      try { const agent = herdr.agent(pane); if (agent && agent.name !== name) { herdr.name(pane, name); log(`named the herdr agent ${name}`) } } catch {}
    },
    async stop() {
      const pid = readPid()
      if (!ours(pid)) return
      signal(pid, 'SIGTERM')
      for (let i = 0; i < 50 && ours(pid); i++) await sleep(100)
      if (ours(pid)) signal(pid, 'SIGKILL')
    },
    // For an exit handler, which cannot wait.
    kill() { const pid = readPid(); if (ours(pid)) signal(pid, 'SIGTERM') },
  }
  return session
}

// Keep one command shown in a herdr session, run again whenever it exits (a person quitting it, or
// its server restarting under it), until hidden. herdr being down only delays it.
export function herdrKeeper({ session, log = () => {}, everyMs = 5000 }) {
  let want = null, timer = null, busy = false
  const tick = async (fresh = false) => {
    if (!want || busy) return
    busy = true
    try {
      if (fresh || !session.started() || session.dead().dead) { await session.start(want); log(want.started) }
      session.named()
    } catch (error) { log(`herdr: ${error.message}`) } finally { busy = false }
  }
  return {
    async show(spec) {
      want = spec
      if (!timer) { timer = setInterval(() => tick(), everyMs); timer.unref?.() }
      while (busy) await sleep(50)
      await tick(true)
    },
    hide() { want = null; session.kill() },
  }
}
