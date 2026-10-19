// A harness session hosted in herdr instead of tmux, on a box where the owner runs herdr. Each
// identity gets its own workspace, labelled with its name, holding the one pane its agent runs in.
// herdr recognises the agent there (claude, codex, pi) and tracks its state itself; the supervisor
// only starts it, answers its startup screens, names it, and restarts it. herdr is never told how
// to resume a harness session: a herdr restart must not reopen one under the owner's own login.

import { spawnSync } from 'node:child_process'

// herdr agent names: lowercase letters, digits, '-' and '_', starting with a letter, at most 32.
export function herdrAgentName(id) {
  const name = String(id || '').toLowerCase().replace(/[^a-z0-9_-]/g, '')
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
    read(pane, lines = 60) { return call(['pane', 'read', pane, '--lines', String(lines)], { json: false }) },
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
// the session's exit status for the supervisor.
export function launcherScript({ env, cwd, command, pidFile, statusFile, credential = null }) {
  const q = value => `'${String(value).replace(/'/g, `'\\''`)}'`
  const kept = ['HERDR_ENV', 'HERDR_PANE_ID', 'HERDR_BIN_PATH', 'HERDR_SOCKET_PATH']
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
    command.map(q).join(' '),
    `echo $? > ${q(statusFile)}`,
    '',
  ].join('\n')
}
