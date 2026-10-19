// A fake herdr for the harness tests: workspaces, panes and agent names in a state file, every call
// logged, and a pane that runs whatever is typed into it in its own process group, as a shell's job.
import { chmodSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export function fakeHerdr(dir) {
  const bin = join(dir, 'herdr'), stateFile = join(dir, 'herdr.json'), logFile = join(dir, 'herdr.log')
  writeFileSync(bin, `#!/usr/bin/env node
const { appendFileSync, readFileSync, writeFileSync } = require('node:fs')
const file = ${JSON.stringify(stateFile)}
const state = (() => { try { return JSON.parse(readFileSync(file, 'utf8')) } catch { return { workspaces: [], panes: {} } } })()
const save = () => writeFileSync(file, JSON.stringify(state))
const [noun, verb, ...rest] = process.argv.slice(2)
appendFileSync(${JSON.stringify(logFile)}, JSON.stringify([noun, verb, ...rest]) + '\\n')
const answer = result => console.log(JSON.stringify({ result }))
if (noun === 'workspace' && verb === 'list') answer({ workspaces: state.workspaces })
else if (noun === 'workspace' && verb === 'create') {
  const n = state.workspaces.length + 1, ws = { workspace_id: 'w' + n, label: rest[rest.indexOf('--label') + 1] }, pane = 'w' + n + ':p1'
  state.workspaces.push(ws); state.panes[pane] = { workspace: ws.workspace_id, name: null }; save()
  answer({ workspace: ws, tab: { root_pane: { pane_id: pane } } })
} else if (noun === 'pane' && verb === 'list') answer({ panes: Object.entries(state.panes).filter(([, p]) => p.workspace === rest[1]).map(([pane_id]) => ({ pane_id })) })
else if (noun === 'pane' && verb === 'run') {
  state.panes[rest[0]].name = null; save()
  require('node:child_process').spawn('/bin/sh', ['-c', 'exec ' + rest[1]], { detached: true, stdio: 'ignore', env: { ...process.env, HERDR_PANE_ID: rest[0] } }).unref()
  answer({})
} else if (noun === 'pane' && verb === 'read') console.log('  ? for shortcuts')
else if (noun === 'pane' && verb === 'send-keys') answer({})
else if (noun === 'agent' && verb === 'list') answer({ agents: Object.entries(state.panes).map(([pane_id, p]) => ({ pane_id, name: p.name })) })
else if (noun === 'agent' && verb === 'rename') { state.panes[rest[0]].name = rest[1]; save(); answer({}) }
else { console.log(JSON.stringify({ error: { code: 'unknown', message: noun + ' ' + verb } })); process.exit(1) }
`)
  chmodSync(bin, 0o755)
  const read = path => { try { return readFileSync(path, 'utf8') } catch { return '' } }
  return {
    bin,
    state: () => { try { return JSON.parse(read(stateFile)) } catch { return { workspaces: [], panes: {} } } },
    calls: () => read(logFile).split('\n').filter(Boolean).map(JSON.parse),
  }
}
