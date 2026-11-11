// herdr-own-pane.mjs — a supervisor must never adopt its own pane as the agent's (crusty, 2026-11-11).
//
//   node test/herdr-own-pane.mjs
//
// herd-infra's add-agent labels an agent's own herdr workspace after the agent, and only an nvoy-claude
// agent gets a `-harness` suffix. For an nvoy-pi agent the workspace the supervisor looks up by label is
// therefore the one it is running in. Adopting that pane made start() send ctrl+c to itself and type the
// launcher into its own stdin: pi never started, nothing was logged, and every restart did the same.
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { herdrClient } from '../mcp/tools/harness_herdr.mjs'
import { fakeHerdr } from './fake-herdr.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const dir = mkdtempSync(join(tmpdir(), 'nvoy-ownpane-'))
const fake = fakeHerdr(dir)
const run = (...args) => spawnSync(fake.bin, args, { encoding: 'utf8' })
run('workspace', 'create', '--label', 'crusty', '--cwd', dir, '--no-focus')          // w1, pane w1:p1: where agent-run is typed
const client = (own) => herdrClient({ bin: fake.bin, env: { ...process.env, ...(own ? { HERDR_PANE_ID: own } : { HERDR_PANE_ID: '' }) } })
const err = (fn) => { try { fn(); return null } catch (e) { return e.message } }

const refused = err(() => client('w1:p1').pane({ label: 'crusty', cwd: dir }))
ok('the workspace the supervisor itself runs in is refused as the agent\'s pane', /itself runs in \(w1:p1\)/.test(refused || ''))
ok('  …and the message says how to fix it', /herdr workspace rename w1 crusty-harness/.test(refused || ''))
ok('  …without creating anything or sending any keys', fake.state().workspaces.length === 1 && !fake.calls().some(c => c[1] === 'send-keys' || c[1] === 'create' && c.includes('--cwd') && c.indexOf('crusty') !== c.lastIndexOf('crusty')))

// The pair: the same lookup from a pane that is NOT in that workspace still finds it, as it must.
ok('PAIR: a supervisor running elsewhere still adopts the identity\'s workspace pane', client('w9:p1').pane({ label: 'crusty', cwd: dir }) === 'w1:p1')
ok('PAIR: with no HERDR_PANE_ID (not in a herdr pane) the lookup is unchanged', client('').pane({ label: 'crusty', cwd: dir }) === 'w1:p1')

// The fix the error asks for: once the supervisor's own workspace is labelled crusty-harness, the agent
// gets its own `crusty` workspace and pane.
const renamed = fake.state()
renamed.workspaces[0].label = 'crusty-harness'
import('node:fs').then(({ writeFileSync }) => {
  writeFileSync(join(dir, 'herdr.json'), JSON.stringify(renamed))
  const pane = client('w1:p1').pane({ label: 'crusty', cwd: dir })
  ok('PAIR: after the rename, the supervisor opens a separate workspace for the agent', pane !== 'w1:p1' && fake.state().workspaces.some(w => w.label === 'crusty'))
  ok('  …and does not touch its own workspace', fake.state().workspaces.some(w => w.label === 'crusty-harness'))

  // close() must not take the supervisor with it.
  const dir2 = mkdtempSync(join(tmpdir(), 'nvoy-ownpane2-')), fake2 = fakeHerdr(dir2)
  spawnSync(fake2.bin, ['workspace', 'create', '--label', 'crusty', '--cwd', dir2, '--no-focus'])
  const c2 = herdrClient({ bin: fake2.bin, env: { ...process.env, HERDR_PANE_ID: 'w1:p1' } })
  ok('close() refuses a workspace holding the supervisor\'s own pane', /own pane/.test(err(() => c2.close('crusty')) || ''))
  ok('  …and the workspace is still there', fake2.state().workspaces.length === 1)
  herdrClient({ bin: fake2.bin, env: { ...process.env, HERDR_PANE_ID: 'w9:p1' } }).close('crusty')
  ok('PAIR: close() from elsewhere still closes it', fake2.state().workspaces.length === 0)
  console.log(fails ? `\n${fails} FAILED` : '\nall passed')
  process.exit(fails ? 1 : 0)
})
