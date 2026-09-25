// Hosted Claude Code and Codex harnesses: the manifest block that turns it on, the Compose service it renders,
// the files that let one persistent session start unattended, and the supervisor's refusals.
// Claude Code is not driven here; a fake `codex app-server` drives the Codex supervisor, and a fake
// tmux that only logs the session it is asked for drives the portable (--remote) Claude supervisor.
// The first live session is the operator's check.
import { appendFileSync, chmodSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, realpathSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { sshChannelEntry } from '../mcp/tools/channel_client.mjs'
import { CODEX_CHANNEL_TOOLS, classifyPane, claudeArgs, codexConfigToml, codexTurnText, defaultInstructions, hasPriorSession, mcpConfig, pendingEnvelopes, seedClaudeJson, seedSettings, serverName } from '../mcp/tools/harness_session.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-hns-'))
const brokerAdapterGid = process.getgid()
const workerHandoffGid = process.getgroups().find(g => g !== brokerAdapterGid)
if (!Number.isInteger(workerHandoffGid)) throw new Error('test runner needs a second supplementary group')
const channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const base = id => ({ version: 1, id, pubkey: 'c'.repeat(64),
  state_dir: join(root, `state-${id}`), runtime_dir: join(root, `run-${id}`), spool_dir: join(root, `spool-${id}`),
  bunker_uri_ref: `/etc/nvoy/credentials/${id}.bunker`, bunker_client_ref: `/etc/nvoy/credentials/${id}.client`,
  broker_adapter_gid: brokerAdapterGid, worker_handoff_gid: workerHandoffGid, watcher_uid: 41021, broker_uid: 41022, adapter_uid: 41023, worker_uid: 41024,
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'],
  relays: ['wss://nos.lol'], worker_enabled: false, delivery_mode: 'notify_only',
  buzz: { relay: 'wss://nave.communities.buzz.xyz', channels: [channel] } })
const harness = { runner: 'claude', credential_ref: '/etc/nvoy/credentials/mc-test.claude-oauth' }
const image = 'registry.example/nvoy@sha256:' + 'e'.repeat(64)
const workerImage = 'registry.example/nvoy-worker@sha256:' + 'a'.repeat(64)

// Each case gets its own manifest root: every production command preflights the whole root, and
// one refused neighbour would fail the rest.
function run(tool, manifest, args = [], env = {}) {
  const dir = mkdtempSync(join(root, 'instances-'))
  writeFileSync(join(dir, `${manifest.id}.json`), JSON.stringify(manifest))
  return spawnSync(process.execPath, [`mcp/tools/${tool}`, '--instance', manifest.id, ...args],
    { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: dir, ...env } })
}

// Manifest
const parse = manifest => spawnSync(process.execPath, ['--input-type=module', '-e',
  `import { readManifest } from './mcp/tools/runtime_manifest.mjs'; try { console.log(JSON.stringify(readManifest(process.env.R, process.env.I).harness)) } catch (e) { console.error(e.message); process.exit(1) }`],
  { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, R: (() => { const d = mkdtempSync(join(root, 'm-')); writeFileSync(join(d, `${manifest.id}.json`), JSON.stringify(manifest)); return d })(), I: manifest.id } })
const accepted = parse({ ...base('mc-test'), harness })
ok('a local-broker, worker-disabled notify_only manifest accepts a Claude harness', accepted.status === 0 && JSON.parse(accepted.stdout).credentialRef === harness.credential_ref)
ok('a manifest without a harness block has none', parse(base('mc-test')).stdout.trim() === 'null')
ok('a harness may name the Codex runner', JSON.parse(parse({ ...base('mc-test'), harness: { ...harness, runner: 'codex' } }).stdout).runner === 'codex')
ok('a harness must name the Claude or Codex runner', parse({ ...base('mc-test'), harness: { ...harness, runner: 'gemini' } }).status !== 0 &&
  parse({ ...base('mc-test'), harness: { ...harness, runner: '' } }).status !== 0)
ok('a harness credential reference must be absolute', parse({ ...base('mc-test'), harness: { ...harness, credential_ref: 'claude-oauth' } }).status !== 0)
ok('a harness credential cannot be one of the Nostr credentials', /must not name a Nostr credential/.test(parse({ ...base('mc-test'), harness: { ...harness, credential_ref: '/etc/nvoy/credentials/mc-test.bunker' } }).stderr))
ok('a harness cannot sit beside a headless model worker', parse({ ...base('mc-test'), harness, delivery_mode: 'headless', worker_enabled: true,
  worker_image: workerImage, worker_runner: 'claude', worker_credential_ref: '/etc/nvoy/credentials/mc-test.provider' }).status !== 0)
ok('a harness may name its model', JSON.parse(parse({ ...base('mc-test'), harness: { ...harness, model: 'claude-opus-5-5' } }).stdout).model === 'claude-opus-5-5')
ok('a harness model cannot smuggle a flag or a shell word', parse({ ...base('mc-test'), harness: { ...harness, model: '--dangerously-skip-permissions' } }).status !== 0 &&
  parse({ ...base('mc-test'), harness: { ...harness, model: 'opus; rm -rf /' } }).status !== 0)
ok('a harness cannot serve a Codex app-server queue', parse({ ...base('mc-test'), harness, delivery_mode: 'codex_app_server', codex_thread_id: '0199a213-81c0-7800-8aa1-bbab2a035a53', codex_transport: 'spawn' }).status !== 0)

// Compose
const rendered = run('render-instance-compose.mjs', { ...base('mc-test'), harness }, ['--image', image, '--worker-image', workerImage])
const out = rendered.stdout
const harnessPart = (out.match(/\n  harness:[\s\S]*?(?=\n  [a-z][a-z_]*:|\nsecrets:|$)/) || [''])[0]
const initPart = (out.match(/\n  init:[\s\S]*?(?=\n  [a-z][a-z_]*:|\nsecrets:|$)/) || [''])[0]
ok('a harness manifest renders a harness service on the release worker image', rendered.status === 0 && harnessPart.includes(`image: ${JSON.stringify(workerImage)}`))
ok('the harness runs as the worker UID with the handoff group, read-only and without capabilities', harnessPart.includes('user: "41024:' + workerHandoffGid + '"') &&
  /read_only: true/.test(harnessPart) && /cap_drop: \[ALL\]/.test(harnessPart) && /no-new-privileges:true/.test(harnessPart))
ok('the harness mounts the adapter runtime queue, its read-only login copy and a persistent home, and nothing keyed',
  harnessPart.includes('source: adapter_runtime') && /source: harness_credentials\n\s+target: \/run\/nvoy-harness-credentials\n\s+read_only: true/.test(harnessPart) &&
  harnessPart.includes('source: harness_home') && !/broker_credentials|bunker|nsec|state_dir|STATE_DIR|spool/i.test(harnessPart))
ok('only the root initializer receives the Claude login secret, from the manifest reference', /nvoy_harness_credential:\n\s+file: "\/etc\/nvoy\/credentials\/mc-test\.claude-oauth"/.test(out) &&
  initPart.includes('source: nvoy_harness_credential') && !/secrets:/.test(harnessPart))
ok('the rendered harness file keeps no template markers or unresolved variables', !/@harness-|\$\{/.test(out))
ok('a notify_only manifest without a harness renders no harness, harness volume or login secret', (() => {
  const plain = run('render-instance-compose.mjs', base('mc-test'), ['--image', image])
  return plain.status === 0 && !/harness/i.test(plain.stdout)
})())
ok('a harness render refuses to guess its image without the release worker digest', /requires --worker-image/.test(run('render-instance-compose.mjs', { ...base('mc-test'), harness }, ['--image', image]).stderr))
ok('a worker image override is still refused where there is neither a worker nor a harness', /worker-disabled/.test(run('render-instance-compose.mjs', base('mc-test'), ['--image', image, '--worker-image', workerImage]).stderr))

// Session files
const manifest = { id: 'mc-test', pubkey: 'c'.repeat(64), buzz: { channels: [channel] } }
ok('the channel server is named for the instance', serverName(manifest) === 'nvoy-mc-test')
const config = mcpConfig({ manifest, root: '/etc/nvoy/instances' })
const entry = config.mcpServers['nvoy-mc-test']
ok('the session starts the keyless channel as its own MCP child for this instance only', Object.keys(config.mcpServers).length === 1 &&
  entry.command === 'node' && JSON.stringify(entry.args) === JSON.stringify(['/srv/nvoy/mcp/tools/claude-channel.mjs', '--instance', 'mc-test']) &&
  JSON.stringify(entry.env) === JSON.stringify({ NVOY_INSTANCE_ROOT: '/etc/nvoy/instances' }))
const seeded = seedClaudeJson({ userID: 'kept', projects: { '/other': { x: 1 }, '/home/harness/workspace': { allowedTools: ['kept'] } } }, '/home/harness/workspace')
ok('first-run and folder-trust flags are asserted and everything Claude Code already wrote is kept', seeded.hasCompletedOnboarding === true && seeded.userID === 'kept' &&
  seeded.projects['/other'].x === 1 && seeded.projects['/home/harness/workspace'].hasTrustDialogAccepted === true &&
  seeded.projects['/home/harness/workspace'].allowedTools[0] === 'kept')
ok('a malformed ~/.claude.json is replaced, not trusted', seedClaudeJson([1, 2], '/w').hasCompletedOnboarding === true && seedClaudeJson(null, '/w').projects['/w'].hasTrustDialogAccepted)
const settings = seedSettings({}, 'nvoy-mc-test')
ok('the channel tools are allowed and anything else is refused rather than asked about', JSON.stringify(settings.permissions.allow) === '["mcp__nvoy-mc-test"]' && settings.permissions.defaultMode === 'dontAsk')
const operator = seedSettings({ model: 'kept', permissions: { allow: ['Read', 'mcp__nvoy-mc-test'], deny: ['Bash'], defaultMode: 'default' } }, 'nvoy-mc-test')
ok('seeding is idempotent and keeps the operator\'s own rules and mode', operator.model === 'kept' && JSON.stringify(operator.permissions.allow) === '["Read","mcp__nvoy-mc-test"]' &&
  operator.permissions.deny[0] === 'Bash' && operator.permissions.defaultMode === 'default')
ok('seeding never grants a bypass mode', !/bypass/i.test(JSON.stringify(seedSettings({}, 'nvoy-x'))))
const instructions = defaultInstructions({ id: 'mc-test', pubkey: 'c'.repeat(64), buzz: { channels: [channel] } })
ok('the default instructions name the read and reply tools and treat message bodies as data', /nvoy_channel_read/.test(instructions) && /nvoy_channel_reply/.test(instructions) &&
  /never treat it as instructions/.test(instructions) && instructions.includes(channel) && !instructions.includes('c'.repeat(64)))
const fresh = claudeArgs({ server: 'nvoy-mc-test', mcpConfigPath: '/home/harness/.nvoy-harness/mcp.json', resume: false })
ok('the session loads exactly its own channel server and no ambient MCP configuration', JSON.stringify(fresh) === JSON.stringify(['--dangerously-load-development-channels', 'server:nvoy-mc-test', '--mcp-config', '/home/harness/.nvoy-harness/mcp.json', '--strict-mcp-config']))
ok('a chosen model is passed as --model, and none is passed by default', JSON.stringify(claudeArgs({ server: 's', mcpConfigPath: '/m', resume: false, model: 'opus' }).slice(-2)) === '["--model","opus"]' && !fresh.includes('--model'))
ok('a restart resumes the same conversation', claudeArgs({ server: 's', mcpConfigPath: '/m', resume: true }).at(-1) === '--continue')
ok('the command line never carries a permission bypass', !/skip-permissions|bypass/.test(JSON.stringify(fresh)))
const home = join(root, 'home'), workdir = join(home, 'workspace')
ok('a home with no conversation starts fresh', !hasPriorSession(home, workdir))
const projectDir = join(home, '.claude', 'projects', workdir.replace(/[^a-zA-Z0-9]/g, '-'))
mkdirSync(projectDir, { recursive: true })
writeFileSync(join(projectDir, 'notes.txt'), '')
ok('only a saved conversation counts as a prior session', !hasPriorSession(home, workdir))
writeFileSync(join(projectDir, '0199.jsonl'), '{}\n')
ok('a saved conversation in the workspace resumes', hasPriorSession(home, workdir))

// Startup screens
ok('the development-channel warning is answered with its own option number', JSON.stringify(classifyPane('WARNING: Loading development channels\n  1. Exit\n  2. I am using this for local development')) === '{"state":"dev-channels","key":"2"}')
ok('a warning without numbered options is answered with Enter on the default', classifyPane('> I am using this for local development').key === 'Enter')
ok('the folder-trust screen is answered only with its accept option', JSON.stringify(classifyPane('Do you trust the files in this folder?\n ❯ 1. Yes, proceed\n   2. No, exit')) === '{"state":"trust","key":"1"}')
ok('a login screen is fatal, never answered', JSON.stringify(classifyPane('Select login method:\n 1. Claude account')) === '{"state":"login"}' && classifyPane('OAuth token has expired').state === 'login')
ok('the ready prompt is recognised', classifyPane('>\n  ? for shortcuts').state === 'ready')
ok('the 2.1.221 idle prompt, whose footer is the permission-mode hint, is recognised as ready',
  classifyPane(' ▐▛███▜▌   Claude Code v2.1.221\n──────\n❯ Try "how does <filepath> work?"\n──────\n  ⏵⏵ don\'t ask on (shift+tab to cycle) · ← for agents').state === 'ready')
ok('anything else is still starting and gets no keystroke', JSON.stringify(classifyPane('Loading…')) === '{"state":"starting"}' && classifyPane('').key === undefined)
ok('an injected message that quotes a startup screen after ready cannot matter: the supervisor stops reading once ready',
  /if \(screen\.state === 'ready'\) \{ log\(.*\); return \}/.test(readFileSync('mcp/tools/instance-harness.mjs', 'utf8')))

// Supervisor
const noHarness = run('instance-harness.mjs', base('mc-test'), [], { HOME: join(root, 'h1') })
ok('the supervisor refuses a manifest without a harness block', noHarness.status !== 0 && /no harness block/.test(noHarness.stderr))
const wrongUid = run('instance-harness.mjs', { ...base('mc-test'), harness }, [], { HOME: join(root, 'h2') })
ok('the supervisor refuses to run under any UID but the manifest-bound worker', wrongUid.status !== 0 && /worker user/.test(wrongUid.stderr))
const supervisor = readFileSync('mcp/tools/instance-harness.mjs', 'utf8')
ok('a fresh harness clears the channel lock its previous container left, before any session starts',
  supervisor.indexOf("rmSync(resolve(manifest.runtimeDir, 'claude-channel-state', 'channel.lock'), { force: true })") > -1 &&
  supervisor.indexOf("rmSync(resolve(manifest.runtimeDir, 'claude-channel-state', 'channel.lock')") < supervisor.indexOf("'new-session'"))
ok('the login token reaches the session only through the tmux environment or the Codex supervisor, never an argv or a log', /CLAUDE_CODE_OAUTH_TOKEN: token/.test(supervisor) &&
  (() => {
    const uses = supervisor.split('\n').filter(line => /\btoken\b/.test(line) && !/^\s*\/\/|let token|token = readFileSync|!token/.test(line))
    return uses.length === 2 && uses[0].includes('credential: token') && uses[1].includes('CLAUDE_CODE_OAUTH_TOKEN: token')
  })())
const codexSupervisor = readFileSync('mcp/tools/codex_harness.mjs', 'utf8')
ok('the Codex supervisor hands the API key only to the app-server environment', (() => {
  const uses = codexSupervisor.split('\n').filter(line => /\bcredential\b/.test(line) && !/^\s*\/\//.test(line))
  return uses.length === 2 && /runCodexHarness\(\{[^}]*credential,/.test(uses[0]) && uses[1].includes('OPENAI_API_KEY: credential')
})())
ok('the supervisor writes the session files owner-only', /writeFileSync\(path, value, \{ mode: 0o600 \}\); chmodSync\(path, 0o600\)/.test(supervisor))
const init = readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')
ok('the initializer copies the login to a worker-owned file, drops the pre-Codex copy, and refuses a stray login source', /provisionSecret\(sources\.harnessCredential, `\$\{harnessCredDir\}\/credential`, m\.workerUid, m\.workerUid/.test(init) &&
  /a runtime without a harness refuses a harness credential source/.test(init) && /rmSync\(`\$\{harnessCredDir\}\/claude-oauth-token`, \{ force: true \}\)/.test(init))
ok('the worker image carries tmux for the session terminal', /apt-get install -y --no-install-recommends ca-certificates tmux/.test(readFileSync('deploy/nvoy-worker.Dockerfile', 'utf8')))
const runner = readFileSync('deploy/runtime-deploy-runner.py', 'utf8')
ok('the fleet reconciler renders a harness with the release worker image and expects its service running', /"harness": raw\.get\("harness"\) is not None/.test(runner) &&
  /instance\["worker"\] or instance\["harness"\]/.test(runner) && /"harness"/.test(runner.slice(runner.indexOf('def verify_running'))))

// Codex session files
const codexManifest = { id: 'dj-test', pubkey: 'c'.repeat(64), buzz: { channels: [channel] } }
const toml = codexConfigToml({ manifest: codexManifest, root: '/etc/nvoy/instances' })
ok('the Codex config loads exactly the keyless Codex channel tools for this instance', (toml.match(/^\[mcp_servers\.[^.\]]+\]$/gm) || []).length === 1 &&
  toml.includes('[mcp_servers.nvoy-dj-test]') && toml.includes('args = ["/srv/nvoy/mcp/tools/codex-channel-mcp.mjs", "--instance", "dj-test"]') &&
  toml.includes('env = { NVOY_INSTANCE_ROOT = "/etc/nvoy/instances" }'))
ok('the Codex config reads the API key from the environment and never asks for an approval', /^model_provider = "nvoy-openai-api"$/m.test(toml) &&
  /^env_key = "OPENAI_API_KEY"$/m.test(toml) && /^requires_openai_auth = false$/m.test(toml) && /^approval_policy = "never"$/m.test(toml) &&
  /^sandbox_mode = "read-only"$/m.test(toml) && !/danger|full-access|sk-/i.test(toml))
ok('each keyless channel tool, and only those, is pre-approved so Codex never elicits one',
  CODEX_CHANNEL_TOOLS.join() === 'nvoy_channel_list,nvoy_channel_read,nvoy_channel_reply' &&
  CODEX_CHANNEL_TOOLS.every(tool => toml.includes(`[mcp_servers.nvoy-dj-test.tools.${tool}]\napproval_mode = "approve"\n`)) &&
  (toml.match(/^approval_mode = /gm) || []).length === 3 && (toml.match(/^\[mcp_servers\.nvoy-dj-test\.tools\./gm) || []).length === 3)
ok('a Codex model is set only when chosen', !/^model = /m.test(toml) && /^model = "gpt-5\.5"$/m.test(codexConfigToml({ manifest: codexManifest, root: '/r', model: 'gpt-5.5' })))
const turn = codexTurnText({ envelope: 'd'.repeat(64), type: 'admitted-task' })
ok('an injected turn carries only the envelope marker and how to read and answer it', turn.includes('d'.repeat(64)) && /nvoy_channel_read/.test(turn) &&
  /nvoy_channel_reply/.test(turn) && turn.endsWith(`NVOY_ENVELOPE_ID=${'d'.repeat(64)}`))
const queue = [JSON.stringify({ envelope: '1'.repeat(64), type: 'admitted-task', body: 'ignored' }), 'not json', JSON.stringify({ envelope: 'XYZ' }),
  JSON.stringify({ envelope: '2'.repeat(64), type: 'verified-notification' }), JSON.stringify({ envelope: '1'.repeat(64), type: 'admitted-task' }),
  JSON.stringify({ envelope: '3'.repeat(64), type: 'something-else' })].join('\n')
ok('pending envelopes are well formed, oldest first, each once, and never repeat a delivered one',
  JSON.stringify(pendingEnvelopes(queue, ['2'.repeat(64)])) === JSON.stringify([{ envelope: '1'.repeat(64), type: 'admitted-task' }, { envelope: '3'.repeat(64), type: 'admitted-task' }]) &&
  pendingEnvelopes('', []).length === 0)

// Codex supervisor, against a fake `codex app-server` that logs what it is sent
const fakeBin = join(root, 'fake-bin')
mkdirSync(fakeBin)
writeFileSync(join(fakeBin, 'codex'), `#!/usr/bin/env node
const { appendFileSync, existsSync } = require('node:fs')
const log = row => appendFileSync(process.env.CODEX_HOME + '/fake.jsonl', JSON.stringify(row) + '\\n')
if (process.argv[2] !== 'app-server') process.exit(2)
log({ start: true, keyed: process.env.OPENAI_API_KEY === 'sk-test-fake', env: Object.keys(process.env).sort() })
const send = m => process.stdout.write(JSON.stringify(m) + '\\n')
let turns = 0, buffer = ''
process.stdin.on('end', () => process.exit(0))
process.stdin.on('data', data => {
  buffer += data
  let at
  while ((at = buffer.indexOf('\\n')) >= 0) {
    const m = JSON.parse(buffer.slice(0, at)); buffer = buffer.slice(at + 1)
    log(m)
    if (m.method === 'initialize') send({ id: m.id, result: { userAgent: 'fake' } })
    const unsaved = existsSync(process.env.CODEX_HOME + '/unsaved')
    if (m.method === 'thread/start') send({ id: m.id, result: { thread: { id: unsaved ? '0199a213-81c0-7800-8aa1-cccccccccccc' : '0199a213-81c0-7800-8aa1-bbab2a035a53' } } })
    if (m.method === 'thread/resume') send(unsaved ? { id: m.id, error: { code: -32600, message: 'no rollout found for thread id ' + m.params.threadId } } : { id: m.id, result: { thread: { id: m.params.threadId } } })
    if (m.method === 'turn/start') {
      const id = 'turn-' + ++turns
      send({ id: m.id, result: { turn: { id } } })
      send({ id: 'srv-' + turns, method: 'item/tool/requestUserInput', params: {} })
      setTimeout(() => send({ method: 'turn/completed', params: { threadId: m.params.threadId, turn: { id, status: 'completed', items: [] } } }), 20)
    }
  }
})
`)
chmodSync(join(fakeBin, 'codex'), 0o755)
const codexHarness = { runner: 'codex', credential_ref: '/etc/nvoy/credentials/dj-test.openai' }
const djRoot = mkdtempSync(join(root, 'instances-'))
const djManifest = { ...base('dj-test'), worker_uid: process.getuid(), harness: codexHarness }
writeFileSync(join(djRoot, 'dj-test.json'), JSON.stringify(djManifest))
mkdirSync(djManifest.runtime_dir, { recursive: true })
const djQueue = join(djManifest.runtime_dir, 'admitted-tasks.jsonl')
const envelope = n => String(n).repeat(64)
writeFileSync(djQueue, JSON.stringify({ envelope: envelope(1), type: 'admitted-task' }) + '\n')
writeFileSync(join(root, 'dj-cred'), 'sk-test-fake\n')
const djHome = join(root, 'dj-home')
const fakeLog = () => { try { return readFileSync(join(djHome, '.codex', 'fake.jsonl'), 'utf8').split('\n').filter(Boolean).map(JSON.parse) } catch { return [] } }
const wait = ms => new Promise(done => setTimeout(done, ms))
async function waitFor(test, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (test()) return true; await wait(25) } return false }
function startCodex() {
  const child = spawn(process.execPath, ['mcp/tools/instance-harness.mjs', '--instance', 'dj-test'], { cwd: resolve('.'), env: { ...process.env,
    NVOY_INSTANCE_ROOT: djRoot, HOME: djHome, NVOY_HARNESS_CREDENTIAL_FILE: join(root, 'dj-cred'), HARNESS_POLL_MS: '25', PATH: `${fakeBin}:${process.env.PATH}` } })
  const run = { child, out: '' }
  child.stdout.on('data', d => { run.out += d }); child.stderr.on('data', d => { run.out += d })
  run.exited = new Promise(done => child.on('exit', done))
  return run
}
const turnStarts = () => fakeLog().filter(m => m.method === 'turn/start')
const first = startCodex()
const firstReady = await waitFor(() => /session ready/.test(first.out))
ok('the Codex supervisor starts a thread in the workspace, baselining what the queue already held', firstReady && /baselined 1 admitted/.test(first.out) &&
  fakeLog().some(m => m.method === 'thread/start' && m.params.cwd === join(djHome, 'workspace')))
appendFileSync(djQueue, JSON.stringify({ envelope: envelope(2), type: 'admitted-task' }) + '\n' + JSON.stringify({ envelope: envelope(3), type: 'verified-notification' }) + '\n')
await waitFor(() => turnStarts().length >= 2 && /turn for 333333333333 ended: completed/.test(first.out))
const injected = turnStarts()
ok('each new admitted envelope is injected once, in order, as a turn on the same thread', injected.length === 2 &&
  injected.every(m => m.params.threadId === '0199a213-81c0-7800-8aa1-bbab2a035a53') &&
  injected[0].params.input[0].text === codexTurnText({ envelope: envelope(2), type: 'admitted-task' }) &&
  injected[1].params.input[0].text === codexTurnText({ envelope: envelope(3), type: 'verified-notification' }) &&
  injected[0].params.clientUserMessageId === `nvoy:${envelope(2)}` && !JSON.stringify(injected).includes(envelope(1)))
ok('a request from Codex is declined, so nothing waits on a person', fakeLog().some(m => m.id === 'srv-1' && m.error && !m.result))
const starts = fakeLog().filter(m => m.start)
ok('the app-server gets the API key and a minimal environment', starts.length === 1 && starts[0].keyed &&
  starts[0].env.filter(k => !/^(__CF|LC_|_$|SHLVL|PWD)/.test(k)).join(',') === 'CODEX_HOME,HOME,OPENAI_API_KEY,PATH')
ok('the key reaches no log', !first.out.includes('sk-test-fake') && !readFileSync(join(djHome, '.nvoy-harness', 'delivered.jsonl'), 'utf8').includes('sk-test'))
ok('the Codex config and instructions are written owner-only, and the instructions only when missing',
  (statSync(join(djHome, '.codex', 'config.toml')).mode & 0o777) === 0o600 && existsSync(join(djHome, 'workspace', 'AGENTS.md')) &&
  (statSync(join(djHome, '.nvoy-harness', 'codex-thread.json')).mode & 0o777) === 0o600)
first.child.kill('SIGTERM'); await first.exited
writeFileSync(join(djHome, 'workspace', 'AGENTS.md'), 'operator edit\n')
const second = startCodex()
await waitFor(() => /session ready/.test(second.out))
appendFileSync(djQueue, JSON.stringify({ envelope: envelope(4), type: 'admitted-task' }) + '\n')
await waitFor(() => turnStarts().length >= 3 && /turn for 444444444444 ended/.test(second.out))
ok('a restart resumes the same thread and injects only what arrived since', /resumed the dj-test thread/.test(second.out) &&
  fakeLog().some(m => m.method === 'thread/resume' && m.params.threadId === '0199a213-81c0-7800-8aa1-bbab2a035a53') &&
  fakeLog().filter(m => m.method === 'thread/start').length === 1 && turnStarts().length === 3 && turnStarts()[2].params.input[0].text.includes(envelope(4)))
ok('the operator\'s instructions survive a restart', readFileSync(join(djHome, 'workspace', 'AGENTS.md'), 'utf8') === 'operator edit\n')
second.child.kill('SIGTERM'); await second.exited
writeFileSync(join(djHome, '.codex', 'unsaved'), '')
const third = startCodex()
await waitFor(() => /session ready/.test(third.out))
appendFileSync(djQueue, JSON.stringify({ envelope: envelope(5), type: 'admitted-task' }) + '\n')
await waitFor(() => turnStarts().length >= 4 && /turn for 555555555555 ended/.test(third.out))
ok('a stored thread Codex never saved is replaced by a new one, not retried forever', /never saved the stored dj-test thread; starting a new one/.test(third.out) &&
  !/next start in/.test(third.out) && fakeLog().filter(m => m.method === 'thread/start').length === 2 &&
  turnStarts()[3]?.params.threadId === '0199a213-81c0-7800-8aa1-cccccccccccc' &&
  JSON.parse(readFileSync(join(djHome, '.nvoy-harness', 'codex-thread.json'), 'utf8')).thread_id === '0199a213-81c0-7800-8aa1-cccccccccccc')
third.child.kill('SIGTERM'); await third.exited

// Portable harness: the same Claude supervisor off the fleet, driven by a client config instead of a manifest
const remoteDir = mkdtempSync(join(root, 'remote-'))
const ownHome = join(remoteDir, 'own-home'), harnessHome = join(ownHome, '.nvoy-harness', 'mac-test')
mkdirSync(ownHome, { mode: 0o700 })
const secretFile = (path, value, mode = 0o600) => { writeFileSync(path, value, { mode }); chmodSync(path, mode); return path }
const keyFile = secretFile(join(remoteDir, 'channel-key'), 'PRIVATE-KEY-MUST-NEVER-PRINT\n')
const knownFile = secretFile(join(remoteDir, 'known_hosts'), 'broker.example ssh-ed25519 AAAAC3NzaTest\n', 0o644)
const loginFile = secretFile(join(remoteDir, 'claude-login'), 'sk-ant-oat-fake-login\n')
const looseKey = secretFile(join(remoteDir, 'loose-key'), 'PRIVATE-KEY-MUST-NEVER-PRINT\n', 0o640)
const fakeClaude = secretFile(join(remoteDir, 'claude'), "#!/bin/sh\necho '2.1.230 (Claude Code)'\n", 0o700)
const client = { instance: 'mac-test', ssh_target: 'nvoy-channel@broker.example', identity_file: keyFile, known_hosts_file: knownFile, credential_file: loginFile }
const clientConfig = (value, mode = 0o600) => secretFile(join(mkdtempSync(join(remoteDir, 'cfg-')), 'client.json'), JSON.stringify(value), mode)
writeFileSync(join(fakeBin, 'tmux'), `#!/usr/bin/env node
const { appendFileSync } = require('node:fs')
const socket = process.argv[3]
let rest = process.argv.slice(4)
if (rest[0] === '-f') rest = rest.slice(2)
const e = process.env
if (rest[0] === 'new-session') appendFileSync(socket + '.log', JSON.stringify({ socket, args: rest, home: e.HOME, configDir: e.CLAUDE_CONFIG_DIR, root: e.NVOY_INSTANCE_ROOT, keyed: e.CLAUDE_CODE_OAUTH_TOKEN === 'sk-ant-oat-fake-login' }) + '\\n')
if (rest[0] === 'display-message') console.log('0 ')
if (rest[0] === 'capture-pane') console.log('  ? for shortcuts')
`)
chmodSync(join(fakeBin, 'tmux'), 0o755)
const remoteEnv = { ...process.env, HOME: ownHome, CLAUDE_CONFIG_DIR: join(ownHome, '.claude'), PATH: `${fakeBin}:${process.env.PATH}`, HARNESS_POLL_MS: '25', HARNESS_WATCH_MS: '50' }
const refused = (value, pattern, mode) => {
  const r = spawnSync(process.execPath, ['mcp/tools/instance-harness.mjs', '--instance', 'mac-test', '--remote', clientConfig(value, mode)], { cwd: resolve('.'), encoding: 'utf8', env: remoteEnv, timeout: 10000 })
  return r.status === 1 && pattern.test(r.stderr) && !/PRIVATE-KEY|sk-ant-oat/.test(r.stdout + r.stderr)
}
ok('a portable config that names a Nostr key or Bunker credential is refused, by field or by value', refused({ ...client, nsec_file: '/x' }, /must not name a Nostr key or Bunker credential/) &&
  refused({ ...client, bunker_uri_ref: '/etc/nvoy/credentials/mac-test.bunker' }, /must not name a Nostr key or Bunker credential/) &&
  refused({ ...client, model: 'nsec1' + 'q'.repeat(58) }, /must not name a Nostr key or Bunker credential/) &&
  refused({ ...client, home: 'bunker://' + 'b'.repeat(64) }, /must not name a Nostr key or Bunker credential/))
ok('a portable config refuses relative paths', refused({ ...client, identity_file: 'channel-key' }, /SSH identity file path must be absolute/) &&
  refused({ ...client, known_hosts_file: 'known_hosts' }, /known_hosts file path must be absolute/) &&
  refused({ ...client, credential_file: 'claude-login' }, /credential file path must be absolute/) && refused({ ...client, home: 'harness' }, /home path must be absolute/))
ok('a portable config refuses an SSH key or login that group or other can read', refused({ ...client, identity_file: looseKey }, /SSH identity file must not be accessible by group or other/) &&
  refused({ ...client, credential_file: looseKey }, /credential file must not be accessible by group or other/))
ok('a portable config refuses another instance, an unknown field, a writable config, and the owner\'s own home', refused({ ...client, instance: 'other-test' }, /different instance/) &&
  refused({ ...client, extra: 1 }, /unknown field extra/) && refused(client, /client config must not be group\/world writable/, 0o666) &&
  refused({ ...client, home: ownHome }, /never your home/) && refused({ ...client, ssh_target: '-oProxyCommand=x@h' }, /fixed user@host/))
const doctor = spawnSync(process.execPath, ['mcp/tools/claude-channel-doctor.mjs', '--mode', 'client', '--server', 'nvoy-mac-test', '--claude', fakeClaude,
  '--identity-file', keyFile, '--known-hosts-file', knownFile, '--ssh-target', client.ssh_target], { cwd: resolve('.'), encoding: 'utf8' })
const doctorConfig = JSON.parse(doctor.stdout || '{}').mcpConfig
const pureRemote = mcpConfig({ manifest: { id: 'mac-test' }, root, remote: { identity: doctorConfig?.mcpServers['nvoy-mac-test'].args.at(-2), knownHosts: resolve(knownFile), target: client.ssh_target } })
ok('the portable channel entry is the doctor\'s client entry, from the one shared function', doctor.status === 0 && Object.keys(pureRemote.mcpServers).length === 1 &&
  JSON.stringify(pureRemote.mcpServers['nvoy-mac-test']) === JSON.stringify(sshChannelEntry({ identity: doctorConfig.mcpServers['nvoy-mac-test'].args.at(-2), knownHosts: resolve(knownFile), target: client.ssh_target })))
const fleetRoot = mkdtempSync(join(root, 'instances-'))
writeFileSync(join(fleetRoot, 'mac-test.json'), JSON.stringify({ ...base('mac-test'), harness }))
const localLock = join(root, 'run-mac-test', 'claude-channel-state', 'channel.lock')
mkdirSync(join(root, 'run-mac-test', 'claude-channel-state'), { recursive: true })
writeFileSync(localLock, '99999\n')
const portable = spawn(process.execPath, ['mcp/tools/instance-harness.mjs', '--instance', 'mac-test', '--remote', clientConfig(client)],
  { cwd: resolve('.'), env: { ...remoteEnv, NVOY_INSTANCE_ROOT: fleetRoot } })
let portableOut = ''
portable.stdout.on('data', d => { portableOut += d }); portable.stderr.on('data', d => { portableOut += d })
const portableExited = new Promise(done => portable.on('exit', done))
ok('the portable supervisor starts its session and sees it ready', await waitFor(() => /mac-test session ready/.test(portableOut)))
await wait(200)
const readText = path => { try { return readFileSync(path, 'utf8') } catch { return '' } }
const written = readText(join(harnessHome, '.nvoy-harness', 'mcp.json'))
const writtenEntry = (() => { try { return JSON.parse(written).mcpServers['nvoy-mac-test'] } catch { return {} } })()
ok('the portable session\'s MCP config is exactly the doctor\'s client config for this instance', !!written && JSON.stringify(JSON.parse(written)) === JSON.stringify(doctorConfig))
ok('the portable entry is the hardened ssh tunnel and carries no secret value', writtenEntry.command === '/usr/bin/ssh' &&
  ['-F /dev/null', 'BatchMode=yes', 'IdentitiesOnly=yes', 'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null', 'ClearAllForwardings=yes', `UserKnownHostsFile=${realpathSync(knownFile)}`, `-i ${realpathSync(keyFile)}`]
    .every(flag => writtenEntry.args.join(' ').includes(flag)) && !/PRIVATE-KEY|sk-ant-oat/.test(written + portableOut))
const sessions = readText(join(harnessHome, '.nvoy-harness', 'tmux.sock.log')).split('\n').filter(Boolean).map(JSON.parse)
ok('the portable session runs on its own tmux socket inside the harness home, with the channel loaded', sessions.length === 1 &&
  sessions[0].socket === join(harnessHome, '.nvoy-harness', 'tmux.sock') && sessions[0].args.includes('claude') && sessions[0].args.includes('server:nvoy-mac-test') &&
  sessions[0].args.includes(join(harnessHome, '.nvoy-harness', 'mcp.json')) && !JSON.stringify(sessions[0].args).includes('sk-ant-oat'))
ok('the portable session gets the harness home and the login, and neither the owner\'s CLAUDE_CONFIG_DIR nor a fleet root', sessions[0]?.home === harnessHome &&
  sessions[0].keyed && sessions[0].configDir === undefined && sessions[0].root === undefined)
ok('the portable harness seeds its own home and never touches the owner\'s ~/.claude or ~/.claude.json', !existsSync(join(ownHome, '.claude')) && !existsSync(join(ownHome, '.claude.json')) &&
  (statSync(join(harnessHome, '.claude.json')).mode & 0o777) === 0o600 &&
  JSON.parse(readText(join(harnessHome, '.claude', 'settings.json'))).permissions.allow.includes('mcp__nvoy-mac-test') &&
  !/Nostr key/.test(readText(join(harnessHome, 'workspace', 'CLAUDE.md'))))
ok('the portable harness leaves every local channel lock alone: the lock is the fleet\'s', readText(localLock) === '99999\n')
portable.kill('SIGTERM'); await portableExited

rmSync(root, { recursive: true, force: true })
console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
