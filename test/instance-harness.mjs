// Hosted Claude Code harness: the manifest block that turns it on, the Compose service it renders,
// the files that let one persistent session start unattended, and the supervisor's refusals.
// tmux and Claude Code are not driven here; the first live session is the operator's check.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { classifyPane, claudeArgs, defaultInstructions, hasPriorSession, mcpConfig, seedClaudeJson, seedSettings, serverName } from '../mcp/tools/harness_session.mjs'

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
ok('a harness must name the Claude runner', parse({ ...base('mc-test'), harness: { ...harness, runner: 'codex' } }).status !== 0)
ok('a harness credential reference must be absolute', parse({ ...base('mc-test'), harness: { ...harness, credential_ref: 'claude-oauth' } }).status !== 0)
ok('a harness credential cannot be one of the Nostr credentials', /must not name a Nostr credential/.test(parse({ ...base('mc-test'), harness: { ...harness, credential_ref: '/etc/nvoy/credentials/mc-test.bunker' } }).stderr))
ok('a harness cannot sit beside a headless model worker', parse({ ...base('mc-test'), harness, delivery_mode: 'headless', worker_enabled: true,
  worker_image: workerImage, worker_runner: 'claude', worker_credential_ref: '/etc/nvoy/credentials/mc-test.provider' }).status !== 0)
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
ok('anything else is still starting and gets no keystroke', JSON.stringify(classifyPane('Loading…')) === '{"state":"starting"}' && classifyPane('').key === undefined)
ok('an injected message that quotes a startup screen after ready cannot matter: the supervisor stops reading once ready',
  /if \(screen\.state === 'ready'\) \{ log\(.*\); return \}/.test(readFileSync('mcp/tools/instance-harness.mjs', 'utf8')))

// Supervisor
const noHarness = run('instance-harness.mjs', base('mc-test'), [], { HOME: join(root, 'h1') })
ok('the supervisor refuses a manifest without a harness block', noHarness.status !== 0 && /no harness block/.test(noHarness.stderr))
const wrongUid = run('instance-harness.mjs', { ...base('mc-test'), harness }, [], { HOME: join(root, 'h2') })
ok('the supervisor refuses to run under any UID but the manifest-bound worker', wrongUid.status !== 0 && /worker user/.test(wrongUid.stderr))
const supervisor = readFileSync('mcp/tools/instance-harness.mjs', 'utf8')
ok('the login token reaches the session only through the tmux environment, never an argv or a log', /CLAUDE_CODE_OAUTH_TOKEN: token/.test(supervisor) &&
  (() => {
    const uses = supervisor.split('\n').filter(line => /\btoken\b/.test(line) && !/^\s*\/\/|let token|token = readFileSync|!token/.test(line))
    return uses.length === 1 && uses[0].includes('CLAUDE_CODE_OAUTH_TOKEN: token')
  })())
ok('the supervisor writes the session files owner-only', /writeFileSync\(path, value, \{ mode: 0o600 \}\); chmodSync\(path, 0o600\)/.test(supervisor))
const init = readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')
ok('the initializer copies the login to a worker-owned file and refuses a stray login source', /provisionSecret\(sources\.harnessCredential, `\$\{harnessCredDir\}\/claude-oauth-token`, m\.workerUid, m\.workerUid/.test(init) &&
  /a runtime without a harness refuses a harness credential source/.test(init))
ok('the worker image carries tmux for the session terminal', /apt-get install -y --no-install-recommends ca-certificates tmux/.test(readFileSync('deploy/nvoy-worker.Dockerfile', 'utf8')))
const runner = readFileSync('deploy/runtime-deploy-runner.py', 'utf8')
ok('the fleet reconciler renders a harness with the release worker image and expects its service running', /"harness": raw\.get\("harness"\) is not None/.test(runner) &&
  /instance\["worker"\] or instance\["harness"\]/.test(runner) && /"harness"/.test(runner.slice(runner.indexOf('def verify_running'))))

rmSync(root, { recursive: true, force: true })
console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
