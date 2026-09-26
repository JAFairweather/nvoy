// Webhook wake for a harness hosted off the fleet: the notifier that POSTs one envelope id per new
// admitted envelope, its credential checks, the manifest block, the rendered `notifier` service and
// the reconciler's expectation of it. The notifier runs for real against a local HTTPS server whose
// throwaway certificate is made here and trusted through NODE_EXTRA_CA_CERTS, so the production
// https-only check is exercised as it is. No real webhook, URL or key is used.
import { appendFileSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:https'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { parseWebhookHeaders, parseWebhookUrl, readCredential, wakeBody, MAX_HEADERS_FILE } from '../mcp/tools/wake_webhook.mjs'
import { admittedMeta } from '../mcp/tools/admitted_queue.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = realpathSync(mkdtempSync(join(tmpdir(), 'nvoy-wwh-')))
const wait = ms => new Promise(done => setTimeout(done, ms))
async function waitFor(test, ms = 8000) { const end = Date.now() + ms; while (Date.now() < end) { if (test()) return true; await wait(20) } return false }
const readText = path => { try { return readFileSync(path, 'utf8') } catch { return '' } }
const envelope = n => n.toString(16).padStart(2, '0').repeat(32)
const brokerAdapterGid = process.getgid()
const workerHandoffGid = process.getgroups().find(g => g !== brokerAdapterGid)
if (!Number.isInteger(workerHandoffGid)) throw new Error('test runner needs a second supplementary group')
const channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const wakeWebhook = id => ({ url_ref: `/etc/nvoy/credentials/${id}.wake-webhook.url`, headers_ref: `/etc/nvoy/credentials/${id}.wake-webhook.headers` })
const base = (id, extra = {}) => ({ version: 1, id, pubkey: 'c'.repeat(64),
  state_dir: join(root, `st-${id}`), runtime_dir: join(root, `rt-${id}`), spool_dir: join(root, `sp-${id}`),
  bunker_uri_ref: `/etc/nvoy/credentials/${id}.bunker`, bunker_client_ref: `/etc/nvoy/credentials/${id}.client`,
  broker_adapter_gid: brokerAdapterGid, worker_handoff_gid: workerHandoffGid, watcher_uid: 41021, broker_uid: 41022, adapter_uid: 41023, worker_uid: process.getuid(),
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'],
  relays: ['wss://nos.lol'], worker_enabled: false, delivery_mode: 'notify_only',
  buzz: { relay: 'wss://nave.communities.buzz.xyz', channels: [channel] }, wake_webhook: wakeWebhook(id), ...extra })
// Queue lines carry everything a real record does; none of it but the envelope, type and time may leave.
const record = (n, type = 'admitted-task') => JSON.stringify({ version: 1, type, instance: 'x', envelope: envelope(n), received_at: 1000 + n,
  sender: 'd'.repeat(64), messages: [{ sender: 'd'.repeat(64), content: `SECRET-BODY-${n}` }], authority: { grant: 'SECRET-GRANT' }, notification: { content: 'SECRET-NOTE' } }) + '\n'

// A throwaway certificate for 127.0.0.1, trusted only by the notifier processes started here.
const certDir = join(root, 'tls'); mkdirSync(certDir)
const tls = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
  '-keyout', join(certDir, 'key.pem'), '-out', join(certDir, 'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8' })
if (tls.status !== 0) throw new Error('openssl could not make the test certificate')

// One HTTPS server; the first path segment names the scenario, whose handler picks the answer.
const requests = [], handlers = {}
let inFlight = 0, maxInFlight = 0
const server = createServer({ key: readFileSync(join(certDir, 'key.pem')), cert: readFileSync(join(certDir, 'cert.pem')) }, (req, res) => {
  let body = ''
  req.on('data', chunk => { body += chunk })
  req.on('end', async () => {
    const scenario = req.url.split('/')[1], seen = requests.filter(r => r.scenario === scenario).length
    const row = { scenario, method: req.method, url: req.url, headers: req.headers, body, t: Date.now() }
    requests.push(row)
    inFlight++; maxInFlight = Math.max(maxInFlight, inFlight)
    const answer = (handlers[scenario] || (() => ({ status: 204 })))(row, seen)
    if (answer.hang) return
    if (answer.delay) await wait(answer.delay)
    inFlight--
    res.writeHead(answer.status, { 'Content-Type': 'text/plain' }); res.end('RESPONSE-SECRET-BODY')
  })
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
const port = server.address().port
const posts = scenario => requests.filter(r => r.scenario === scenario)
const bodies = scenario => posts(scenario).map(r => JSON.parse(r.body))

const outputs = []
function setup(id, scenario, { url, headers, manifest = {} } = {}) {
  const fleet = mkdtempSync(join(root, 'i-'))
  const m = base(id, manifest)
  writeFileSync(join(fleet, `${id}.json`), JSON.stringify(m))
  mkdirSync(join(m.runtime_dir, 'claude-channel-state'), { recursive: true, mode: 0o700 })
  const credentials = mkdtempSync(join(root, 'cred-'))
  const urlFile = join(credentials, 'url'), headersFile = join(credentials, 'headers')
  writeFileSync(urlFile, url ?? `https://127.0.0.1:${port}/${scenario}/hooks/wake?token=URLSECRET-TOKEN\n`, { mode: 0o600 })
  writeFileSync(headersFile, headers ?? 'Authorization: Bearer HEADERSECRET-VALUE\nX-Wake-Tenant: HEADERSECRET-TENANT\n', { mode: 0o600 })
  const queue = join(m.runtime_dir, 'admitted-tasks.jsonl')
  writeFileSync(queue, '')
  return { id, fleet, m, queue, urlFile, headersFile, readLog: join(m.runtime_dir, 'claude-channel-state', 'read.jsonl'),
    state: join(m.runtime_dir, 'wake-webhook-state', 'state.json') }
}
function notifier(s, flags = [], env = {}) {
  const child = spawn(process.execPath, ['mcp/tools/admitted-webhook-notify.mjs', '--instance', s.id, '--poll-ms', '25', '--timeout-ms', '1000', ...flags],
    { cwd: resolve('.'), env: { ...process.env, NVOY_INSTANCE_ROOT: s.fleet, NVOY_WAKE_WEBHOOK_URL_FILE: s.urlFile,
      NVOY_WAKE_WEBHOOK_HEADERS_FILE: s.headersFile, NODE_EXTRA_CA_CERTS: join(certDir, 'cert.pem'), ...env } })
  const run = { child, out: '', err: '' }
  child.stdout.on('data', data => { run.out += data })
  child.stderr.on('data', data => { run.err += data })
  run.exited = new Promise(done => child.on('exit', code => { outputs.push(run.out + run.err); done(code) }))
  run.stop = () => { child.kill('SIGTERM'); return run.exited }
  return run
}
// An adapter rewrite replaces the file; a truncate-then-write would look like appended history.
const rewrite = (path, text) => { writeFileSync(`${path}.new`, text); renameSync(`${path}.new`, path) }
const markRead = (s, n) => appendFileSync(s.readLog, JSON.stringify({ version: 1, instance: s.id, envelope: envelope(n), read_at: Date.now() }) + '\n', { mode: 0o600 })

try {
  // Delivery, body shape, headers, order
  const a = setup('wa-test', 'a')
  writeFileSync(a.queue, record(1) + record(2))
  let na = notifier(a, ['--renotify-ms', '86400000'])
  ok('the first start baselines at the queue end and posts no history', await waitFor(() => /baselined at 02020202/.test(na.out)) &&
    await wait(300).then(() => posts('a').length === 0) && JSON.parse(readText(a.state)).cursor === envelope(2))
  appendFileSync(a.queue, record(3))
  ok('a new admitted envelope is posted once', await waitFor(() => posts('a').length === 1) && await wait(200).then(() => posts('a').length === 1))
  const first = posts('a')[0]
  ok('the body is exactly instance, envelope, type and receipt time, in that order', first.body === JSON.stringify({ instance: 'wa-test', envelope: envelope(3), type: 'admitted-task', at: 1003 }))
  ok('it is an HTTPS POST to the operator URL with a JSON content type and the operator headers', first.method === 'POST' && first.url === '/a/hooks/wake?token=URLSECRET-TOKEN' &&
    first.headers['content-type'] === 'application/json' && first.headers.authorization === 'Bearer HEADERSECRET-VALUE' && first.headers['x-wake-tenant'] === 'HEADERSECRET-TENANT')
  ok('the log names the envelope prefix and the status only', /POST 03030303 -> 204/.test(na.out))
  appendFileSync(a.queue, record(4, 'verified-notification'))
  ok('a verified notification keeps its type', await waitFor(() => posts('a').length === 2) && bodies('a')[1].type === 'verified-notification')
  ok('no message body, sender, authority or notification reaches the wire', posts('a').every(r => !/SECRET|"(?:sender|messages|authority|notification|content)"/.test(r.body) &&
    JSON.stringify(Object.keys(JSON.parse(r.body))) === '["instance","envelope","type","at"]'))
  handlers.a = () => ({ status: 204, delay: 60 })
  maxInFlight = 0
  appendFileSync(a.queue, record(5) + record(6) + record(7))
  ok('a burst is delivered in queue order, one request in flight at a time', await waitFor(() => posts('a').length === 5) &&
    JSON.stringify(bodies('a').slice(2).map(b => b.envelope)) === JSON.stringify([5, 6, 7].map(envelope)) && maxInFlight === 1)
  handlers.a = undefined
  await waitFor(() => /POST 07070707 -> 204/.test(na.out))
  await na.stop()
  ok('the cursor persists as an envelope id, owner-only', JSON.parse(readText(a.state)).cursor === envelope(7) && (statSync(a.state).mode & 0o777) === 0o600)
  appendFileSync(a.queue, record(8))
  na = notifier(a, ['--renotify-ms', '86400000'])
  ok('a restart resumes from its cursor: only what arrived while it was down is posted', await waitFor(() => posts('a').length === 6) &&
    await wait(200).then(() => posts('a').length === 6) && bodies('a')[5].envelope === envelope(8) && !/baselined/.test(na.out))
  rewrite(a.queue, record(7) + record(8) + record(9))
  ok('a rewritten queue is re-placed on the last envelope seen', await waitFor(() => posts('a').length === 7) && bodies('a')[6].envelope === envelope(9) &&
    await wait(200).then(() => posts('a').length === 7))
  rewrite(a.queue, record(10))
  await wait(200)
  appendFileSync(a.queue, record(11))
  ok('a rewrite without the last envelope seen continues from its end rather than replaying', await waitFor(() => posts('a').length === 8) &&
    bodies('a')[7].envelope === envelope(11) && await wait(150).then(() => posts('a').length === 8))
  await waitFor(() => /POST 0b0b0b0b -> 204/.test(na.out))
  await na.stop()
  rewrite(a.queue, record(20) + record(21))
  na = notifier(a, ['--renotify-ms', '86400000'])
  ok('a cursor the queue no longer holds starts from its end on restart, posting nothing old', await waitFor(() => /cursor is not in the admitted queue/.test(na.out)) &&
    await wait(250).then(() => posts('a').length === 8) && JSON.parse(readText(a.state)).cursor === envelope(21))
  markRead(a, 22)
  appendFileSync(a.queue, record(22))
  ok('an envelope the harness has already read is not posted', await waitFor(() => /16161616 already read; not posted/.test(na.out)) && posts('a').length === 8)
  await na.stop()
  // An oversized record whose tail, cut at the reader's 1 MiB chunk boundary, is itself a valid record.
  const pad = 2 * 1024 * 1024 - statSync(a.queue).size
  appendFileSync(a.queue, 'x'.repeat(pad) + record(23) + record(24))
  na = notifier(a, ['--renotify-ms', '86400000'])
  ok('a record over its 1 MiB bound is dropped whole, not split into lines that might parse', await waitFor(() => posts('a').length === 9) &&
    bodies('a')[8].envelope === envelope(24) && await wait(200).then(() => posts('a').length === 9) && !/17171717/.test(na.out))
  await na.stop()

  // Retry, backoff, give-up and error classes
  const b = setup('wb-test', 'b')
  handlers.b = () => ({ status: 500 })
  const nb = notifier(b, ['--attempts', '3', '--retry-ms', '60', '--retry-max-ms', '1000', '--renotify-ms', '86400000'])
  await waitFor(() => /baselined/.test(nb.out))
  appendFileSync(b.queue, record(1))
  ok('a failing webhook is retried a bounded number of times, then given up and logged', await waitFor(() => /gave up on 01010101 after 3 attempt/.test(nb.out)) &&
    posts('b').length === 3 && await wait(300).then(() => posts('b').length === 3))
  const gaps = posts('b').slice(1).map((r, i) => r.t - posts('b')[i].t)
  ok('retries back off', gaps[0] >= 55 && gaps[1] >= 115 && gaps[1] > gaps[0])
  ok('each failed attempt logs its status and the next delay', /POST 01010101 -> 500; retry in 60ms/.test(nb.out) && /POST 01010101 -> 500; retry in 120ms/.test(nb.out))
  handlers.b = (row, seen) => ({ status: seen < 4 ? 503 : 202 })
  appendFileSync(b.queue, record(2))
  ok('the queue moves on after a give-up, and a transient failure recovers on retry', await waitFor(() => /POST 02020202 -> 202/.test(nb.out)) && posts('b').length === 5 &&
    JSON.parse(readText(b.state)).cursor === envelope(2))
  handlers.b = (row, seen) => seen === 5 ? { hang: true } : { status: 204 }
  appendFileSync(b.queue, record(3))
  ok('a POST that outlives its timeout is logged as a timeout and retried', await waitFor(() => /POST 03030303 -> timeout; retry/.test(nb.out) && /POST 03030303 -> 204/.test(nb.out), 6000))
  await nb.stop()
  const closedPort = await new Promise(done => { const probe = createServer().listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close(() => done(port)) }) })
  const closed = setup('wc-test', 'c', { url: `https://127.0.0.1:${closedPort}/c/hooks\n` })
  const nc = notifier(closed, ['--attempts', '2', '--retry-ms', '20'])
  await waitFor(() => /baselined/.test(nc.out))
  appendFileSync(closed.queue, record(1))
  ok('a network failure is logged by its error class', await waitFor(() => /POST 01010101 -> ECONNREFUSED/.test(nc.out) && /gave up on 01010101/.test(nc.out)))
  await nc.stop()
  const untrusted = setup('wu-test', 'u')
  const nu = notifier(untrusted, ['--attempts', '1'], { NODE_EXTRA_CA_CERTS: '' })
  await waitFor(() => /baselined/.test(nu.out))
  appendFileSync(untrusted.queue, record(1))
  ok('a certificate the notifier does not trust is refused, not posted to', await waitFor(() => /gave up on 01010101/.test(nu.out)) && posts('u').length === 0 &&
    !/-> 20\d/.test(nu.out))
  await nu.stop()

  // Re-notify
  const r = setup('wr-test', 'r')
  const nr = notifier(r, ['--renotify-ms', '300', '--renotify-max', '2'])
  await waitFor(() => /baselined/.test(nr.out))
  appendFileSync(r.queue, record(1))
  ok('an envelope still unread after --renotify-ms is posted again', await waitFor(() => posts('r').length === 2 && /POST 01010101 -> 204 \(re-notify 1\/2\)/.test(nr.out)) &&
    posts('r')[1].t - posts('r')[0].t >= 290 && posts('r')[1].body === posts('r')[0].body)
  ok('re-notify stops at --renotify-max', await waitFor(() => /01010101 still unread after 2 re-notify; stopping/.test(nr.out)) && posts('r').length === 3 &&
    await wait(700).then(() => posts('r').length === 3) && JSON.parse(readText(r.state)).watch.length === 0)
  appendFileSync(r.queue, record(2))
  await waitFor(() => posts('r').length === 4)
  markRead(r, 2)
  ok('an envelope that appears in the read log is not re-notified', await wait(900).then(() => posts('r').length === 4) && JSON.parse(readText(r.state)).watch.length === 0)
  appendFileSync(r.queue, record(3))
  await waitFor(() => /POST 03030303 -> 204/.test(nr.out))
  await nr.stop()
  ok('the re-notify watch survives a restart', JSON.parse(readText(r.state)).watch.map(w => w.envelope).join() === envelope(3))
  const nr2 = notifier(r, ['--renotify-ms', '300', '--renotify-max', '2'])
  ok('and the restarted notifier re-notifies it', await waitFor(() => posts('r').length === 6) && bodies('r')[5].envelope === envelope(3))
  await nr2.stop()
  const z = setup('wz-test', 'z')
  const nz = notifier(z, ['--renotify-ms', '100', '--renotify-max', '0'])
  await waitFor(() => /baselined/.test(nz.out))
  appendFileSync(z.queue, record(1))
  ok('--renotify-max 0 posts each envelope once', await waitFor(() => posts('z').length === 1) && await wait(500).then(() => posts('z').length === 1))
  await nz.stop()

  // Flags, the manifest precondition and the worker user
  const f = setup('wf-test', 'f')
  const refuse = (flags, pattern, env = {}, s = f) => { const run = spawnSync(process.execPath, ['mcp/tools/admitted-webhook-notify.mjs', '--instance', s.id, ...flags],
    { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: s.fleet, NVOY_WAKE_WEBHOOK_URL_FILE: s.urlFile, NVOY_WAKE_WEBHOOK_HEADERS_FILE: s.headersFile, ...env }, timeout: 5000 })
    outputs.push(run.stdout + run.stderr); return run.status === 1 && pattern.test(run.stderr) }
  ok('--renotify-ms and --renotify-max are bounded', refuse(['--renotify-ms', '50'], /--renotify-ms must be 100\.\.86400000/) && refuse(['--renotify-max', '11'], /--renotify-max must be 0\.\.10/) &&
    refuse(['--renotify-max', '-1'], /--renotify-max/))
  ok('attempts, retry and timeout are bounded', refuse(['--attempts', '0'], /--attempts must be 1\.\.20/) && refuse(['--attempts', '21'], /--attempts/) &&
    refuse(['--timeout-ms', '60001'], /--timeout-ms/) && refuse(['--retry-max-ms', '3600001'], /--retry-max-ms/))
  const other = setup('wo-test', 'o', { manifest: { worker_uid: 41024 } })
  ok('the notifier runs only as the manifest-bound worker user', refuse([], /must run as the manifest-bound worker user/, {}, other))
  const none = setup('wn-test', 'n', { manifest: { wake_webhook: undefined } })
  ok('a manifest without a wake_webhook block starts no notifier', refuse([], /no wake_webhook block/, {}, none))

  // Credentials
  const refusedUrl = (text, pattern) => { try { parseWebhookUrl(text); return false } catch (e) { return pattern.test(e.message) && !e.message.includes('example.invalid') && !e.message.includes('SECRET') } }
  ok('a valid https URL is accepted, query included', parseWebhookUrl('https://hooks.example.invalid/wake?token=x\n') === 'https://hooks.example.invalid/wake?token=x')
  ok('a non-https URL is refused', refusedUrl('http://hooks.example.invalid/wake\n', /must use https/) && refusedUrl('ftp://hooks.example.invalid/\n', /must use https/))
  ok('a URL carrying user info or a fragment is refused', refusedUrl('https://u:SECRET@hooks.example.invalid/\n', /user info/) && refusedUrl('https://hooks.example.invalid/#SECRET\n', /fragment/))
  ok('a URL file of more than one line, or with a CR or whitespace, is refused', refusedUrl('https://hooks.example.invalid/a\nhttps://hooks.example.invalid/b\n', /exactly one line/) &&
    refusedUrl('https://hooks.example.invalid/a\r\n', /exactly one line/) && refusedUrl('https://hooks.example.invalid/a b', /whitespace/) && refusedUrl('', /whitespace/) && refusedUrl('not a url', /whitespace|not a valid URL/))
  const refusedHeaders = (text, pattern) => { try { parseWebhookHeaders(text); return false } catch (e) { return pattern.test(e.message) && !/SECRET|X-Bad|Bad Name/.test(e.message) } }
  ok('a curl -H @file headers file is accepted, blank lines ignored', JSON.stringify(parseWebhookHeaders('Authorization: Bearer abc\n\nX-Custom:  v1 \n')) === JSON.stringify([['Authorization', 'Bearer abc'], ['X-Custom', 'v1']]))
  ok('a header name that is not an RFC 7230 token is refused', refusedHeaders('Bad Name: SECRET\n', /not an RFC 7230 token/) && refusedHeaders('X-Bad(: SECRET\n', /RFC 7230/) &&
    refusedHeaders(' X-Bad: SECRET\n', /RFC 7230/) && refusedHeaders('SECRET-no-colon\n', /is not "Name: value"/))
  ok('CR/LF injection is refused', refusedHeaders('X-A: SECRET\r\nHost: evil.example.invalid\r\n', /carriage return/) && refusedHeaders('X-A: SECRET\x00x\n', /printable ASCII/) &&
    refusedHeaders('X-A: SECRET\x0bx\n', /printable ASCII/))
  ok('Host, Content-Length and Content-Type overrides are refused, in any case', ['Host', 'content-length', 'CONTENT-TYPE', 'Transfer-Encoding', 'Connection'].every(name => refusedHeaders(`${name}: SECRET\n`, /sets itself/)))
  ok('an empty headers file, an empty value, a repeated header or too many headers are refused', refusedHeaders('\n\n', /at least one/) && refusedHeaders('X-A:  \n', /non-empty/) &&
    refusedHeaders('X-A: SECRET\nx-a: SECRET2\n', /repeats/) && refusedHeaders(Array.from({ length: 17 }, (_, i) => `X-H${i}: v`).join('\n'), /more than 16/))
  const credDir = mkdtempSync(join(root, 'files-'))
  const credFile = (name, text, mode = 0o600) => { const p = join(credDir, name); writeFileSync(p, text, { mode }); chmodSync(p, mode); return p }
  const refusedFile = (path, pattern, max = 64) => { try { readCredential(path, 'wake webhook headers file', max); return false } catch (e) { return pattern.test(e.message) && !e.message.includes('SECRET') } }
  symlinkSync(credFile('real', 'X-A: SECRET\n'), join(credDir, 'link'))
  ok('a credential file must be an owner-only regular file within its bound', refusedFile(credFile('loose', 'X-A: SECRET\n', 0o640), /owner-only/) &&
    refusedFile(join(credDir, 'link'), /regular non-symlink/) && refusedFile(join(credDir, 'absent'), /missing/) && refusedFile(credFile('big', 'X-A: SECRET' + 'x'.repeat(100)), /exceeds its 64-byte bound/) &&
    readCredential(credFile('fine', 'X-A: v\n'), 'x', MAX_HEADERS_FILE) === 'X-A: v\n')
  const httpUrl = setup('wh-test', 'h', { url: 'http://127.0.0.1:9/h/URLSECRET\n' })
  ok('the notifier refuses a non-https URL at start, without echoing it', refuse([], /must use https/, {}, httpUrl) && !/URLSECRET|127\.0\.0\.1/.test(outputs.at(-1)))
  const hostHeader = setup('wi-test', 'i', { headers: 'Host: HEADERSECRET.example.invalid\n' })
  ok('the notifier refuses a header override at start, without echoing it', refuse([], /sets itself/, {}, hostHeader) && !/HEADERSECRET/.test(outputs.at(-1)))
  const loose = setup('wl-test', 'l')
  chmodSync(loose.headersFile, 0o644)
  ok('the notifier refuses a group- or world-readable credential copy', refuse([], /owner-only/, {}, loose))
  ok('the body builder emits only the four fields', wakeBody('x', { envelope: envelope(1), type: 'admitted-task', at: null, messages: 'SECRET', sender: 'SECRET' }) ===
    JSON.stringify({ instance: 'x', envelope: envelope(1), type: 'admitted-task', at: null }))
  ok('the queue reader keeps only the envelope, type and receipt time of a record', JSON.stringify(admittedMeta(record(1))) ===
    JSON.stringify({ envelope: envelope(1), type: 'admitted-task', at: 1001 }))

  // Log redaction, across every notifier run above
  const all = outputs.join('\n')
  ok('no log line carries the URL, a header value, a response body or message content', outputs.length >= 12 &&
    !/URLSECRET|HEADERSECRET|RESPONSE-SECRET|SECRET-BODY|SECRET-GRANT|SECRET-NOTE|127\.0\.0\.1|hooks\/wake|Bearer/.test(all))
  ok('the envelope never appears in full in a log', ![1, 2, 3, 4, 5, 8, 9, 11].some(n => all.includes(envelope(n))))

  // Manifest
  const parse = manifest => spawnSync(process.execPath, ['--input-type=module', '-e',
    `import { readManifest } from './mcp/tools/runtime_manifest.mjs'; try { console.log(JSON.stringify(readManifest(process.env.R, process.env.I).wakeWebhook)) } catch (e) { console.error(e.message); process.exit(1) }`],
    { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, R: (() => { const d = mkdtempSync(join(root, 'm-')); writeFileSync(join(d, `${manifest.id}.json`), JSON.stringify(manifest)); return d })(), I: manifest.id } })
  const refusedManifest = (wake, pattern, extra = {}) => { const run = parse(base('mv-test', { wake_webhook: wake, ...extra })); return run.status !== 0 && pattern.test(run.stderr) }
  const accepted = parse(base('mv-test'))
  ok('a local-broker, worker-disabled notify_only manifest accepts a wake_webhook', accepted.status === 0 &&
    accepted.stdout.trim() === JSON.stringify({ urlRef: '/etc/nvoy/credentials/mv-test.wake-webhook.url', headersRef: '/etc/nvoy/credentials/mv-test.wake-webhook.headers' }))
  ok('a manifest without the block has none', parse(base('mv-test', { wake_webhook: undefined })).stdout.trim() === 'null')
  ok('both references must be absolute paths under /etc/nvoy/credentials', refusedManifest({ ...wakeWebhook('mv-test'), url_ref: 'mv.url' }, /under \/etc\/nvoy\/credentials/) &&
    refusedManifest({ ...wakeWebhook('mv-test'), headers_ref: '/root/mv.headers' }, /under \/etc\/nvoy\/credentials/) &&
    refusedManifest({ ...wakeWebhook('mv-test'), url_ref: '/etc/nvoy/credentials/../instances/mv.json' }, /under \/etc\/nvoy\/credentials/) &&
    refusedManifest({ url_ref: wakeWebhook('mv-test').url_ref }, /url_ref and headers_ref/) && refusedManifest({}, /url_ref and headers_ref/))
  ok('the two references must be two files', refusedManifest({ url_ref: '/etc/nvoy/credentials/a', headers_ref: '/etc/nvoy/credentials/a' }, /must be two files/))
  ok('neither reference may name a Nostr credential', refusedManifest({ ...wakeWebhook('mv-test'), url_ref: '/etc/nvoy/credentials/mv-test.bunker' }, /must not name a Nostr credential/) &&
    refusedManifest({ ...wakeWebhook('mv-test'), headers_ref: '/etc/nvoy/credentials/mv-test.client' }, /must not name a Nostr credential/))
  ok('neither reference may name the harness login', refusedManifest({ ...wakeWebhook('mv-test'), headers_ref: '/etc/nvoy/credentials/mv.claude' }, /harness credential/,
    { harness: { runner: 'claude', credential_ref: '/etc/nvoy/credentials/mv.claude' } }))
  ok('a wake_webhook is refused beside a headless worker or on a Codex app-server binding', refusedManifest(wakeWebhook('mv-test'), /requires a local-broker, worker-disabled notify_only/,
    { delivery_mode: 'headless', worker_enabled: true, worker_image: 'registry.example/w@sha256:' + 'a'.repeat(64), worker_runner: 'claude', worker_credential_ref: '/etc/nvoy/credentials/mv.provider' }) &&
    refusedManifest(wakeWebhook('mv-test'), /requires a local-broker, worker-disabled notify_only/, { delivery_mode: 'codex_app_server', codex_thread_id: '0199a213-81c0-7800-8aa1-bbab2a035a53' }))

  // Compose
  const image = 'registry.example/nvoy@sha256:' + 'e'.repeat(64), workerImage = 'registry.example/nvoy-worker@sha256:' + 'a'.repeat(64)
  const render = (manifest, args = []) => { const dir = mkdtempSync(join(root, 'r-')); writeFileSync(join(dir, `${manifest.id}.json`), JSON.stringify(manifest))
    return spawnSync(process.execPath, ['mcp/tools/render-instance-compose.mjs', '--instance', manifest.id, '--image', image, ...args], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: dir } }) }
  const rendered = render(base('mv-test', { worker_uid: 41024 }))
  const out = rendered.stdout
  const part = name => (out.match(new RegExp(`\\n  ${name}:[\\s\\S]*?(?=\\n  [a-z][a-z_]*:|\\nsecrets:|$)`)) || [''])[0]
  const notifierPart = part('notifier'), initPart = part('init')
  const runtimeDir = JSON.stringify(join(root, 'rt-mv-test')), stateDir = JSON.stringify(join(root, 'rt-mv-test', 'wake-webhook-state'))
  ok('a wake_webhook manifest renders a notifier service on the runtime image, with no worker image needed', rendered.status === 0 && notifierPart.includes(`image: ${JSON.stringify(image)}`) &&
    notifierPart.includes('command: ["node", "mcp/tools/admitted-webhook-notify.mjs", "--instance", "mv-test"]'))
  ok('the notifier runs as the worker UID with the handoff group, read-only and without capabilities', notifierPart.includes(`user: "41024:${workerHandoffGid}"`) &&
    /read_only: true/.test(notifierPart) && /cap_drop: \[ALL\]/.test(notifierPart) && /no-new-privileges:true/.test(notifierPart))
  ok('it mounts the runtime read-only and writes only its own state volume over <runtime>/wake-webhook-state',
    notifierPart.includes(`source: adapter_runtime\n        target: ${runtimeDir}\n        read_only: true`) &&
    notifierPart.includes(`source: wake_webhook_state\n        target: ${stateDir}\n`) && !notifierPart.includes(`target: ${stateDir}\n        read_only`))
  ok('it gets the webhook credentials read-only, and nothing keyed', /source: wake_webhook_credentials\n\s+target: \/run\/nvoy-wake-webhook-credentials\n\s+read_only: true/.test(notifierPart) &&
    notifierPart.includes('NVOY_WAKE_WEBHOOK_URL_FILE: /run/nvoy-wake-webhook-credentials/url') && notifierPart.includes('NVOY_WAKE_WEBHOOK_HEADERS_FILE: /run/nvoy-wake-webhook-credentials/headers') &&
    !/broker_credentials|harness_credentials|harness_home|bunker|nsec|STATE_DIR|spool|secrets:|network_mode/i.test(notifierPart))
  ok('only the root initializer receives the webhook files, from the manifest references', /nvoy_wake_webhook_url:\n\s+file: "\/etc\/nvoy\/credentials\/mv-test\.wake-webhook\.url"/.test(out) &&
    /nvoy_wake_webhook_headers:\n\s+file: "\/etc\/nvoy\/credentials\/mv-test\.wake-webhook\.headers"/.test(out) &&
    initPart.includes('source: nvoy_wake_webhook_url') && initPart.includes('source: nvoy_wake_webhook_headers') && initPart.includes(`target: ${stateDir}`) &&
    initPart.includes('NVOY_WAKE_WEBHOOK_URL_SOURCE: /run/secrets/wake-webhook-url'))
  ok('the rendered file keeps no template markers or unresolved variables', !/@webhook-|\$\{/.test(out) && /\n  wake_webhook_state: \{\}/.test(out) && /\n  wake_webhook_credentials: \{\}/.test(out))
  const plain = render(base('mv-test', { wake_webhook: undefined }))
  ok('a manifest without the block renders no notifier, webhook volume or webhook secret', plain.status === 0 && !/notifier|wake/i.test(plain.stdout))
  const both = render(base('mv-test', { harness: { runner: 'claude', credential_ref: '/etc/nvoy/credentials/mv.claude' } }), ['--worker-image', workerImage])
  ok('a notifier renders beside a fleet harness without disturbing it', both.status === 0 && /\n  harness:/.test(both.stdout) && /\n  notifier:/.test(both.stdout) && !/@(?:webhook|harness)-|\$\{/.test(both.stdout))
  const init = readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')
  ok('the initializer makes the state volume and both credential copies worker-owned, and refuses stray webhook sources',
    /provision\(`\$\{m\.runtimeDir\}\/wake-webhook-state`, m\.workerUid, m\.workerUid, 0o700/.test(init) &&
    /provisionSecret\(sources\.wakeWebhookUrl, `\$\{webhookCredDir\}\/url`, m\.workerUid, m\.workerUid/.test(init) &&
    /provisionSecret\(sources\.wakeWebhookHeaders, `\$\{webhookCredDir\}\/headers`, m\.workerUid, m\.workerUid/.test(init) &&
    /a runtime without a wake webhook refuses webhook credential sources/.test(init))

  // Reconciler: the real verify_running, against a fake docker that reports which services run
  const deployRoot = mkdtempSync(join(root, 'deploy-'))
  const fakeDocker = join(deployRoot, 'docker')
  writeFileSync(fakeDocker, `#!/bin/sh\nif [ "$4" = ps ] && [ "$5" = --status ]; then printf '%s\\n' $FAKE_SERVICES; exit 0; fi\nif [ "$4" = ps ]; then printf '{"State":"exited","ExitCode":0}\\n'; exit 0; fi\nexit 2\n`, { mode: 0o700 })
  const verify = (manifest, services) => {
    const dir = mkdtempSync(join(deployRoot, 'i-')); writeFileSync(join(dir, `${manifest.id}.json`), JSON.stringify(manifest))
    const run = spawnSync('python3', ['-c', `import importlib.util, pathlib
spec = importlib.util.spec_from_file_location('runner', 'deploy/runtime-deploy-runner.py'); runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
try:
    [runner.verify_running(pathlib.Path('x.yml'), i) for i in runner.instances()]; print('running')
except Exception as e: print(e)`], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: dir, NVOY_DOCKER: fakeDocker, FAKE_SERVICES: services } })
    return run.stdout.trim() || run.stderr.trim()
  }
  ok('the reconciler expects a notifier when the manifest has a wake_webhook', verify(base('dv-test'), 'watcher broker adapter') === 'dv-test: services not running: notifier' &&
    verify(base('dv-test'), 'watcher broker adapter notifier') === 'running')
  ok('and expects none without one', verify(base('dv-test', { wake_webhook: undefined }), 'watcher broker adapter') === 'running')
} finally {
  server.close()
}
console.log(fails ? `\n${fails} failed` : '\nall passed')
process.exit(fails ? 1 : 0)
