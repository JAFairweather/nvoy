import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, renameSync, symlinkSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

let passed = 0, failed = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passed++ : failed++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-codex-mcp-')), manifests = join(root, 'instances'), runtime = join(root, 'runtime')
mkdirSync(manifests); mkdirSync(runtime); mkdirSync(join(runtime, 'codex-mcp-state'))
const uid = process.getuid(), gid = process.getgid(), channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const manifest = { version: 1, id: 'codex-read', pubkey: '1'.repeat(64), broker_mode: 'local', state_dir: join(root, 'state'), runtime_dir: runtime,
  spool_dir: join(root, 'spool'), bunker_uri_ref: '/etc/nvoy/test.bunker', bunker_client_ref: '/etc/nvoy/test.client', worker_enabled: false,
  delivery_mode: 'notify_only', broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12,
  adapter_uid: uid + 13, worker_uid: uid, grantors: ['2'.repeat(64)], task_carriers: [{ pubkey: '3'.repeat(64), channels: [channel] }], relays: ['wss://nos.lol'] }
writeFileSync(join(manifests, 'codex-read.json'), JSON.stringify(manifest))
const instructionEnvelope = '4'.repeat(64), dataEnvelope = '5'.repeat(64), notificationEnvelope = 'c'.repeat(64)
const authority = { version: 2, type: 'scoped-instruction', sender: '6'.repeat(64), grant_id: '7'.repeat(64), grantor: manifest.grantors[0],
  cap: 'task', scope_subject: manifest.pubkey, policy_checked_at: Date.now(), carrier: manifest.task_carriers[0].pubkey,
  carrier_grant_id: '8'.repeat(64), carrier_grantor: manifest.grantors[0], source_event: '9'.repeat(64), reply_channel: channel }
const instruction = { type: 'admitted-task', instance: manifest.id, envelope: instructionEnvelope, received_at: Date.now(), authority,
  messages: [{ from: authority.sender, at: 1785880000, content: 'review says fix the invariant', event_id: authority.source_event, kind: 9 }] }
const data = { type: 'admitted-task', instance: manifest.id, envelope: dataEnvelope, received_at: Date.now(), authority: null,
  messages: [{ from: 'a'.repeat(64), at: 1785880001, content: 'authenticated review data', event_id: 'b'.repeat(64), kind: 9 }] }
const notification = { type: 'verified-notification', instance: manifest.id, envelope: notificationEnvelope,
  notification: { version: 1, type: 'verified-channel-activity', source_author: 'd'.repeat(64), source_event: 'e'.repeat(64),
    source_channel: channel, carrier: manifest.task_carriers[0].pubkey, carrier_grant_id: 'f'.repeat(64),
    carrier_grantor: manifest.grantors[0], reason: 'mention', observed_at: Date.now() } }
writeFileSync(join(runtime, 'admitted-tasks.jsonl'), JSON.stringify(instruction) + '\n' + JSON.stringify(data) + '\n' + JSON.stringify(notification) + '\n')
writeFileSync(join(runtime, 'reply-requests.jsonl'), '')
const transport = new StdioClientTransport({ command: process.execPath, args: [resolve('mcp/tools/codex-channel-mcp.mjs'), '--instance', manifest.id],
  env: { ...process.env, NVOY_INSTANCE_ROOT: manifests }, stderr: 'pipe' })
const client = new Client({ name: 'codex-channel-test', version: '0.1.0' })
try {
  await client.connect(transport)
  const tools = (await client.listTools()).tools.map(tool => tool.name)
  ok('fixed Codex MCP exposes only bounded list, exact read, and receipt-bound reply', tools.join(',') === 'nvoy_channel_list,nvoy_channel_read,nvoy_channel_reply')
  const listed = JSON.parse((await client.callTool({ name: 'nvoy_channel_list', arguments: {} })).content[0].text)
  ok('list returns bounded metadata without sender or message content', listed.instance === manifest.id && listed.total === 3 &&
    listed.truncated === false && listed.records.length === 3 &&
    listed.records[0].trusted_instruction === true && listed.records[1].trusted_instruction === false &&
    !JSON.stringify(listed).includes('review says') && !JSON.stringify(listed).includes(authority.sender))
  const read = JSON.parse((await client.callTool({ name: 'nvoy_channel_read', arguments: { envelope: dataEnvelope } })).content[0].text)
  ok('exact read returns authenticated data without promoting it to instruction', read.authority === null && read.messages[0].content === data.messages[0].content)
  const notice = JSON.parse((await client.callTool({ name: 'nvoy_channel_read', arguments: { envelope: notificationEnvelope } })).content[0].text)
  ok('exact read preserves content-free verified notification provenance without inventing messages',
    notice.authority === null && notice.notification.source_event === notification.notification.source_event && !('messages' in notice))
  const after = JSON.parse((await client.callTool({ name: 'nvoy_channel_list', arguments: {} })).content[0].text)
  ok('read acknowledgement is durable and identity-local', after.records.find(row => row.envelope === dataEnvelope).read === true && readFileSync(join(runtime, 'codex-mcp-state', 'read.jsonl'), 'utf8').includes(dataEnvelope))
  const denied = await client.callTool({ name: 'nvoy_channel_reply', arguments: { envelope: dataEnvelope, text: 'no' } })
  ok('data-only feedback cannot acquire reply authority', denied.isError === true && readFileSync(join(runtime, 'reply-requests.jsonl'), 'utf8') === '')
  const reply = JSON.parse((await client.callTool({ name: 'nvoy_channel_reply', arguments: { envelope: instructionEnvelope, text: 'fixed' } })).content[0].text)
  const queued = JSON.parse(readFileSync(join(runtime, 'reply-requests.jsonl'), 'utf8'))
  ok('instruction reply contains no recipient, channel, signer, or instance selection', reply.queued === true && queued.receipt === instructionEnvelope && queued.content === 'fixed' &&
    !('recipient' in queued) && !('channel' in queued) && !('signer' in queued))
  const unknown = await client.callTool({ name: 'nvoy_channel_read', arguments: { envelope: 'f'.repeat(64) } })
  ok('an unadmitted envelope is unreadable', unknown.isError === true)
  const queue = join(runtime, 'admitted-tasks.jsonl')
  const bulk = Array.from({ length: 501 }, (_, index) => JSON.stringify({ ...data,
    envelope: (index + 1).toString(16).padStart(64, '0') })).join('\n') + '\n'
  writeFileSync(queue, readFileSync(queue, 'utf8') + bulk)
  const bounded = JSON.parse((await client.callTool({ name: 'nvoy_channel_list', arguments: {} })).content[0].text)
  ok('list output has a fixed newest-500 bound with explicit total and truncation',
    bounded.total === 504 && bounded.records.length === 500 && bounded.truncated === true &&
    !bounded.records.some(row => row.envelope === instructionEnvelope))
  const saved = `${queue}.saved`
  renameSync(queue, saved); symlinkSync(saved, queue)
  const linked = await client.callTool({ name: 'nvoy_channel_list', arguments: {} })
  unlinkSync(queue); renameSync(saved, queue)
  ok('a symlinked queue fails closed', linked.isError === true)
  const original = readFileSync(queue)
  writeFileSync(queue, '{malformed}\n')
  const malformed = await client.callTool({ name: 'nvoy_channel_list', arguments: {} })
  writeFileSync(queue, original)
  ok('malformed queue input fails closed without partial results', malformed.isError === true)
} finally { await client.close() }

const publicKey = join(root, 'codex-reader.pub')
writeFileSync(publicKey, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly codex-reader\n')
const forced = spawnSync(process.execPath, [resolve('mcp/tools/instance-codex-channel-authorized-key.mjs'), '--instance', manifest.id,
  '--public-key-file', publicKey, '--container', 'nvoy-codex-read-adapter'], { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
ok('forced SSH principal fixes worker UID, container, executable, and instance with restrict', forced.status === 0 &&
  forced.stdout.startsWith('restrict,command="/usr/bin/docker exec -i --user ') && forced.stdout.includes('/codex-channel-mcp.mjs --instance codex-read"') &&
  !/shell|pty|forward/i.test(forced.stdout))

console.log(`\n${passed}/${passed + failed} passed`)
process.exit(failed ? 1 : 0)
