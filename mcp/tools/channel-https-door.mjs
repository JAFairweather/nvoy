#!/usr/bin/env node
// channel-https-door.mjs — the channel MCP over HTTPS, for a harness host that cannot reach SSH.
//
// A remote harness normally reaches its channel through a forced-command SSH principal
// (participant_unit.principalLine). Some harness hosts cannot open port 22 at all: Grok Bot cloud
// computers have passed only HTTPS since an egress change in October 2026, with every hostname
// resolving to a synthetic proxy address. This door is the same channel on a different wire.
//
// It adds transport and nothing else. Each authenticated Streamable HTTP session becomes exactly
// channelArgv(manifest) — the process the SSH principal `docker exec`s into the adapter — and
// JSON-RPC is relayed between the two unchanged. The caller supplies no argument, chooses no
// instance and no command, and never reaches a shell. The door runs as the `door` service of the
// participant stack, with the same image, workerUid:workerHandoffGid and mounts as that exec'd
// process, and refuses to start as anyone else. So the door cannot widen what the channel may do,
// only who can dial it — and a compromise of the door itself yields what a valid token already does.
//
// Who can dial it is one bearer token. Only its SHA-256 reaches the stack (manifest
// channel_door.token_hash_ref, copied worker-owned by init); the token itself is minted once into a
// 0600 file for the operator to hand to the harness. 256 random bits make guessing moot; the
// failure bucket below only bounds log noise and work done for strangers. It never throttles the
// right token, so strangers cannot lock the harness out.
//
//   channel-https-door.mjs mint  --instance <id> --token-out <path> [--token-hash-file <path>]
//   channel-https-door.mjs serve --instance <id> --listen <host:port | unix:/path> --token-hash-file <path>
//                                [--allowed-host <h>]...
//
// Served path: /door/<id>/mcp. TLS terminates at the reverse proxy in front of it.

import { createServer } from 'node:http'
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { chmodSync, lstatSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { channelArgv } from './participant_unit.mjs'

const MAX_BODY = 1024 * 1024
const HEX64 = /^[0-9a-f]{64}$/

export const tokenDigest = token => createHash('sha256').update(String(token)).digest()

// A door is an http.Server that is not yet listening. Everything it may spawn is fixed here, by
// the caller, before the first request: `argv` is never derived from anything a request carries.
export function createDoor({ id, tokenHash, argv, env = { PATH: '/usr/bin:/bin' }, allowedHosts = [],
  maxSessions = 1, idleMs = 30 * 60 * 1000, failLimit = 20, log = console.log }) {
  if (!HEX64.test(String(tokenHash))) throw new Error('door token hash must be 64 hex')
  if (!Array.isArray(argv) || !argv.length || argv.some(a => typeof a !== 'string')) throw new Error('door argv must be a string array')
  const expected = Buffer.from(tokenHash, 'hex')
  const path = `/door/${id}/mcp`
  const sessions = new Map()
  let failures = 0, failWindow = 0

  const authorized = req => {
    const m = /^Bearer ([^\s]+)$/.exec(String(req.headers.authorization || ''))
    return Boolean(m) && timingSafeEqual(tokenDigest(m[1]), expected)
  }
  const refuse = (res, code, text, headers = {}) => { res.writeHead(code, { 'content-type': 'text/plain', ...headers }).end(text) }

  // Resolves once the channel process has exited, so a caller can wait for its lock to be free.
  // Every close in flight is tracked, whatever started it: a client that DELETEs and at once
  // re-initializes must not spawn a channel while its predecessor still holds the lock.
  const closing = new Set()
  const closeSession = async (sid, why) => {
    const s = sessions.get(sid)
    if (!s) return
    sessions.delete(sid)
    clearTimeout(s.idle)
    log(`channel-https-door: ${id} session ${sid.slice(0, 8)} closed (${why})`)
    s.transport.close().catch(() => {})
    const exited = s.child.close().catch(() => {})
    closing.add(exited)
    await exited
    closing.delete(exited)
  }
  const touch = (sid) => {
    const s = sessions.get(sid)
    if (!s) return
    clearTimeout(s.idle)
    s.idle = setTimeout(() => closeSession(sid, 'idle'), idleMs)
    s.idle.unref?.()
  }

  const readBody = req => new Promise((resolveBody, reject) => {
    const chunks = []; let size = 0
    req.on('data', c => {
      size += c.length
      if (size > MAX_BODY) { reject(Object.assign(new Error('body too large'), { status: 413 })); req.destroy(); return }
      chunks.push(c)
    })
    req.on('end', () => {
      try { resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8'))) }
      catch { reject(Object.assign(new Error('body is not JSON'), { status: 400 })) }
    })
    req.on('error', reject)
  })

  async function openSession(req, res, body) {
    const isInit = (Array.isArray(body) ? body : [body]).some(m => m?.method === 'initialize')
    if (!isInit) return refuse(res, 400, 'missing or unknown mcp-session-id')
    // The channel holds a per-identity lock, so a second one exits at once while the first lives.
    // A client that reconnects without a DELETE must not be locked out until the idle timeout:
    // the newest session wins, and its channel starts only after the evicted one has exited.
    while (sessions.size >= maxSessions) await closeSession(sessions.keys().next().value, 'evicted by a newer session')
    await Promise.all([...closing])
    const child = new StdioClientTransport({ command: argv[0], args: argv.slice(1), env, stderr: 'inherit' })
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableDnsRebindingProtection: allowedHosts.length > 0,
      allowedHosts,
      onsessioninitialized: sid => {
        sessions.set(sid, { transport, child, idle: null })
        touch(sid)
        log(`channel-https-door: ${id} session ${sid.slice(0, 8)} opened`)
      },
      onsessionclosed: sid => closeSession(sid, 'client deleted it'),
    })
    // Relay both ways, unchanged. A response is routed back to its POST by JSON-RPC id; a
    // notification with no originating request goes to the session's standalone SSE stream.
    transport.onmessage = m => { child.send(m).catch(e => log(`channel-https-door: ${id} relay to channel failed: ${e.message}`)) }
    child.onmessage = m => { transport.send(m).catch(e => log(`channel-https-door: ${id} relay to client failed: ${e.message}`)) }
    child.onclose = () => { if (transport.sessionId) closeSession(transport.sessionId, 'channel exited') }
    child.onerror = e => log(`channel-https-door: ${id} channel error: ${e.message}`)
    transport.onclose = () => { if (transport.sessionId) closeSession(transport.sessionId, 'transport closed'); else child.close().catch(() => {}) }
    await child.start()
    await transport.start()
    await transport.handleRequest(req, res, body)
    if (!transport.sessionId) child.close().catch(() => {})
  }

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://door.invalid')
      if (url.pathname !== path) return refuse(res, 404, 'not found')
      if (!authorized(req)) {
        const now = Date.now()
        if (now - failWindow > 60_000) { failWindow = now; failures = 0 }
        if (++failures > failLimit) return refuse(res, 429, 'too many failed attempts', { 'retry-after': '60' })
        if (failures === failLimit) log(`channel-https-door: ${id} ${failLimit} failed authorizations this minute — answering 429 for the rest of it`)
        return refuse(res, 401, 'unauthorized', { 'www-authenticate': 'Bearer' })
      }
      const sid = req.headers['mcp-session-id']
      const existing = typeof sid === 'string' ? sessions.get(sid) : undefined
      if (req.method === 'POST') {
        // A declared oversize body is refused before a byte of it is read; an undeclared one is cut
        // off mid-stream by readBody.
        if (Number(req.headers['content-length']) > MAX_BODY) return refuse(res, 413, 'body too large', { connection: 'close' })
        const body = await readBody(req)
        if (existing) { touch(sid); return existing.transport.handleRequest(req, res, body) }
        return openSession(req, res, body)
      }
      // Streamable HTTP: a server with no sessionless GET stream answers 405, and 404 only for a
      // session it does not know — which a client reads as "re-initialize". A connector that probes
      // with a bare GET and is told 404 gives up instead. Refusals are logged: they are the only
      // trace a remote connector leaves.
      if (typeof sid !== 'string') {
        log(`channel-https-door: ${id} ${req.method} without a session refused 405`)
        return refuse(res, 405, 'method not allowed without mcp-session-id', { allow: 'POST' })
      }
      if (!existing) {
        log(`channel-https-door: ${id} ${req.method} for unknown session ${sid.slice(0, 8)} refused 404`)
        return refuse(res, 404, 'unknown mcp-session-id')
      }
      touch(sid)
      await existing.transport.handleRequest(req, res)
      if (req.method === 'DELETE') closeSession(sid, 'client deleted it')
    } catch (e) {
      if (!res.headersSent) refuse(res, e.status || 500, e.status ? e.message : 'internal error')
      if (!e.status) log(`channel-https-door: ${id} request failed: ${e.message}`)
    }
  })
}

// ---- CLI --------------------------------------------------------------------------------------
const die = message => { console.error(`channel-https-door: ${message}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const flags = n => process.argv.flatMap((a, i) => a === n && process.argv[i + 1] ? [process.argv[i + 1]] : [])

function loadManifest(id) {
  const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
  let manifest
  try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
  // The same precondition the SSH principal generator enforces: the door opens only the
  // keyless, notify-only channel, never a worker or a broker. The manifest also re-checks it.
  if (manifest.brokerMode !== 'local' || manifest.deliveryMode !== 'notify_only' || manifest.workerEnabled) {
    die('the channel door requires a local-broker, worker-disabled notify_only instance')
  }
  if (!manifest.channelDoor) die(`${manifest.id} has no channel_door in its manifest`)
  return manifest
}


async function main() {
  const cmd = process.argv[2]
  const id = flag('--instance')
  if (!['mint', 'serve'].includes(cmd) || !id) die('usage: mint --instance <id> --token-out <path> | serve --instance <id> --listen <host:port|unix:/path> [--allowed-host <h>]...')
  const manifest = loadManifest(id)
  const hashPath = flag('--token-hash-file') || manifest.channelDoor.tokenHashRef

  if (cmd === 'mint') {
    const out = flag('--token-out') || die('mint needs --token-out <path> (a new file; it is never overwritten)')
    const token = randomBytes(32).toString('hex')
    // The token file is created exclusively and 0600 before the hash is installed, so a failed
    // mint never leaves a hash on the host with no token anywhere to match it.
    try { writeFileSync(out, `${token}\n`, { flag: 'wx', mode: 0o600 }) } catch (e) { die(`cannot create ${out}: ${e.message}`) }
    const tmp = `${hashPath}.tmp-${process.pid}`
    try { writeFileSync(tmp, `${tokenDigest(token).toString('hex')}\n`, { flag: 'wx', mode: 0o640 }); chmodSync(tmp, 0o640); renameSync(tmp, hashPath) }
    catch (e) { try { unlinkSync(tmp) } catch { /* nothing to clean */ } die(`cannot install ${hashPath}: ${e.message}`) }
    console.log(`channel-https-door: minted a door token for ${manifest.id}`)
    console.log(`  token (give to the harness, then delete): ${out}`)
    console.log(`  hash (stays on this host):               ${hashPath}`)
    console.log(`  minting again replaces the hash, so the old token stops working at the next serve restart`)
    return
  }

  let tokenHash
  try {
    const st = lstatSync(hashPath)
    if (!st.isFile() || st.isSymbolicLink()) die(`${hashPath} must be a regular non-symlink file`)
    tokenHash = readFileSync(hashPath, 'utf8').trim()
  } catch (e) { if (e.code) die(`no door token hash at ${hashPath} — run mint first`); throw e }
  if (!HEX64.test(tokenHash)) die(`${hashPath} does not hold a 64-hex SHA-256`)

  const listen = flag('--listen') || die('serve needs --listen <host:port> or unix:/path')
  // The spawned channel inherits this process's uid:gid, so this is the check that it runs as the
  // worker and not as whoever started the door.
  if (process.getuid() !== manifest.workerUid || process.getgid() !== manifest.workerHandoffGid) {
    die(`the door must run as the manifest worker ${manifest.workerUid}:${manifest.workerHandoffGid}, not ${process.getuid()}:${process.getgid()}`)
  }
  const env = { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', NVOY_INSTANCE_ROOT: process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances' }
  const door = createDoor({ id: manifest.id, tokenHash, argv: channelArgv(manifest), env, allowedHosts: flags('--allowed-host') })
  const where = listen.startsWith('unix:') ? { path: listen.slice(5) } : (() => {
    const m = /^(.+):(\d+)$/.exec(listen) || die('--listen must be host:port or unix:/path')
    return { host: m[1], port: Number(m[2]) }
  })()
  if (where.path) { try { unlinkSync(where.path) } catch { /* no stale socket */ } }
  await new Promise((ok, fail) => { door.once('error', fail); door.listen(where, ok) })
  if (where.path) chmodSync(where.path, 0o660)
  console.log(`channel-https-door: serving /door/${manifest.id}/mcp on ${listen}`)
  const stop = () => door.close(() => process.exit(0))
  process.on('SIGTERM', stop)
  process.on('SIGINT', stop)
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) main().catch(e => die(e.message))
