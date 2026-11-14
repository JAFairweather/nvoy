#!/usr/bin/env node
// A real per-connection Bunker round trip for the operations monitor. Run inside
// the broker container, where its existing transport credential is mounted.
import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { makeBunkerSigner } from './nip46-signer.mjs'

function credential(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile() || stat.size === 0 || stat.size > 4096 || (stat.mode & 0o077)) throw new Error('unsafe credential')
    return readFileSync(fd, 'utf8').trim()
  } finally { closeSync(fd) }
}

export async function check({ env = process.env, open = makeBunkerSigner, now = Date.now } = {}) {
  let signer
  try {
    if (!env.NVOY_BUNKER_URI_FILE || !env.NVOY_BROKER_CREDENTIAL) throw new Error('credential unavailable')
    const uri = credential(env.NVOY_BUNKER_URI_FILE)
    const client = credential(env.NVOY_BROKER_CREDENTIAL)
    signer = open(uri, client)
    const start = now()
    await signer.ping()
    return { verdict: 'ok', latency_ms: Math.max(0, now() - start) }
  } catch (error) {
    const message = String(error?.message || '')
    const verdict = /timed out/.test(message) ? 'timeout'
      : /invalid response/.test(message) ? 'invalid_response' : 'unavailable'
    return { verdict }
  } finally {
    try { signer?.close() } catch { /* cleanup only */ }
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const result = await check()
  process.stdout.write(`${JSON.stringify(result)}\n`)
  if (result.verdict !== 'ok') process.exitCode = 1
}
