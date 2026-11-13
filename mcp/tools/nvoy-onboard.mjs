#!/usr/bin/env node
// nvoy-onboard.mjs — add an agent from one owner-signed setup request: phase A (#289) and B (#323).
//
//   nvoy-onboard.mjs show <name> [--instance-root <dir>] [--relay wss://…]…
//   nvoy-onboard.mjs run <name> [--authorized-keys <path>] [--givers-redeploy] [--out <dir>]
//                            [--instance-root <dir>] [--state-dir <dir>] [--relay wss://…]… [--writer-relay wss://…]
//   nvoy-onboard.mjs watch [--runner <runner.json>] [--out <dir>] [--instance-root <dir>] [--state-dir <dir>]
//   nvoy-onboard.mjs runner-pair [--runner <runner.json>]
//
// watch is one tick of phase B (docs/ONBOARD_PHASE_B.md): every unfinished request, oldest first,
// with the pairing link and each step's state sealed to the owner in a receipt the runner key signs.
// runner-pair pairs that key once, the way instance-pair pairs an agent.
//
// show fetches and verifies the newest request and prints the plan; it writes nothing. run carries
// out the steps in onboard_run.mjs, one receipt each, and can be run again to carry on. The request
// is read from the grant relays and every installed agent's relays; only its owner's signature counts.
//
// Exit: 0 every step done · 1 refused · 2 usage · 4 waiting on a step (a pending receipt says which).

import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { verifyEvent, nip19 } from 'nostr-tools'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grantReadRelays } from './grant_relays.mjs'
import { publishRelay, queryRelay } from './public_relays.mjs'
import { MAX_AGE_S, requestD, SETUP_KIND, OnboardRefusal } from './onboard_request.mjs'
import { onboard, WRITERS_D, WRITERS_KIND } from './onboard_run.mjs'
import { readInstallDetails, readRunnerConfig, WRITER_RELAY } from './onboard_receipt.mjs'
import { readPages, watchTick } from './onboard_watch.mjs'
import { readOnboardGrants } from './onboard_delegate.mjs'
import { scopeHash } from './grant_fold.mjs'
import { pairInstance } from './instance-pair.mjs'
import { readManifest } from './runtime_manifest.mjs'
import { makeBunkerSigner } from './nip46-signer.mjs'
import { openBuzzSession } from './buzz_native.mjs'

const argv = process.argv.slice(2)
const flag = name => { const index = argv.indexOf(name); return index < 0 ? '' : argv[index + 1] || '' }
const all = name => argv.reduce((acc, arg, index) => (arg === name && argv[index + 1] ? [...acc, argv[index + 1]] : acc), [])
const [command, name] = argv
const named = ['show', 'run'].includes(command)
if (!(named || ['watch', 'runner-pair'].includes(command)) || (named && (!name || name.startsWith('--')))) {
  console.error('usage: nvoy-onboard.mjs show|run <name> [--authorized-keys <path>] [--givers-redeploy] [--out <dir>] [--instance-root <dir>] [--state-dir <dir>] [--relay wss://…]…')
  console.error('       nvoy-onboard.mjs watch|runner-pair [--runner <runner.json>] [--out <dir>] [--instance-root <dir>] [--state-dir <dir>]')
  process.exit(2)
}
const here = dirname(fileURLToPath(import.meta.url))

const readUrls = relays => grantReadRelays([...relays, ...all('--relay')], process.env.NVOY_GRANT_RELAYS || '')
async function readAll(urls, filter, read = queryRelay) {
  const reads = await Promise.all(urls.map(url => read(url, filter)))
  if (!reads.some(read => read.answered)) throw new OnboardRefusal('ONBOARD_NO_RELAY', 'no relay answered')
  return [...new Map(reads.flatMap(read => read.events).map(event => [event.id, event])).values()]
}
const fetchEvents = ({ relays, owners, name, delegates = [] }) =>
  readAll(readUrls(relays), { kinds: [SETUP_KIND], authors: [...new Set([...owners, ...delegates])], '#d': [requestD(name, 'add_agent'), requestD(name, 'bind_runtime')] })
// Every request kind from the trusted owners, paged back over the window a request stays valid, so
// newer owner events never push an unfinished add out of a fixed window; watch keeps the add_agent
// ones by their d tag.
const fetchAll = async ({ relays, owners, delegates = [] }) => {
  const incomplete = []
  const events = await readAll(readUrls(relays),
    { kinds: [SETUP_KIND], authors: [...new Set([...owners, ...delegates])], since: Math.floor(Date.now() / 1000) - MAX_AGE_S - 600 },
    async (url, filter) => { const read = await readPages(queryRelay, url, filter); if (read.answered && !read.complete) incomplete.push(url); return read })
  return { events, incomplete }
}
const verify = event => { try { return verifyEvent(JSON.parse(JSON.stringify(event))) } catch { return false } }
// The owners' live `onboard` grants (DESIGN_ONBOARDING_DELEGATE), paged in full from every grant relay,
// fail closed: fewer than a quorum of complete reads is "unknown", and unknown reads no delegate.
const readDelegates = ({ relays, owners }) => readOnboardGrants({ urls: readUrls(relays), grantors: owners, verify, scopeHash,
  read: (url, filter) => readPages(queryRelay, url, filter) })
// The owner's newest writer lists on the server's relay, for the relay writer step in run and watch.
const writersFrom = relay => async ({ owners }) => queryRelay(relay, { kinds: [WRITERS_KIND], authors: owners, '#d': [WRITERS_D] })

// The agent's own connection, from its seated credential files, for the hive claim and room joins.
function joinWith(manifest) {
  const signer = makeBunkerSigner(readFileSync(manifest.bunkerUriRef, 'utf8').trim(), readFileSync(manifest.bunkerClientRef, 'utf8').trim(), { idleMs: 30000 })
  return { signer, fetchImpl: globalThis.fetch, open: () => openBuzzSession({ relay: manifest.buzz.relay, signer }), close: () => signer.close?.() }
}

const runTool = (tool, args) => spawnSync(process.execPath, [join(here, tool), ...args], { stdio: 'inherit' }).status ?? 1
const PAIR_TIMEOUT_S = 300
const root = resolve(flag('--instance-root') || process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances')
const out = resolve(flag('--out') || join(process.env.HOME || '/root', '.nvoy', 'staged'))
const stateDir = resolve(flag('--state-dir') || '/var/lib/nvoy-onboard')
const asRoot = () => { if (process.getuid?.() !== 0) throw new Error('run as root: the credential files must be root-owned') }
const runnerSigner = runner => makeBunkerSigner(readFileSync(runner.bunkerUriRef, 'utf8').trim(), readFileSync(runner.bunkerClientRef, 'utf8').trim(), { idleMs: 30000 })

// Pairs the runner key once. Its link is printed for the operator to hand to the owner, as for an agent.
async function runnerPair(runner) {
  asRoot()
  const { nostrConnectSigner } = await import('../../lib/nave-connect.mjs')
  const paired = await pairInstance(runner, { pair: nostrConnectSigner, relays: runner.relays, perms: runner.perms, timeoutMs: PAIR_TIMEOUT_S * 1000,
    onUri: uri => console.log(`\nOpen this link in your Bunker and approve it with the nvoy-onboard key (${nip19.npubEncode(runner.pubkey)}).\nIt works once, and this tool waits ${PAIR_TIMEOUT_S} s for it:\n\n${uri}\n`) })
  console.log(`paired: the runner signs as ${paired.npub}; a probe it signed verified.`)
  for (const path of paired.written) console.log(`seated: ${path} (root 0600)`)
}

async function watch(runner) {
  asRoot()
  const signer = runnerSigner(runner)
  try {
    const { nostrConnectSigner } = await import('../../lib/nave-connect.mjs')
    // In-process, so the link reaches only the sealed receipt; it is never printed or logged.
    const pair = async ({ name, out: dir, onUri }) => {
      try {
        const paired = await pairInstance(readManifest(dir, name), { pair: nostrConnectSigner, timeoutMs: PAIR_TIMEOUT_S * 1000,
          onUri: uri => onUri(uri, Math.floor(Date.now() / 1000) + PAIR_TIMEOUT_S) })
        console.log(`paired: ${name} signs as ${paired.npub}`)
        return 0
      } catch (error) { console.error(`pairing ${name}: ${error.message}`); return 1 }
    }
    const publish = async event => {
      const urls = [...new Set([...runner.relays, ...readUrls([])])]
      return Promise.all(urls.map(url => publishRelay(url, event)))
    }
    const tick = await watchTick({ root, out, stateDir, runner, fetchAll, fetchEvents, runTool, joinWith, pair, readWriters: writersFrom(runner.writerRelay), readDelegates,
      publish, signer, verify,
      installFor: name => readInstallDetails({ instance: name, sshTarget: runner.sshTarget }) })
    const { ran, incomplete } = tick
    return ran.some(entry => entry.error) || incomplete.length ? 1 : 0
  } finally { signer.close?.() }
}

if (!named) {
  try {
    const runner = readRunnerConfig(flag('--runner') || undefined)
    process.exit(command === 'watch' ? await watch(runner) : (await runnerPair(runner), 0))
  } catch (error) {
    console.error(`nvoy-onboard ${command}: ${error.message}`)
    process.exit(1)
  }
}

try {
  const { receipts } = await onboard({ command, name, fetchEvents, runTool, joinWith, verify, readDelegates, readWriters: writersFrom(flag('--writer-relay') || WRITER_RELAY),
    root, out, stateDir, keysPath: flag('--authorized-keys'), giversRedeploy: argv.includes('--givers-redeploy') })
  process.exit(receipts.some(row => row.state === 'refused') ? 1 : receipts.every(row => row.state === 'done') ? 0 : command === 'show' ? 0 : 4)
} catch (error) {
  console.error(`nvoy-onboard: ${error.code ? `${error.code}: ` : ''}${error.message}`)
  process.exit(1)
}
