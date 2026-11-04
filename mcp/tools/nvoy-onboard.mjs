#!/usr/bin/env node
// nvoy-onboard.mjs — add an agent from one owner-signed setup request, phase A (#289).
//
//   nvoy-onboard.mjs show <name> [--instance-root <dir>] [--relay wss://…]…
//   nvoy-onboard.mjs run <name> [--authorized-keys <path>] [--givers-redeploy] [--out <dir>]
//                            [--instance-root <dir>] [--state-dir <dir>] [--relay wss://…]…
//
// show fetches and verifies the newest request and prints the plan; it writes nothing. run carries
// out the steps in onboard_run.mjs, one receipt each, and can be run again to carry on. The request
// is read from the grant relays and every installed agent's relays; only its owner's signature counts.
//
// Exit: 0 every step done · 1 refused · 2 usage · 4 waiting on a step (a pending receipt says which).

import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grantReadRelays } from './grant_relays.mjs'
import { queryRelay } from './public_relays.mjs'
import { requestD, SETUP_KIND, OnboardRefusal } from './onboard_request.mjs'
import { onboard } from './onboard_run.mjs'
import { makeBunkerSigner } from './nip46-signer.mjs'
import { openBuzzSession } from './buzz_native.mjs'

const argv = process.argv.slice(2)
const flag = name => { const index = argv.indexOf(name); return index < 0 ? '' : argv[index + 1] || '' }
const all = name => argv.reduce((acc, arg, index) => (arg === name && argv[index + 1] ? [...acc, argv[index + 1]] : acc), [])
const [command, name] = argv
if (!['show', 'run'].includes(command) || !name || name.startsWith('--')) {
  console.error('usage: nvoy-onboard.mjs show|run <name> [--authorized-keys <path>] [--givers-redeploy] [--out <dir>] [--instance-root <dir>] [--state-dir <dir>] [--relay wss://…]…')
  process.exit(2)
}
const here = dirname(fileURLToPath(import.meta.url))

async function fetchEvents({ relays, owners, name }) {
  const filter = { kinds: [SETUP_KIND], authors: owners, '#d': [requestD(name, 'add_agent'), requestD(name, 'bind_runtime')] }
  const urls = grantReadRelays([...relays, ...all('--relay')], process.env.NVOY_GRANT_RELAYS || '')
  const reads = await Promise.all(urls.map(url => queryRelay(url, filter)))
  if (!reads.some(read => read.answered)) throw new OnboardRefusal('ONBOARD_NO_RELAY', 'no relay answered')
  return [...new Map(reads.flatMap(read => read.events).map(event => [event.id, event])).values()]
}

// The agent's own connection, from its seated credential files, for the hive claim and room joins.
function joinWith(manifest) {
  const signer = makeBunkerSigner(readFileSync(manifest.bunkerUriRef, 'utf8').trim(), readFileSync(manifest.bunkerClientRef, 'utf8').trim(), { idleMs: 30000 })
  return { signer, fetchImpl: globalThis.fetch, open: () => openBuzzSession({ relay: manifest.buzz.relay, signer }), close: () => signer.close?.() }
}

const runTool = (tool, args) => spawnSync(process.execPath, [join(here, tool), ...args], { stdio: 'inherit' }).status ?? 1

try {
  const { receipts } = await onboard({ command, name, fetchEvents, runTool, joinWith,
    root: resolve(flag('--instance-root') || process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'),
    out: resolve(flag('--out') || join(process.env.HOME || '/root', '.nvoy', 'staged')),
    stateDir: resolve(flag('--state-dir') || '/var/lib/nvoy-onboard'),
    keysPath: flag('--authorized-keys'), giversRedeploy: argv.includes('--givers-redeploy') })
  process.exit(receipts.some(row => row.state === 'refused') ? 1 : receipts.every(row => row.state === 'done') ? 0 : command === 'show' ? 0 : 4)
} catch (error) {
  console.error(`nvoy-onboard: ${error.code ? `${error.code}: ` : ''}${error.message}`)
  process.exit(1)
}
