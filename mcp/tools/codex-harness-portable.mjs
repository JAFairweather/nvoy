#!/usr/bin/env node
// Run one identity's watchable Codex harness on this box, on its owner's ChatGPT login. See
// codex_portable_harness.mjs. The Claude form is instance-harness.mjs --remote; Codex has its own
// entry because its config, login and wake source all differ.
//
//   node mcp/tools/codex-harness-portable.mjs --instance <id> --config <client-config.json>
//
// It refuses to start with an OpenAI API key in reach: in the config, in CODEX_HOME's login, or in
// this environment. The app-server's environment is built, not inherited, so none reaches Codex.

import { fixedPath, SSH } from './channel_client.mjs'
import { readCodexClientConfig, refuseApiKeyEnvironment, runCodexPortableHarness } from './codex_portable_harness.mjs'

const die = message => { console.error(`codex-harness-portable: ${message}`); process.exit(1) }
const log = message => console.log(`codex-harness-portable: ${message}`)
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), configPath = flag('--config')
if (!id || !configPath) die('usage: --instance <id> --config <client-config.json>')
let config, ssh = SSH
try {
  refuseApiKeyEnvironment(process.env)
  config = readCodexClientConfig(configPath, id)
  // A replacement ssh (a test's, or one outside /usr/bin) must still be a fixed, owner-held file.
  if (process.env.NVOY_HARNESS_SSH) ssh = fixedPath(process.env.NVOY_HARNESS_SSH, 'ssh executable', null).path
} catch (error) { die(error.message) }

let stopping = false
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true; process.exit(0) })
try { await runCodexPortableHarness({ config, log, stopping: () => stopping, ssh }) } catch (error) { die(error.message) }
process.exit(0)
