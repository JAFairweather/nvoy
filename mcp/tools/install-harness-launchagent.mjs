#!/usr/bin/env node
// Install a portable harness supervisor (Claude, Codex or pi) as a macOS LaunchAgent, so it runs headless,
// starts at login and is restarted by launchd, and the only thing on screen is the agent itself, in
// its herdr workspace. The supervisor is told to use herdr outright: at login herdr may not be up
// yet, and the session waits for it rather than starting in tmux where no one would see it.
//
//   node mcp/tools/install-harness-launchagent.mjs --runner claude|codex|pi --instance <id> --config <client-config.json> [--print]

import { accessSync, chmodSync, constants, mkdirSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readClientConfig } from './channel_client.mjs'
import { readCodexClientConfig } from './codex_portable_harness.mjs'
import { readPiClientConfig } from './pi_harness_extension.mjs'

const die = message => { console.error(`install-harness-launchagent: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const runner = flag('--runner'), id = flag('--instance'), configArg = flag('--config')
const printOnly = process.argv.includes('--print')
if (!['claude', 'codex', 'pi'].includes(runner) || !id || !configArg) die('usage: --runner claude|codex|pi --instance <id> --config <client-config.json> [--print]')
const config = resolve(configArg)
let logs
try {
  logs = runner === 'claude' ? resolve(readClientConfig(config, id).home, '.nvoy-harness', 'launchagent')
    : runner === 'codex' ? resolve(readCodexClientConfig(config, id).codexHome, 'nvoy', 'launchagent')
    : resolve(readPiClientConfig(config, id).stateDir, 'nvoy', 'launchagent')
} catch (error) { die(error.message) }
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const entry = resolve(repoRoot, 'mcp/tools', { claude: 'instance-harness.mjs', codex: 'codex-harness-portable.mjs', pi: 'pi-harness.mjs' }[runner])
const args = runner === 'claude' ? ['--instance', id, '--remote', config] : ['--instance', id, '--config', config]
// The installer's own PATH, so the supervisor finds the same claude, codex, pi and herdr the owner does.
const path = [...new Set((process.env.PATH || '').split(':').filter(isAbsolute))].join(':') || '/usr/bin:/bin'
// node by its PATH name (Homebrew's stable link), not this process's versioned path, which an upgrade removes.
const node = path.split(':').map(dir => resolve(dir, 'node')).find(file => { try { accessSync(file, constants.X_OK); return true } catch { return false } }) || process.execPath
const label = `pub.nave.nvoy.${id}.harness`
const esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
if ([node, entry, config, logs, path, homedir(), ...args].some(value => /[\n\r\0]/.test(value))) die('a path contains an unsafe control character')
const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${esc(label)}</string>
<key>ProgramArguments</key><array>${[node, entry, ...args].map(a => `<string>${esc(a)}</string>`).join('')}</array>
<key>WorkingDirectory</key><string>${esc(repoRoot)}</string>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>${esc(homedir())}</string><key>PATH</key><string>${esc(path)}</string><key>HARNESS_TERMINAL</key><string>herdr</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>${esc(resolve(logs, 'stdout.log'))}</string>
<key>StandardErrorPath</key><string>${esc(resolve(logs, 'stderr.log'))}</string>
<key>ProcessType</key><string>Interactive</string><key>ThrottleInterval</key><integer>10</integer>
</dict></plist>
`
if (printOnly) { process.stdout.write(plist); process.exit(0) }
const target = resolve(homedir(), 'Library', 'LaunchAgents', `${label}.plist`)
mkdirSync(dirname(target), { recursive: true, mode: 0o700 })
mkdirSync(logs, { recursive: true, mode: 0o700 })
const tmp = `${target}.${process.pid}.tmp`
writeFileSync(tmp, plist, { mode: 0o600 })
chmodSync(tmp, 0o600)
renameSync(tmp, target)
console.log(target)
console.log(`load with: launchctl bootstrap gui/${process.getuid()} ${target}`)
