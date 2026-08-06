#!/usr/bin/env node
import { chmodSync, mkdirSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readManifest, instanceId } from './runtime_manifest.mjs'

const die = message => { console.error(`install-codex-bridge-launchagent: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
const printOnly = process.argv.includes('--print')
if (!id) die('usage: --instance <id> [--print]')
const root = resolve(process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances')
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (manifest.brokerMode !== 'remote' || manifest.deliveryMode !== 'codex_app_server' || manifest.codexTransport !== 'local_control_socket') {
  die('instance must be a keyless remote-broker codex_app_server binding')
}
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const bridge = resolve(repoRoot, 'mcp/tools/codex-remote-bridge.mjs')
const logs = resolve(manifest.runtimeDir, 'launchagent')
const label = `pub.nave.nvoy.${manifest.id}.codex-bridge`
const esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
const values = [process.execPath, bridge, manifest.id, root, logs]
if (values.some(value => /[\n\r\0]/.test(value))) die('manifest paths contain an unsafe control character')
const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${esc(label)}</string>
<key>ProgramArguments</key><array><string>${esc(process.execPath)}</string><string>${esc(bridge)}</string><string>--instance</string><string>${esc(manifest.id)}</string><string>--interval-ms</string><string>2000</string></array>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>${esc(homedir())}</string><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin</string><key>NVOY_INSTANCE_ROOT</key><string>${esc(root)}</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>${esc(resolve(logs, 'stdout.log'))}</string>
<key>StandardErrorPath</key><string>${esc(resolve(logs, 'stderr.log'))}</string>
<key>ProcessType</key><string>Background</string><key>ThrottleInterval</key><integer>10</integer>
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
