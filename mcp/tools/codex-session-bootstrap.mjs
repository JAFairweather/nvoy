#!/usr/bin/env node
// Operator-only bootstrap for one persistent Codex participant task.
//
// This tool is deliberately outside every watcher/broker path. It creates or selects a task from
// local operator arguments, then prints the immutable task id that belongs in the Nvoy manifest.
// No Nostr event, grant, carrier, or message body can choose or create a Codex task.

import { realpathSync, statSync } from 'node:fs'
import { resolve } from 'node:path'
import { appServerCall } from './codex_app_server.mjs'

const die = message => { console.error(`codex-session-bootstrap: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const name = flag('--name')
const cwdArg = flag('--cwd')
const socket = flag('--socket') || resolve(process.env.HOME || '', '.codex', 'app-server-control', 'app-server-control.sock')
const model = flag('--model')

if (!name || !cwdArg) die('usage: --name <task-name> --cwd <project-root> [--socket <absolute-path>] [--model <id>]')
if (name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) die('task name must be 1-80 printable characters')
if (!socket.startsWith('/')) die('socket must be an absolute local path')
let cwd
try { cwd = realpathSync(cwdArg); if (!statSync(cwd).isDirectory()) throw new Error('not a directory') } catch { die('cwd must be an existing directory') }

try {
  const result = await appServerCall({ socketPath: socket, bootstrap: { name, cwd, model }, timeoutMs: 30_000 })
  process.stdout.write(JSON.stringify(result) + '\n')
} catch (error) { die(error.message || String(error)) }
