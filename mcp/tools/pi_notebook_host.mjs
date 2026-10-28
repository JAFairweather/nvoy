// Optional owner-configured notebook host. No credentials, subprocess, channel
// consumer or model settings here; the installed adapter owns its Pi lifecycle.
import { readFileSync } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { fixedPath } from './channel_client.mjs'

const PROMPT_BYTES = 64_000 // matches the notebook responder's input contract

export function readNotebookConfig(raw, stateDir) {
  if (raw === undefined) return null
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
      Object.keys(raw).sort().join(',') !== 'adapter_dir,prompt_file' ||
      typeof raw.adapter_dir !== 'string' || !isAbsolute(raw.adapter_dir) || resolve(raw.adapter_dir) !== raw.adapter_dir ||
      typeof raw.prompt_file !== 'string') throw new Error('notebook requires only absolute adapter_dir and prompt_file paths')
  const files = ['notebook_pi_lifecycle.mjs', 'notebook_pi_responder.mjs', 'notebook_pi_socket.mjs']
    .map(name => fixedPath(resolve(raw.adapter_dir, name), 'notebook adapter module', 128 * 1024))
  if (files.some(file => dirname(file.path) !== raw.adapter_dir || (file.stat.mode & 0o022))) {
    throw new Error('notebook adapter modules must share a fixed owner-held directory and not be group/world writable')
  }
  const prompt = fixedPath(raw.prompt_file, 'notebook system prompt', PROMPT_BYTES)
  if (prompt.stat.mode & 0o077) throw new Error('notebook system prompt must be owner-only (mode 0600)')
  const socketPath = resolve(stateDir, 'notebook.sock')
  if (Buffer.byteLength(socketPath) > 100) throw new Error('state_dir is too deep for the notebook socket')
  return Object.freeze({ modulePath: files[0].path, promptFile: prompt.path, socketPath })
}

export async function installPiNotebook(pi, config) {
  if (!config) return null
  try {
    // Recheck at use; never read a notebook-supplied filename or prompt.
    const checked = readNotebookConfig({ adapter_dir: dirname(config.modulePath), prompt_file: config.promptFile }, dirname(config.socketPath))
    if (checked.modulePath !== config.modulePath || checked.socketPath !== config.socketPath) throw new Error('changed binding')
    const data = readFileSync(checked.promptFile)
    if (data.length > PROMPT_BYTES) throw new Error('prompt too large')
    const systemPrompt = new TextDecoder('utf-8', { fatal: true }).decode(data)
    if (!systemPrompt.trim() || systemPrompt.includes('\0')) throw new Error('invalid prompt')
    const module = await import(pathToFileURL(checked.modulePath).href)
    if (typeof module.registerNotebookResponder !== 'function') throw new Error('missing adapter entry')
    const handle = module.registerNotebookResponder(pi, { socketPath: checked.socketPath, systemPrompt })
    if (!handle || typeof handle.close !== 'function' || typeof handle.settled !== 'function') throw new Error('invalid adapter handle')
    return handle
  } catch {
    // Do not let filesystem/module diagnostics expose prompts or private paths.
    throw new Error('notebook adapter could not be registered; check its owner-held modules and prompt')
  }
}
