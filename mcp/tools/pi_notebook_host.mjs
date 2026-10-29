// Optional owner-configured notebook host. No credentials, subprocess, channel
// consumer or model settings here; the installed adapter owns its Pi lifecycle.
import { readFileSync, lstatSync, realpathSync } from 'node:fs'
import { basename, dirname, isAbsolute, parse, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { fixedPath } from './channel_client.mjs'

const PROMPT_BYTES = 64_000 // matches the notebook responder's input contract

function fixedModel(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
      Object.keys(raw).sort().join(',') !== 'id,provider' ||
      raw.provider !== 'openai-codex' || typeof raw.id !== 'string' ||
      !/^[a-z0-9][a-z0-9.\-\[\]]{0,63}$/i.test(raw.id)) {
    throw new Error('evaluation requires a fixed openai-codex model identity')
  }
  return Object.freeze({ provider: raw.provider, id: raw.id })
}

function evaluationSocket(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path ||
      basename(path) !== 'notebook-eval.sock' || Buffer.byteLength(path) > 100) {
    throw new Error('evaluation needs a short absolute notebook-eval.sock path')
  }
  const parent = dirname(path), uid = process.getuid?.()
  const st = lstatSync(parent)
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== uid || (st.mode & 0o077) ||
      realpathSync(parent) !== parent) throw new Error('evaluation socket parent must be pre-created and owner-only')
  // A private leaf must not be replaceable through a writable ancestor.
  for (let dir = parent; ; dir = dirname(dir)) {
    const entry = lstatSync(dir), stickyRoot = entry.uid === 0 && (entry.mode & 0o1000)
    if (!entry.isDirectory() || ![0, uid].includes(entry.uid) || ((entry.mode & 0o022) && !stickyRoot)) {
      throw new Error('evaluation socket ancestors must be owner-held')
    }
    if (dir === parse(dir).root) break
  }
  return path
}

function readEvalRoster(raw, productionPrompt) {
  if (!Array.isArray(raw) || raw.length !== 6) throw new Error('eval_roster requires exactly six candidates')
  const paths = new Set(), variants = new Set(), counts = { planner: 0, drawer: 0, critic: 0 }
  const roster = raw.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item) ||
        Object.keys(item).sort().join(',') !== 'model,output_tokens,prompt_file,reasoning,role,socket_path' ||
        !Object.hasOwn(counts, item.role) ||
        !['minimal', 'low', 'medium', 'high', 'xhigh'].includes(item.reasoning) ||
        !Number.isInteger(item.output_tokens) || item.output_tokens < 1 || item.output_tokens > 8192 ||
        typeof item.prompt_file !== 'string') throw new Error('malformed evaluation candidate')
    const model = fixedModel(item.model)
    const prompt = fixedPath(item.prompt_file, 'evaluation prompt', PROMPT_BYTES)
    if ((prompt.stat.mode & 0o077) || prompt.path === productionPrompt) throw new Error('evaluation prompt must be private and separate from production')
    const socketPath = evaluationSocket(item.socket_path)
    const variant = JSON.stringify([item.role, model.provider, model.id, item.reasoning, item.output_tokens])
    if (paths.has(socketPath)) throw new Error('duplicate evaluation socket path')
    if (variants.has(variant)) throw new Error('duplicate evaluation candidate')
    paths.add(socketPath); variants.add(variant); counts[item.role]++
    return Object.freeze({ role: item.role, prompt_file: prompt.path, model,
      reasoning: item.reasoning, output_tokens: item.output_tokens, socket_path: socketPath })
  })
  if (Object.values(counts).some(count => count !== 2)) throw new Error('eval_roster needs two candidates per role')
  return Object.freeze(roster)
}

export function readNotebookConfig(raw, stateDir) {
  if (raw === undefined) return null
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
      !Object.hasOwn(raw, 'adapter_dir') || !Object.hasOwn(raw, 'prompt_file') ||
      Object.keys(raw).some(key => !['adapter_dir', 'prompt_file', 'eval_prompt_file', 'eval_model', 'eval_response_format', 'eval_roster'].includes(key)) ||
      typeof raw.adapter_dir !== 'string' || !isAbsolute(raw.adapter_dir) || resolve(raw.adapter_dir) !== raw.adapter_dir ||
      typeof raw.prompt_file !== 'string') throw new Error('notebook requires fixed adapter/prompt paths and bounded eval options')
  if ((Object.hasOwn(raw, 'eval_model') || Object.hasOwn(raw, 'eval_response_format')) && !Object.hasOwn(raw, 'eval_prompt_file')) {
    throw new Error('eval options require a separate eval prompt')
  }
  const evalResponseFormat = Object.hasOwn(raw, 'eval_response_format') ? raw.eval_response_format : 'semantic-v1'
  if (!['semantic-v1', 'story-panel-v1'].includes(evalResponseFormat)) {
    throw new Error('unsupported evaluation response format')
  }
  if (Object.hasOwn(raw, 'eval_prompt_file') && typeof raw.eval_prompt_file !== 'string') {
    throw new Error('evaluation needs a fixed prompt path')
  }
  const files = ['notebook_pi_lifecycle.mjs', 'notebook_pi_responder.mjs', 'notebook_pi_socket.mjs']
    .map(name => fixedPath(resolve(raw.adapter_dir, name), 'notebook adapter module', 128 * 1024))
  if (files.some(file => dirname(file.path) !== raw.adapter_dir || (file.stat.mode & 0o022))) {
    throw new Error('notebook adapter modules must share a fixed owner-held directory and not be group/world writable')
  }
  const prompt = fixedPath(raw.prompt_file, 'notebook system prompt', PROMPT_BYTES)
  if (prompt.stat.mode & 0o077) throw new Error('notebook system prompt must be owner-only (mode 0600)')
  if (Object.hasOwn(raw, 'eval_roster') && ['eval_prompt_file', 'eval_model', 'eval_response_format'].some(key => Object.hasOwn(raw, key))) {
    throw new Error('choose eval_roster or the legacy evaluation binding, not both')
  }
  const evalRoster = Object.hasOwn(raw, 'eval_roster') ? readEvalRoster(raw.eval_roster, prompt.path) : Object.freeze([])
  const socketPath = resolve(stateDir, 'notebook.sock')
  if (Buffer.byteLength(socketPath) > 100) throw new Error('state_dir is too deep for the notebook socket')
  let evalPromptFile = null, evalSocketPath = null
  let evalModel = null
  if (raw.eval_prompt_file !== undefined) {
    const evalPrompt = fixedPath(raw.eval_prompt_file, 'notebook eval prompt', PROMPT_BYTES)
    if (evalPrompt.stat.mode & 0o077) throw new Error('notebook eval prompt must be owner-only (mode 0600)')
    if (evalPrompt.path === prompt.path) throw new Error('notebook eval prompt must be separate')
    evalPromptFile = evalPrompt.path
    evalSocketPath = resolve(stateDir, 'notebook-eval.sock')
    if (Buffer.byteLength(evalSocketPath) > 100) throw new Error('state_dir is too deep for the notebook eval socket')
    if (raw.eval_model !== undefined) {
      if (!raw.eval_model || typeof raw.eval_model !== 'object' || Array.isArray(raw.eval_model) ||
          Object.keys(raw.eval_model).sort().join(',') !== 'id,provider' ||
          raw.eval_model.provider !== 'openai-codex' || typeof raw.eval_model.id !== 'string' ||
          !/^[a-z0-9][a-z0-9.\-\[\]]{0,63}$/i.test(raw.eval_model.id)) {
        throw new Error('eval_model requires a fixed openai-codex model identity')
      }
      evalModel = Object.freeze({ provider: raw.eval_model.provider, id: raw.eval_model.id })
    }
  }
  return Object.freeze({ modulePath: files[0].path, promptFile: prompt.path, socketPath, evalPromptFile, evalSocketPath, evalModel, evalResponseFormat, evalRoster })
}

export async function installPiNotebook(pi, config, evalMode = false) {
  if (!config) return null
  try {
    // Recheck at use; never read a notebook-supplied filename or prompt.
    const checked = readNotebookConfig({ adapter_dir: dirname(config.modulePath), prompt_file: config.promptFile,
      ...(config.evalPromptFile ? { eval_prompt_file: config.evalPromptFile } : {}),
      ...(config.evalPromptFile ? { eval_response_format: config.evalResponseFormat } : {}),
      ...(config.evalRoster?.length ? { eval_roster: config.evalRoster } : {}),
      ...(config.evalModel ? { eval_model: config.evalModel } : {}) }, dirname(config.socketPath))
    if (checked.modulePath !== config.modulePath || checked.socketPath !== config.socketPath ||
        checked.evalSocketPath !== config.evalSocketPath ||
        checked.evalResponseFormat !== config.evalResponseFormat ||
        checked.evalModel?.id !== config.evalModel?.id ||
        checked.evalModel?.provider !== config.evalModel?.provider) throw new Error('changed binding')
    if (JSON.stringify(checked.evalRoster) !== JSON.stringify(config.evalRoster)) throw new Error('changed roster')
    const candidate = Number.isInteger(evalMode) ? checked.evalRoster[evalMode] : null
    if (evalMode !== false && evalMode !== true && !candidate) throw new Error('missing candidate')
    if (evalMode === true && !checked.evalPromptFile) throw new Error('missing eval binding')
    const data = readFileSync(candidate ? candidate.prompt_file : evalMode === true ? checked.evalPromptFile : checked.promptFile)
    if (data.length > PROMPT_BYTES) throw new Error('prompt too large')
    const systemPrompt = new TextDecoder('utf-8', { fatal: true }).decode(data)
    if (!systemPrompt.trim() || systemPrompt.includes('\0')) throw new Error('invalid prompt')
    const module = await import(pathToFileURL(checked.modulePath).href)
    if (typeof module.registerNotebookResponder !== 'function') throw new Error('missing adapter entry')
    const handle = module.registerNotebookResponder(pi, candidate ? {
      socketPath: candidate.socket_path, systemPrompt, fixedModel: candidate.model, responseFormat: 'role-eval-v1',
      evaluation: { role: candidate.role, reasoning: candidate.reasoning, outputTokens: candidate.output_tokens },
    } : { socketPath: evalMode === true ? checked.evalSocketPath : checked.socketPath,
      systemPrompt, ...(evalMode === true ? { responseFormat: checked.evalResponseFormat } : {}),
      ...(evalMode === true && checked.evalModel ? { fixedModel: checked.evalModel } : {}) })
    if (!handle || typeof handle.close !== 'function' || typeof handle.settled !== 'function') throw new Error('invalid adapter handle')
    return handle
  } catch {
    // Do not let filesystem/module diagnostics expose prompts or private paths.
    throw new Error('notebook adapter could not be registered; check its owner-held modules and prompt')
  }
}

// All handles belong to this one extension/Pi registry. No new Pi process, login
// store, request-level model selector or channel consumer is introduced.
export async function installPiNotebooks(pi, config) {
  const handles = []
  let closing
  const settled = () => Promise.all(handles.map(handle => handle.settled()))
  const close = () => closing ||= (async () => {
    const closed = await Promise.allSettled(handles.map(handle => Promise.resolve().then(() => handle.close())))
    const drained = await Promise.allSettled(handles.map(handle => Promise.resolve().then(() => handle.settled())))
    if ([...closed, ...drained].some(result => result.status === 'rejected')) throw new Error('notebook handles did not all settle')
  })()
  try {
    const notebook = await installPiNotebook(pi, config)
    if (notebook) handles.push(notebook)
    const notebookEval = config?.evalPromptFile ? await installPiNotebook(pi, config, true) : null
    if (notebookEval) handles.push(notebookEval)
    const evaluations = []
    for (let i = 0; i < (config?.evalRoster.length || 0); i++) {
      const handle = await installPiNotebook(pi, config, i)
      handles.push(handle); evaluations.push(handle)
    }
    // The adapter drains on session_shutdown and retains its hooks so a later
    // session_start can bind again. close() means permanent extension disposal,
    // not a session transition; only the owner/partial-failure path invokes it.
    return { notebook, notebookEval, evaluations: Object.freeze(evaluations), close, settled }
  } catch (error) {
    await close()
    throw error
  }
}
