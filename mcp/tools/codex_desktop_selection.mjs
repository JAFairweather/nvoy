import { lstatSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

export function verifySelectedDesktopProject({ statePath, threadId, projectLabel }) {
  const rawPath = String(statePath || '')
  const path = resolve(rawPath)
  const thread = String(threadId || '')
  const label = String(projectLabel || '')
  if (!rawPath.startsWith('/') || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(thread) || !label.trim()) {
    throw new Error('Codex Desktop selection proof is not fully bound')
  }
  let stat
  try { stat = lstatSync(path) } catch { throw new Error('Codex Desktop state is unavailable') }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 4 * 1024 * 1024 || (stat.mode & 0o022)) {
    throw new Error('Codex Desktop state must be a bounded non-writable regular file')
  }
  let state
  try { state = JSON.parse(readFileSync(path, 'utf8')) } catch { throw new Error('Codex Desktop state is invalid JSON') }
  const selected = state?.['selected-project']
  const assignment = state?.['thread-project-assignments']?.[thread]
  const projectId = String(assignment?.projectId || '')
  const project = state?.['local-projects']?.[projectId]
  const cwd = String(assignment?.cwd || '')
  const roots = Array.isArray(project?.rootPaths) ? project.rootPaths.map(value => resolve(String(value || ''))) : []
  if (selected?.type !== 'local' || selected?.projectId !== projectId || assignment?.projectKind !== 'local' ||
      !projectId || project?.id !== projectId || project?.name !== label || !cwd.startsWith('/') || !roots.includes(resolve(cwd))) {
    throw new Error('configured Codex thread is not in the selected project')
  }
  return Object.freeze({ projectId, cwd: resolve(cwd) })
}
