// onboard_stage.mjs — the hosted agent's channel public key, staged across by an operator helper
// (waggle docs/DESIGN_ADD_AN_AGENT.md, "Two ways in"). The runner cannot read herd-cloud's agent home, so
// the helper writes only the public half, atomically, to a request-bound name in the runner's state dir.
//
// Contract with the helper: file `<stateDir>/<request id>.staged-channel.pub`, a regular file (no link),
// at most 1 KiB, one OpenSSH line `<type> <base64> nvoy-stage:<instance>:<request id>`. The comment binds
// the key to this instance and this request. The runner reports what it finds; it never trusts it.
// The row carries a public key only. Anything that looks private is refused and never echoed.

import { createHash } from 'node:crypto'
import { lstatSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { readPublicKey } from './instance_apply.mjs'

export const STAGED_MAX_BYTES = 1024
export const stagedKeyPath = (stateDir, request) => join(stateDir, `${request}.staged-channel.pub`)

// SHA256:<unpadded base64>, the form `ssh-keygen -lf` prints, so the page and the owner can compare.
export const keyFingerprint = ({ keyBody }) =>
  `SHA256:${createHash('sha256').update(Buffer.from(keyBody, 'base64')).digest('base64').replace(/=+$/, '')}`

// -> null when nothing is staged for this request (an own-box agent), else { state, detail, key? }.
export function readStagedKey({ stateDir, request, instance, bound = null }) {
  const path = stagedKeyPath(stateDir, request)
  let st
  try { st = lstatSync(path) } catch (error) {
    if (error?.code === 'ENOENT') return null
    return { state: 'refused', detail: `cannot read the staged channel key: ${error?.code || 'error'}` }
  }
  if (!st.isFile()) return { state: 'refused', detail: 'the staged channel key is not a plain file' }
  if (st.size > STAGED_MAX_BYTES) return { state: 'refused', detail: 'the staged channel key file is too large' }
  const text = readFileSync(path, 'utf8')
  let key
  try { key = readPublicKey(text) } catch (error) {
    // readPublicKey's messages never repeat the input.
    return { state: 'refused', detail: `the staged channel key is not one public key: ${error.message}` }
  }
  const comment = text.trim().split(/\s+/)[2] || ''
  if (comment !== `nvoy-stage:${instance}:${request}`)
    return { state: 'refused', detail: 'the staged channel key is not bound to this instance and request' }
  const fingerprint = keyFingerprint(key)
  if (bound && (bound.keyType !== key.keyType || bound.keyBody !== key.keyBody))
    return { state: 'refused', detail: `the staged channel key ${fingerprint} differs from the key the owner bound ${keyFingerprint(bound)}`, key }
  return { state: 'done', detail: `${key.keyType} ${key.keyBody} (${fingerprint}), staged for the owner to bind`, key }
}
