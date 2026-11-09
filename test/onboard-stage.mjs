import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { keyFingerprint, readStagedKey, stagedKeyPath } from '../mcp/tools/onboard_stage.mjs'

const tmp = mkdtempSync(join(tmpdir(), 'nvoy-stage-'))
const request = 'ab'.repeat(32), instance = 'curator2'
const BODY = 'AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'a'.repeat(40)
const line = comment => `ssh-ed25519 ${BODY} ${comment}\n`
const put = text => writeFileSync(stagedKeyPath(tmp, request), text)
const read = (bound = null) => readStagedKey({ stateDir: tmp, request, instance, bound })

assert.equal(read(), null, 'nothing staged: an own-box agent has no row')

put(line(`nvoy-stage:${instance}:${request}`))
let row = read()
assert.equal(row.state, 'done'); assert.match(row.detail, new RegExp(`^ssh-ed25519 ${BODY} \\(SHA256:[A-Za-z0-9+/]{43}\\), staged for the owner to bind$`))
assert.equal(keyFingerprint({ keyBody: BODY }).length, 'SHA256:'.length + 43)

// Bound to this instance and request, or refused.
put(line(`nvoy-stage:other:${request}`)); assert.equal(read().state, 'refused')
put(line(`nvoy-stage:${instance}:${'cd'.repeat(32)}`)); assert.match(read().detail, /not bound to this instance and request/)
put(`ssh-ed25519 ${BODY}\n`); assert.equal(read().state, 'refused', 'a key with no binding comment')

// One public key only; private material is refused and never echoed.
put('-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETSECRET\n-----END OPENSSH PRIVATE KEY-----\n')
row = read(); assert.equal(row.state, 'refused'); assert.ok(!row.detail.includes('SECRETSECRET'))
put(line(`nvoy-stage:${instance}:${request}`) + line(`nvoy-stage:${instance}:${request}`)); assert.equal(read().state, 'refused', 'two lines')
put('ssh-rsa AAAA ' + `nvoy-stage:${instance}:${request}\n`); assert.equal(read().state, 'refused', 'an unsupported type')
put('x'.repeat(2000)); assert.match(read().detail, /too large/)

// Exactly one line of three tokens: extra text after the binding is refused.
put(line(`nvoy-stage:${instance}:${request}`).trim() + ' extra\n'); assert.match(read().detail, /extra text after its binding comment/)
put(line(`nvoy-stage:${instance}:${request} # note`)); assert.equal(read().state, 'refused')

// A file that cannot be read, or vanishes between the check and the read, is a refused row and not a throw.
put(line(`nvoy-stage:${instance}:${request}`)); chmodSync(stagedKeyPath(tmp, request), 0)
if (process.getuid?.() !== 0) { row = read(); assert.equal(row.state, 'refused'); assert.match(row.detail, /cannot read the staged channel key: EACCES/) }
chmodSync(stagedKeyPath(tmp, request), 0o644)
{
  const raced = readStagedKey({ stateDir: tmp, request, instance, fs: { readFileSync: () => { const e = new Error('gone'); e.code = 'ENOENT'; throw e } } })
  assert.equal(raced.state, 'refused'); assert.match(raced.detail, /cannot read the staged channel key: ENOENT/)
}

// A link is not a file.
rmSync(stagedKeyPath(tmp, request)); writeFileSync(join(tmp, 'elsewhere'), line(`nvoy-stage:${instance}:${request}`))
symlinkSync(join(tmp, 'elsewhere'), stagedKeyPath(tmp, request)); assert.match(read().detail, /not a plain file/)
rmSync(stagedKeyPath(tmp, request)); mkdirSync(stagedKeyPath(tmp, request)); assert.match(read().detail, /not a plain file/)
rmSync(stagedKeyPath(tmp, request), { recursive: true })

// When the owner has bound a key, a different staged key is a mismatch naming both fingerprints.
put(line(`nvoy-stage:${instance}:${request}`))
assert.equal(read({ keyType: 'ssh-ed25519', keyBody: BODY }).state, 'done')
row = read({ keyType: 'ssh-ed25519', keyBody: 'AAAAC3NzaC1lZDI1NTE5AAAAIK1' + 'b'.repeat(40) })
assert.equal(row.state, 'refused'); assert.match(row.detail, /differs from the key the owner bound/)

rmSync(tmp, { recursive: true, force: true })
console.log('onboard-stage: no file no row, request and instance binding, one public key, private material never echoed, links refused, bind mismatch pass')
