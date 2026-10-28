import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, chmodSync, writeFileSync, rmSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { realpathSync } from 'node:fs'
import { readNotebookConfig, installPiNotebook } from '../mcp/tools/pi_notebook_host.mjs'

async function fixture(fn) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'pnb-')))
  chmodSync(dir, 0o700)
  const adapter = join(dir, 'adapter'), state = join(dir, 'state'), prompt = join(dir, 'prompt.txt')
  mkdirSync(adapter, { mode: 0o700 }); mkdirSync(state, { mode: 0o700 })
  for (const name of ['notebook_pi_lifecycle.mjs','notebook_pi_responder.mjs','notebook_pi_socket.mjs']) {
    writeFileSync(join(adapter,name), name.includes('lifecycle') ?
      'export function registerNotebookResponder(pi, options) { pi.options=options; return { settled: async () => {}, close: async () => {} }; }' : 'export {};', { mode: 0o600 })
  }
  writeFileSync(prompt, 'TRUSTED NOTEBOOK PROMPT', { mode: 0o600 })
  try { await fn({ dir, adapter, state, prompt, raw: { adapter_dir: adapter, prompt_file: prompt } }) }
  finally { rmSync(dir, { recursive: true }) }
}
test('absent config is inert; configured adapter receives only fixed prompt and derived socket', async () => {
  assert.equal(readNotebookConfig(undefined, '/unused'), null)
  assert.equal(await installPiNotebook({}, null), null)
  await fixture(async ({ raw, state }) => {
    const config=readNotebookConfig(raw,state), pi={}
    assert(Object.isFrozen(config))
    const handle=await installPiNotebook(pi,config)
    assert.equal(typeof handle.settled, 'function')
    assert.deepEqual(pi.options,{ socketPath: join(state,'notebook.sock'), systemPrompt:'TRUSTED NOTEBOOK PROMPT' })
  })
})
test('unknown selectors, relative paths, long socket and writable sources fail closed', async () => {
  await fixture(async ({ raw, state, adapter, prompt }) => {
    for (const bad of [null, true, [], {}, { ...raw, model:'other' }, { ...raw, socket:'/elsewhere' },
                      { ...raw, prompt_file:'relative' }, { ...raw, adapter_dir:'relative' }]) {
      assert.throws(() => readNotebookConfig(bad,state))
    }
    assert.throws(() => readNotebookConfig(raw,'/'+ 'x'.repeat(100)),/too deep/)
    chmodSync(prompt,0o644);assert.throws(() => readNotebookConfig(raw,state),/owner-only/);chmodSync(prompt,0o600)
    const module=join(adapter,'notebook_pi_socket.mjs')
    chmodSync(module,0o666);assert.throws(() => readNotebookConfig(raw,state),/writable/)
  })
})
test('symlink prompt and changed/invalid content are refused without exposing contents', async () => {
  await fixture(async ({ raw, state, prompt, dir }) => {
    const link=join(dir,'link');symlinkSync(prompt,link)
    assert.throws(() => readNotebookConfig({ ...raw,prompt_file:link },state),/symlink/)
    const config=readNotebookConfig(raw,state)
    for (const text of ['', '\0PRIVATE PROMPT', Buffer.from([255]), 'x'.repeat(64001)]) {
      writeFileSync(prompt,text)
      await assert.rejects(installPiNotebook({},config), error => error.message ===
        'notebook adapter could not be registered; check its owner-held modules and prompt')
    }
  })
})
