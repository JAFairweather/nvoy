import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, chmodSync, writeFileSync, rmSync, symlinkSync, copyFileSync, existsSync } from 'node:fs'
import net from 'node:net'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { realpathSync } from 'node:fs'
import { readNotebookConfig, installPiNotebook, installPiNotebooks } from '../mcp/tools/pi_notebook_host.mjs'

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

function rosterFixture(dir) {
  return ['planner','drawer','critic'].flatMap(role => {
    const prompt = join(dir, role + '.txt')
    writeFileSync(prompt, 'FIXED ' + role, {mode:0o600})
    return [0,1].map(i => {
      const parent = join(dir, role[0] + i)
      mkdirSync(parent, {mode:0o700})
      return {role, prompt_file:prompt, model:{provider:'openai-codex',id:'candidate-' + i},
        reasoning:i ? 'high' : 'medium', output_tokens:2048,
        socket_path:join(parent,'notebook-eval.sock')}
    })
  })
}

test('six fixed candidates are immutable; production options remain unchanged', async () => {
  await fixture(async ({raw,state,dir,adapter}) => {
    writeFileSync(join(adapter,'notebook_pi_lifecycle.mjs'), `
      export function registerNotebookResponder(pi,options) {
        pi.calls.push(options); const n=pi.calls.length;
        return {close:async()=>{pi.closed.push(n)},settled:async()=>{pi.drained.push(n)}};
      }`, {mode:0o600})
    const rows=rosterFixture(dir), config=readNotebookConfig({...raw,eval_roster:rows},state)
    rows[0].model.id='mutated'; rows[0].reasoning='low'
    const handlers=[],pi={calls:[],closed:[],drained:[],on:(_name,fn)=>{handlers.push(fn)}}
    const group=await installPiNotebooks(pi,config)
    assert.equal(group.evaluations.length,6)
    assert.equal(group.notebookEval,null)
    assert.deepEqual(pi.calls[0],{socketPath:join(state,'notebook.sock'),systemPrompt:'TRUSTED NOTEBOOK PROMPT'})
    assert.equal(new Set(pi.calls.map(call=>call.socketPath)).size,7)
    assert(Object.isFrozen(config.evalRoster) && Object.isFrozen(config.evalRoster[0].model))
    for(let i=0;i<6;i++) {
      const row=config.evalRoster[i],call=pi.calls[i+1]
      assert.deepEqual(call,{socketPath:row.socket_path,systemPrompt:'FIXED '+row.role,
        fixedModel:row.model,responseFormat:'role-eval-v1',
        evaluation:{role:row.role,reasoning:row.reasoning,outputTokens:row.output_tokens}})
    }
    assert.equal(handlers.length,0,'group must not own restartable session hooks')
    await group.close(); await group.close()
    assert.deepEqual(pi.closed,[1,2,3,4,5,6,7])
    assert.deepEqual(pi.drained,[1,2,3,4,5,6,7])
  })
})

test('roster rejects duplicates, missing roles, selectors and unsafe paths', async () => {
  await fixture(async ({raw,state,dir}) => {
    const rows=rosterFixture(dir)
    const alter=(index,fields)=>rows.map((row,i)=>i===index?{...row,...fields}:row)
    for(const bad of [[], rows.slice(0,5), [...rows,rows[0]], null,
      alter(1,{socket_path:rows[0].socket_path}), alter(1,{reasoning:'medium',model:rows[0].model}),
      alter(0,{role:'critic'}), alter(0,{role:'other'}), alter(0,{reasoning:'unknown'}),
      alter(0,{output_tokens:true}),alter(0,{output_tokens:8193}),alter(0,{output_tokens:0}),
      alter(0,{output_tokens:1.5}),alter(0,{model:{provider:'other',id:'x'}}),
      alter(0,{model:{provider:'openai-codex',id:'x',extra:true}}),alter(0,{extra:true}),
      alter(0,{socket_path:join(dir,'notebook.sock')}),alter(0,{socket_path:'relative/notebook-eval.sock'}),
      alter(0,{socket_path:'/'+ 'x'.repeat(100)+'/notebook-eval.sock'}),
      alter(0,{socket_path:join(dir,'absent','notebook-eval.sock')}),
      alter(0,{prompt_file:raw.prompt_file})]) {
      assert.throws(()=>readNotebookConfig({...raw,eval_roster:bad},state))
    }
    assert.throws(()=>readNotebookConfig({...raw,eval_roster:rows,eval_prompt_file:rows[0].prompt_file},state))
    chmodSync(join(dir,'p0'),0o755)
    assert.throws(()=>readNotebookConfig({...raw,eval_roster:rows},state),/owner-only/)
    chmodSync(join(dir,'p0'),0o700)
    const link=join(dir,'linked');symlinkSync(join(dir,'p0'),link)
    assert.throws(()=>readNotebookConfig({...raw,eval_roster:alter(0,{socket_path:join(link,'notebook-eval.sock')})},state))
    chmodSync(rows[0].prompt_file,0o644)
    assert.throws(()=>readNotebookConfig({...raw,eval_roster:rows},state),/private/)
  })
})

test('partial registration failure closes and settles every acquired handle', async () => {
  await fixture(async ({raw,state,dir,adapter}) => {
    writeFileSync(join(adapter,'notebook_pi_lifecycle.mjs'), `
      export function registerNotebookResponder(pi,options) {
        if(++pi.n===4)throw Error('PRIVATE DIAGNOSTIC');
        const n=pi.n;
        return {close:async()=>{pi.closed.push(n)},settled:async()=>{pi.drained.push(n)}};
      }`, {mode:0o600})
    const config=readNotebookConfig({...raw,eval_roster:rosterFixture(dir)},state)
    const pi={n:0,closed:[],drained:[],on(){}}
    await assert.rejects(installPiNotebooks(pi,config),/could not be registered/)
    assert.deepEqual(pi.closed,[1,2,3]);assert.deepEqual(pi.drained,[1,2,3])
  })
})

test('real six-variant host shares one registry, rebinds across sessions, and refuses unavailable model',
  {skip:!process.env.HERD_BOARD_ADAPTER_TEST_DIR}, async () => {
  await fixture(async ({raw,state,dir,adapter}) => {
    for(const name of ['notebook_pi_lifecycle.mjs','notebook_pi_responder.mjs','notebook_pi_socket.mjs']) {
      copyFileSync(join(process.env.HERD_BOARD_ADAPTER_TEST_DIR,name),join(adapter,name))
    }
    const rows=rosterFixture(dir),config=readNotebookConfig({...raw,eval_roster:rows},state)
    const handlers=new Map(),calls=[],finds=[]
    const pi={on(name,fn){const list=handlers.get(name)||[];list.push(fn);handlers.set(name,list);return ()=>{};}}
    const live={id:'live',provider:'openai-codex',input:['image','text']}
    let unavailable=false
    const registry={
      find(provider,id){finds.push(this);return unavailable && id==='candidate-1' ? undefined : {...live,provider,id}},
      isUsingOAuth(){assert.equal(this,registry);return true},
      streamSimple(m,context,options){
        assert.equal(this,registry);calls.push({model:m.id,context,options})
        const text='{"fixture":true}'
        return {async *[Symbol.asyncIterator](){yield {type:'text_delta',delta:text}},result:async()=>({
          role:'assistant',provider:m.provider,model:m.id,stopReason:'stop',content:[{type:'text',text}],usage:{output:10}})}
      },
    }
    const group=await installPiNotebooks(pi,config)
    const exchange=socketPath=>new Promise((resolve,reject)=>{
      const socket=net.createConnection(socketPath),parts=[]
      socket.setTimeout(1500,()=>socket.destroy(Error('test timeout')))
      socket.on('error',reject)
      socket.on('connect',()=>socket.write(JSON.stringify({request_id:'notebook-'+'c'.repeat(32),context:'fixture',deadline_ms:1000,
        image:{mime_type:'image/png',data:'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aG9kAAAAASUVORK5CYII='}})+'\n'))
      socket.on('data',chunk=>{parts.push(chunk);const data=Buffer.concat(parts).toString('utf8');
        if(data.endsWith('\n')){socket.end();try{resolve(JSON.parse(data))}catch(error){reject(error)}}})
    })
    try {
      for(const fn of handlers.get('session_start'))fn({},{model:live,modelRegistry:registry})
      await group.settled()
      assert.equal(finds.length,6);assert(finds.every(value=>value===registry))
      const prod=await exchange(config.socketPath)
      assert.equal(prod.response_format,'semantic-v1');assert.equal(prod.metrics.model,'live')
      for(const row of rows) {
        const response=await exchange(row.socket_path)
        assert.equal(response.response_format,'role-eval-v1')
        assert.equal(response.metrics.model,row.model.id)
        assert.equal(response.evaluation.role,row.role)
        const call=calls.at(-1)
        assert.equal(call.options.reasoning,row.reasoning)
        assert.equal(call.options.maxTokens,row.output_tokens)
        assert.equal(call.context.systemPrompt,'FIXED '+row.role)
        assert.equal(call.context.messages.length,1);assert.equal(call.context.tools.length,0)
      }
      // Session shutdown is not extension disposal. All seven sockets drain,
      // then the same registered handles must bind again in this Pi process.
      for(let session=0;session<2;session++) {
        for(const fn of handlers.get('session_shutdown'))await fn({},{model:live,modelRegistry:registry})
        await group.settled()
        for(const path of [config.socketPath,...rows.map(row=>row.socket_path)])assert.equal(existsSync(path),false)
        const nextLive={...live,id:'live-session-'+session}
        for(const fn of handlers.get('session_start'))await fn({},{model:nextLive,modelRegistry:registry})
        await group.settled()
        assert.equal(existsSync(config.socketPath),true,'production must rebind after session shutdown')
        assert.equal((await exchange(config.socketPath)).metrics.model,nextLive.id)
        for(const row of rows) {
          const response=await exchange(row.socket_path)
          assert.equal(response.metrics.model,row.model.id)
          assert.equal(response.evaluation.role,row.role)
          assert.equal(calls.at(-1).options.reasoning,row.reasoning)
          assert.equal(calls.at(-1).context.messages.length,1)
        }
      }
      unavailable=true
      for(const fn of handlers.get('model_select'))fn({model:live},{model:live,modelRegistry:registry})
      await group.settled()
      for(const row of rows)assert.equal(existsSync(row.socket_path),row.model.id==='candidate-0')
      assert.equal((await exchange(config.socketPath)).metrics.model,'live')
      assert.equal((await exchange(rows[0].socket_path)).metrics.model,'candidate-0')
      await assert.rejects(exchange(rows[1].socket_path),/ENOENT/)
    } finally {await group.close()}
    for(const path of [config.socketPath,...rows.map(row=>row.socket_path)])assert.equal(existsSync(path),false)
    const before=finds.length
    for(const fn of handlers.get('session_start'))await fn({},{model:live,modelRegistry:registry})
    await group.settled()
    assert.equal(finds.length,before,'permanently disposed registrations cannot restart')
    for(const path of [config.socketPath,...rows.map(row=>row.socket_path)])assert.equal(existsSync(path),false)
  })
})
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

test('alternate format is fixed owner configuration and affects only evaluation', async () => {
  await fixture(async ({ raw, state, dir }) => {
    const evalPrompt=join(dir,'eval.txt')
    writeFileSync(evalPrompt,'FIXED STORY PANEL PROMPT',{mode:0o600})
    const evalModel={provider:'openai-codex',id:'configured-model'}
    const config=readNotebookConfig({...raw,eval_prompt_file:evalPrompt,
      eval_model:evalModel,eval_response_format:'story-panel-v1'},state)
    assert.equal(config.evalResponseFormat,'story-panel-v1')
    const production={},evaluation={}
    const prodHandle=await installPiNotebook(production,config)
    const evalHandle=await installPiNotebook(evaluation,config,true)
    assert.deepEqual(production.options,{socketPath:join(state,'notebook.sock'),systemPrompt:'TRUSTED NOTEBOOK PROMPT'})
    assert.deepEqual(evaluation.options,{socketPath:join(state,'notebook-eval.sock'),
      systemPrompt:'FIXED STORY PANEL PROMPT',fixedModel:evalModel,responseFormat:'story-panel-v1'})
    await prodHandle.close();await evalHandle.close()
  })
})

test('existing evaluation configurations retain semantic-v1 default', async () => {
  await fixture(async ({ raw, state, dir }) => {
    const prompt=join(dir,'eval.txt');writeFileSync(prompt,'EVAL',{mode:0o600})
    for(const extra of [{},{eval_response_format:'semantic-v1'}]) {
      const config=readNotebookConfig({...raw,eval_prompt_file:prompt,...extra},state),pi={}
      assert.equal(config.evalResponseFormat,'semantic-v1')
      const handle=await installPiNotebook(pi,config,true)
      assert.deepEqual(pi.options,{socketPath:join(state,'notebook-eval.sock'),systemPrompt:'EVAL',responseFormat:'semantic-v1'})
      await handle.close()
    }
  })
})

test('format/model selectors need a separate evaluation binding', async () => {
  await fixture(async ({ raw, state, dir }) => {
    const evalPrompt=join(dir,'eval.txt');writeFileSync(evalPrompt,'EVAL',{mode:0o600})
    for(const extra of [{eval_response_format:'story-panel-v1'},
      {eval_model:{provider:'openai-codex',id:'configured'}}]) {
      assert.throws(()=>readNotebookConfig({...raw,...extra},state),/separate eval prompt/)
    }
    for(const format of [null,undefined,true,{},'other','', 'story-panel-v1 ']) {
      assert.throws(()=>readNotebookConfig({...raw,eval_prompt_file:evalPrompt,eval_response_format:format},state),/unsupported evaluation/)
    }
    assert.throws(()=>readNotebookConfig({...raw,eval_prompt_file:raw.prompt_file,eval_response_format:'story-panel-v1'},state),/separate/)
    assert.throws(()=>readNotebookConfig({...raw,eval_prompt_file:evalPrompt,response_format:'story-panel-v1'},state))
    assert.throws(()=>readNotebookConfig({...raw,eval_prompt_file:undefined,eval_response_format:'story-panel-v1'},state),/fixed prompt path/)
    assert.throws(()=>readNotebookConfig(Object.create(raw),state))
  })
})

test('evaluation format and binding are rechecked before registration', async () => {
  await fixture(async ({ raw, state, dir }) => {
    const evalPrompt=join(dir,'eval.txt');writeFileSync(evalPrompt,'EVAL',{mode:0o600})
    const config=readNotebookConfig({...raw,eval_prompt_file:evalPrompt,eval_response_format:'story-panel-v1'},state)
    for(const changed of [{...config,evalResponseFormat:'other'},
      {...config,evalSocketPath:join(state,'notebook.sock')},
      {...config,evalPromptFile:null}]) {
      const pi={}
      await assert.rejects(installPiNotebook(pi,changed,true),/could not be registered/)
      assert.equal(pi.options,undefined)
    }
  })
})

test('real herd-board adapter preserves separate socket formats with a fake model',
  {skip:!process.env.HERD_BOARD_ADAPTER_TEST_DIR}, async () => {
  await fixture(async ({raw,state,dir,adapter}) => {
    for(const name of ['notebook_pi_lifecycle.mjs','notebook_pi_responder.mjs','notebook_pi_socket.mjs']) {
      copyFileSync(join(process.env.HERD_BOARD_ADAPTER_TEST_DIR,name),join(adapter,name))
    }
    const evalPrompt=join(dir,'eval.txt');writeFileSync(evalPrompt,'FIXED STORY',{mode:0o600})
    const config=readNotebookConfig({...raw,eval_prompt_file:evalPrompt,eval_response_format:'story-panel-v1'},state)
    const handlers=new Map(),calls=[]
    const pi={on(name,fn){const list=handlers.get(name)||[];list.push(fn);handlers.set(name,list);return ()=>{};}}
    const model={id:'fake',provider:'openai-codex',input:['image','text']}
    const modelRegistry={isUsingOAuth:()=>true,streamSimple(m,context,options){
      calls.push({context,options})
      const text='{"v":1,"mode":"answer","text":"Fake transport fixture only."}'
      return {async *[Symbol.asyncIterator](){yield {type:'text_delta',delta:text}},result:async()=>({
        role:'assistant',provider:m.provider,model:m.id,stopReason:'stop',content:[{type:'text',text}],usage:{output:10}})}
    }}
    const production=await installPiNotebook(pi,config),evaluation=await installPiNotebook(pi,config,true)
    try {
      for(const handler of handlers.get('session_start'))handler({},{model,modelRegistry})
      await Promise.all([production.settled(),evaluation.settled()])
      const request={request_id:'notebook-'+'a'.repeat(32),context:'offline test',deadline_ms:1000,
        image:{mime_type:'image/png',data:'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aG9kAAAAASUVORK5CYII='}}
      async function exchange(socketPath) {
        return new Promise((resolve,reject)=>{
          const socket=net.createConnection(socketPath),parts=[]
          socket.setTimeout(1500,()=>socket.destroy(Error('test timeout')))
          socket.on('error',reject)
          socket.on('connect',()=>socket.write(JSON.stringify(request)+'\n'))
          socket.on('data',chunk=>{parts.push(chunk);const data=Buffer.concat(parts).toString('utf8');
            if(data.endsWith('\n')){socket.end();try{resolve(JSON.parse(data))}catch(error){reject(error)}}})
        })
      }
      const prod=await exchange(config.socketPath),candidate=await exchange(config.evalSocketPath)
      assert.equal(prod.response_format,'semantic-v1')
      assert.equal(candidate.response_format,'story-panel-v1')
      assert.equal(prod.metrics.model,'fake');assert.equal(candidate.metrics.model,'fake')
      assert.deepEqual(calls.map(c=>c.context.systemPrompt),['TRUSTED NOTEBOOK PROMPT','FIXED STORY'])
      assert(calls.every(c=>c.context.messages.length===1 && c.context.tools.length===0 && c.options.maxRetries===0))
    } finally {await production.close();await evaluation.close()}
  })
})
