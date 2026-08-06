import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { submitExternalProposal, fetchExternalDecision } from '../mcp/tools/nact_external_client.mjs'

let n=0, pass=0
const t=async(name,fn)=>{n++;try{await fn();pass++;console.log(`ok   — ${name}`)}catch(e){console.error(`FAIL — ${name}\n  ${e.stack||e}`)}}
const sk=generateSecretKey(), pubkey=getPublicKey(sk), calls=[]
const signer={signEvent:async event=>finalizeEvent({...event,pubkey},sk)}
const fetchImpl=async(url,options)=>{calls.push({url,options});return{ok:true,status:200,json:async()=>({state:'pending'})}}
const proposal={version:1,proposal_id:'a'.repeat(32),instance:'codex-jaf',fingerprint:'b'.repeat(64),action:'nostr-private-reply',content:'reply',recipient:'jaf',context:'receipt',created_at_ms:1,expires_at_ms:2}
await t('submission is body-bound NIP-98 from the participant to the pinned route',async()=>{
  await submitExternalProposal({endpoint:'https://nact.nave.pub',signer,proposal,fetchImpl})
  const call=calls.pop(), event=JSON.parse(Buffer.from(call.options.headers.authorization.slice(6),'base64').toString())
  assert.equal(call.url,'https://nact.nave.pub/api/propose-external');assert.equal(call.options.method,'POST');assert.ok(verifyEvent(event))
  assert.equal(event.tags.find(tag=>tag[0]==='payload')[1].length,64);assert.equal(call.options.body,JSON.stringify(proposal))
})
await t('polling is participant-authenticated and body-binds the proposal id',async()=>{
  await fetchExternalDecision({endpoint:'https://nact.nave.pub',signer,proposalId:proposal.proposal_id,fetchImpl})
  const call=calls.pop(), event=JSON.parse(Buffer.from(call.options.headers.authorization.slice(6),'base64').toString())
  assert.equal(call.url,'https://nact.nave.pub/api/external-approval');assert.equal(call.options.method,'POST')
  assert.equal(call.options.body,JSON.stringify({proposal_id:proposal.proposal_id}));assert.ok(verifyEvent(event))
  assert.equal(event.tags.find(tag=>tag[0]==='payload')[1],createHash('sha256').update(call.options.body).digest('hex'))
})
await t('non-HTTPS, credentialed, pathful, and query-bearing endpoints fail closed',async()=>{
  for(const endpoint of ['http://nact.test','https://u:p@nact.test','https://nact.test/path','https://nact.test/?x=1'])
    await assert.rejects(()=>submitExternalProposal({endpoint,signer,proposal,fetchImpl}),/invalid endpoint/)
})

console.log(`\n${pass}/${n} passed`);process.exit(pass===n?0:1)
