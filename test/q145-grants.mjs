import test from 'node:test'
import assert from 'node:assert/strict'
import { missingBrokerGrantsAreEnded } from '../bin/q145-grants.mjs'

test('broker gaps are safe only when every absent event is an ended grant', () => {
  const grant = { id: 'grant', kind: 440 }
  const revoke = { id: 'revoke', kind: 441, pubkey: '4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d', tags: [['e', grant.id]] }
  assert.deepEqual(missingBrokerGrantsAreEnded([grant, revoke], new Set([revoke.id])), { missing: [grant.id], safe: true })
  assert.equal(missingBrokerGrantsAreEnded([grant], new Set()).safe, false)
  assert.equal(missingBrokerGrantsAreEnded([grant, revoke], new Set([grant.id])).safe, false)
})
