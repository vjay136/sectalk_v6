import assert from 'node:assert/strict'
import test from 'node:test'
import {runAuditAnchor} from '../scripts/audit-anchor.mjs'

const receipt=(entry,hex='a')=>({entry,sha256:hex.repeat(64)})

test('the independent audit job anchors only with an explicit bootstrap or a verified previous receipt',async()=>{
  let latest=null
  let head=receipt('9007199254740994')
  const store={latest:async()=>latest,append:async value=>{latest=value}}
  const database={verify:async previous=>{assert.deepEqual(previous,latest);return head}}
  await assert.rejects(runAuditAnchor({database,store}),/bootstrap/)
  assert.deepEqual(await runAuditAnchor({database,store,initialize:true}),{status:'anchored',...head})
  await assert.rejects(runAuditAnchor({database,store,initialize:true}),/already initialized/)
  assert.deepEqual(await runAuditAnchor({database,store}),{status:'verified',...head})
  head=receipt('9007199254740995','b')
  assert.deepEqual(await runAuditAnchor({database,store}),{status:'anchored',...head})
  assert.deepEqual(latest,head)
})

test('a failed native verifier, rewind, replacement, or independent write failure prevents acknowledgment',async()=>{
  const previous=receipt('9007199254740995')
  const store={latest:async()=>previous,append:async()=>{throw new Error('Independent write failed')}}
  await assert.rejects(runAuditAnchor({database:{verify:async value=>{
    assert.deepEqual(value,previous)
    throw new Error('Native verifier refused the chain')
  }},store}),/refused/)
  await assert.rejects(runAuditAnchor({database:{verify:async()=>receipt('9007199254740994')},store}),/mismatch/)
  await assert.rejects(runAuditAnchor({database:{verify:async()=>receipt('9007199254740995','b')},store}),/mismatch/)
  await assert.rejects(runAuditAnchor({database:{verify:async()=>receipt('9007199254740996')},store}),/write failed/)
})
