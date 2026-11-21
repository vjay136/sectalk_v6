import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import test from 'node:test'
import {DeviceId,OlmMachine,RequestType,UserId,initAsync} from '@matrix-org/matrix-sdk-crypto-wasm'
import {matrixUser,olmDirectoryTranscript,olmPrekeysTranscript,verifyOlmPublish} from '../apps/web/lib/olm-directory-proof.ts'

test('the approved-device directory accepts real Matrix library keys and rejects mismatched identities or mutated prekeys',async()=>{
  const owner=randomUUID()
  const device=randomUUID()
  await initAsync()
  const cryptoMachine=await OlmMachine.initialize(new UserId(matrixUser(owner)),new DeviceId(device))
  try{
    const upload=(await cryptoMachine.outgoingRequests()).find(request=>request.type===RequestType.KeysUpload)
    assert.ok(upload)
    const {device_keys:bundle,one_time_keys:prekeys}=JSON.parse(upload.body)
    assert.ok(Object.keys(prekeys).length>0)
    assert.equal(await verifyOlmPublish(owner,device,bundle,prekeys),true)
    assert.equal(await verifyOlmPublish(randomUUID(),device,bundle,prekeys),false)
    assert.equal(await verifyOlmPublish(owner,randomUUID(),bundle,prekeys),false)
    const [name,selected]=Object.entries(prekeys)[0]
    assert.equal(await verifyOlmPublish(owner,device,bundle,{[name]:{...selected,key:'0'.repeat(43)}}),false)
    assert.equal(await verifyOlmPublish(owner,device,bundle,{[name]:{...selected,fallback:true}}),false)
    const reordered=Object.fromEntries(Object.entries(bundle).reverse())
    assert.deepEqual(olmDirectoryTranscript(owner,device,bundle),olmDirectoryTranscript(owner,device,reordered))
    assert.notDeepEqual(olmPrekeysTranscript(owner,device,randomUUID(),bundle,prekeys),
      olmPrekeysTranscript(owner,device,randomUUID(),bundle,prekeys))
  }finally{cryptoMachine.close()}
})
