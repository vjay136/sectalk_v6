import { readFile } from 'node:fs/promises'
import assert from 'node:assert/strict'
import { verifySecrets } from './verify-secrets.mjs'

const totals = {
  AUTH:17, ORG:14, MSG:22, THR:5, ROOM:11, PRES:3, NOTIF:10, FILE:15,
  TASK:10, SRCH:9, CALL:23, AI:15, SEC:16, BILL:16, ADM:14, SOC:14,
  PLT:5, ANL:7, PLAT:13,
}
const validStates = ['NOT_STARTED','IN_PROGRESS','DONE','BLOCKED_EXTERNAL']
const freeOptional = new Set(['AUTH-05','ORG-08','ORG-09','SEC-04','PLAT-13'])
const fullRelease = process.argv.includes('--release')
const freeRelease = process.argv.includes('--release-free')
assert.ok(!(fullRelease && freeRelease),'Choose exactly one release scope.')
const read = file => readFile(new URL(file, import.meta.url),'utf8')
const [spec,matrix] = await Promise.all([read('../features.md'),read('../docs/FEATURE_MATRIX.md')])
const registry = [...spec.matchAll(/^- (([A-Z]+)-(\d{2})) (.+)$/gm)]
const registryNames = new Map(registry.map(([,id,,,name])=>[id,name.trim()]))
const states = new Map()
for (const line of matrix.split(/\r?\n/)) {
  if (!/^\| [A-Z]+-\d{2} \| /.test(line)) continue
  const [,id,name,role,screen,api,events,tests,state,evidence] = line.split(/(?<!\\)\|/).map(value=>value.trim())
  assert.ok(!states.has(id), 'Duplicate matrix row '+id)
  assert.equal(name.replace(/\\\|/g,'|'),registryNames.get(id),'Mismatched feature name '+id)
  assert.ok(validStates.includes(state),'Invalid state for '+id)
  if (state==='DONE' || state==='BLOCKED_EXTERNAL') {
    assert.ok([role,screen,api,events,tests,evidence].every(value=>value && value!=='—'),'Incomplete verification record for '+id)
  }
  states.set(id,state)
}
const expected = Object.entries(totals).flatMap(([module,count])=>Array.from({length:count},(_,i)=>module+'-'+String(i+1).padStart(2,'0')))
assert.equal(registry.length,239)
assert.deepEqual([...registryNames.keys()].sort(),expected.sort())
assert.deepEqual([...states.keys()].sort(),expected)
const counts = Object.fromEntries(validStates.map(state=>[state,[...states.values()].filter(value=>value===state).length]))
console.log(JSON.stringify({ registry:expected.length, ...counts }))
if (fullRelease || freeRelease) {
  const allowed = freeRelease ? freeOptional : new Set()
  const incomplete = expected.filter(id=>states.get(id)!=='DONE')
  const blocked = incomplete.filter(id=>!allowed.has(id))
  if(blocked.length){
    console.error('Release blocked. Incomplete required entries: '+blocked.join(', '))
    process.exitCode=1
  }else{
    try {
      const findings=verifySecrets(freeRelease?{buildAll:true}:{build:true})
      if(findings.length){
        for(const {file,rule} of findings)console.error(file+' — '+rule)
        process.exitCode=1
      }else if(freeRelease){
        console.log(JSON.stringify({scope:'free',required:expected.length-freeOptional.size,
          optionalIncomplete:incomplete.map(id=>({id,status:states.get(id)}))}))
      }
    } catch {
      console.error('Release blocked. The browser asset secret checks could not complete.')
      process.exitCode=1
    }
  }
}
