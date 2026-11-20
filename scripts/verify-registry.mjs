import { readFile } from 'node:fs/promises'
import assert from 'node:assert/strict'

const totals = {
  AUTH:17, ORG:14, MSG:22, THR:5, ROOM:11, PRES:3, NOTIF:10, FILE:15,
  TASK:10, SRCH:9, CALL:23, AI:15, SEC:16, BILL:16, ADM:14, SOC:14,
  PLT:5, ANL:7, PLAT:13,
}
const validStates = ['NOT_STARTED','IN_PROGRESS','DONE','BLOCKED_EXTERNAL']
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
if (process.argv.includes('--release') && counts.DONE!==expected.length) {
  console.error('Release blocked. All 239 entries must have status DONE.')
  process.exitCode=1
}
