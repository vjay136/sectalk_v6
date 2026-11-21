import assert from 'node:assert/strict'
import {spawnSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {mkdtemp,rmdir,unlink,writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {test} from 'node:test'
import {fileURLToPath} from 'node:url'
import {captureSupabaseBackups,verifySupabaseBackupObservation} from '../scripts/supabase-backup-observation.mjs'

const json=value=>Buffer.from(JSON.stringify(value))
const sha=value=>createHash('sha256').update(value).digest('hex')
const approval={format:'sectalk-supabase-backup-approval-v1',sourceProject:'s'.repeat(20),testProject:'t'.repeat(20),
  region:'eu-central-1',workspace:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',keyVersion:2,
  reviewFrom:'2026-11-08T10:00:00Z',reviewThrough:'2026-11-13T10:00:00Z',
  observeFrom:'2026-11-15T00:00:00Z',observeThrough:'2026-11-16T00:00:00Z'}
const approvalRaw=json(approval)
const approvalSha256=sha(approvalRaw)
const at='2026-11-15T12:00:00Z'
const token='synthetic-backups-read-token-only'
const seconds=value=>Date.parse(value)/1000
const valid={
  region:approval.region,walg_enabled:true,pitr_enabled:true,
  backups:[
    {id:7362918,is_physical_backup:true,status:'COMPLETED',inserted_at:'2026-11-09T10:00:00+00:00'},
    {id:7973425,is_physical_backup:false,status:'REMOVED',inserted_at:'2026-11-14T10:00:00Z'},
    {id:6834281,is_physical_backup:true,status:'ARCHIVED',inserted_at:'2026-11-10T10:00:00Z'},
    {id:3819881,is_physical_backup:false,status:'FUTURE_STATUS',inserted_at:'2026-11-12T10:00:00Z'},
  ],
  physical_backup_data:{earliest_physical_backup_date_unix:seconds('2026-11-07T00:00:00Z'),
    latest_physical_backup_date_unix:seconds('2026-11-13T12:00:00Z')},
}

function options(body,extra={}){
  return {approvalRaw,approvalSha256,token,captureConfirmed:true,now:()=>new Date(at),
    fetcher:async()=>new Response(JSON.stringify(body),{headers:{'Content-Type':'application/json'}}),...extra}
}

async function inspect(body,extra={}){
  const captureRaw=await captureSupabaseBackups(options(body,extra))
  return verifySupabaseBackupObservation({approvalRaw,approvalSha256,captureRaw,captureSha256:sha(captureRaw)})
}

test('exact GET observes one approved test-project catalog and physical bounds without claiming restores or erasure',async()=>{
  let calls=0
  const result=await inspect(valid,{fetcher:async(url,init)=>{
    calls++
    assert.equal(url,'https://api.supabase.com/v1/projects/'+approval.testProject+'/database/backups')
    assert.equal(init.method,'GET')
    assert.equal(init.redirect,'error')
    assert.equal(init.cache,'no-store')
    assert.equal(init.headers.Authorization,'Bearer '+token)
    assert.equal(init.body,undefined)
    return new Response(JSON.stringify(valid),{headers:{'Content-Type':'application/json; charset=utf-8'}})
  }})
  assert.equal(calls,1)
  assert.equal(result.catalog.state,'entries_reported')
  assert.equal(result.catalog.entries,4)
  assert.equal(result.catalog.inReviewInterval,3)
  assert.equal(result.catalog.unknownStatus,1)
  assert.equal(result.catalog.statusCounts.removed,1)
  assert.equal(result.catalog.statusCounts.archived,1)
  assert.equal(result.physicalBounds.reviewRelation,'bounds_span_interval')
  assert.equal(result.pitr,'enabled_with_reported_bounds')
  for(const status of [result.restoreAvailability,result.providerDeletion,result.backupErasure])assert.equal(status,'unverified')
  for(const value of [approval.testProject,approval.sourceProject,approval.workspace,token,'7362918','FUTURE_STATUS']){
    assert.ok(!JSON.stringify(result).includes(value))
  }
})

test('distinguishes empty, omitted, partial, inconsistent and unknown states from observed bounds',async()=>{
  const region=approval.region
  const omitted=await inspect({region,backups:[],pitr_enabled:true,walg_enabled:false,physical_backup_data:{}})
  assert.equal(omitted.catalog.state,'empty_reported_list')
  assert.equal(omitted.pitr,'enabled_bounds_unconfirmed')
  assert.equal(omitted.physicalBounds.state,'omitted')
  const unknown=await inspect({region})
  assert.equal(unknown.catalog.entries,null)
  assert.equal(unknown.pitr,'unknown')
  assert.equal(unknown.walG,'unknown')
  assert.equal(unknown.physicalBounds.state,'omitted')
  const partial=await inspect({...valid,pitr_enabled:false,physical_backup_data:{latest_physical_backup_date_unix:seconds(at)}})
  assert.equal(partial.pitr,'reported_disabled')
  assert.equal(partial.physicalBounds.state,'partially_reported')
  assert.equal(partial.physicalBounds.latest,'2026-11-15T12:00:00.000Z')
  assert.equal(partial.physicalBounds.reviewRelation,'unknown')
  for(const bounds of [
    {earliest_physical_backup_date_unix:seconds(at),latest_physical_backup_date_unix:seconds('2026-11-07T00:00:00Z')},
    {earliest_physical_backup_date_unix:0,latest_physical_backup_date_unix:seconds(at)},
    {earliest_physical_backup_date_unix:seconds(at),latest_physical_backup_date_unix:seconds(at)+99999},
  ]){
    assert.equal((await inspect({...valid,physical_backup_data:bounds})).physicalBounds.state,'inconsistent')
  }
  const intersects=await inspect({...valid,physical_backup_data:{
    earliest_physical_backup_date_unix:seconds('2026-11-12T00:00:00Z'),latest_physical_backup_date_unix:seconds(at)}})
  assert.equal(intersects.physicalBounds.reviewRelation,'bounds_intersect_interval')
  const outside=await inspect({...valid,physical_backup_data:{
    earliest_physical_backup_date_unix:seconds('2026-11-14T00:00:00Z'),latest_physical_backup_date_unix:seconds(at)}})
  assert.equal(outside.physicalBounds.reviewRelation,'no_intersection')
  const duplicate=await inspect({...valid,backups:[valid.backups[0],valid.backups[0]]})
  assert.equal(duplicate.catalog.state,'unknown')
  const paged=await inspect(valid,{fetcher:async()=>new Response(JSON.stringify(valid),{
    headers:{'Content-Type':'application/json',Link:'<https://example.invalid/next>; rel="next"'},
  })})
  assert.equal(paged.catalog.state,'possibly_incomplete')
  assert.equal(paged.catalog.entries,null)
})

test('blocks same-project, stale, unconfirmed, unauthorized, wrong-region and tampered evidence',async()=>{
  const never=()=>assert.fail('The scope should fail before fetch.')
  await assert.rejects(captureSupabaseBackups(options(valid,{captureConfirmed:false,fetcher:never})),/Confirm/)
  await assert.rejects(captureSupabaseBackups(options(valid,{now:()=>new Date('2026-11-20T00:00:00Z'),fetcher:never})),/interval is closed/)
  const reused=json({...approval,sourceProject:approval.testProject})
  await assert.rejects(captureSupabaseBackups(options(valid,{approvalRaw:reused,approvalSha256:sha(reused),fetcher:never})),/distinct/)
  for(const status of [401,403,429,500]){
    await assert.rejects(captureSupabaseBackups(options(valid,{fetcher:async()=>new Response('private diagnostic',{status})})),/authorized/)
  }
  await assert.rejects(captureSupabaseBackups(options({...valid,region:'unexpected-region'})),/approved test project region/)
  const captureRaw=await captureSupabaseBackups(options(valid))
  const captured=JSON.parse(captureRaw)
  const foreign=json({...captured,projectRef:approval.sourceProject})
  const verify=(raw,known=sha(raw))=>verifySupabaseBackupObservation({approvalRaw,approvalSha256,captureRaw:raw,captureSha256:known})
  assert.throws(()=>verify(foreign),/different project/)
  assert.throws(()=>verify(foreign,sha(captureRaw)),/independently recorded digest/)
  assert.throws(()=>verify(json({...captured,body:json({region:approval.region}).toString('base64')})),/differs from the captured bytes/)
})

test('the offline CLI verifies both independent digests without a management token',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sectalk-supabase-backups-'))
  const scope=join(root,'approval.json'),inventory=join(root,'inventory.json')
  const captureRaw=await captureSupabaseBackups(options(valid))
  const saved=[]
  try{
    for(const [path,bytes] of [[scope,approvalRaw],[inventory,captureRaw]]){
      await writeFile(path,bytes,{mode:0o600,flag:'wx'})
      saved.push(path)
    }
    const cli=fileURLToPath(new URL('../scripts/supabase-backup-observation.mjs',import.meta.url))
    const outcome=spawnSync(process.execPath,[cli,'--approval',scope,'--approval-sha256',approvalSha256,'--inventory',inventory,
      '--inventory-sha256',sha(captureRaw)],{encoding:'utf8',windowsHide:true,timeout:5000,env:{...process.env,SECTALK_BACKUP_OBSERVER_TOKEN:''}})
    assert.equal(outcome.status,0,outcome.stderr)
    assert.equal(JSON.parse(outcome.stdout).catalog.entries,4)
  }finally{
    for(const path of saved)await unlink(path)
    await rmdir(root)
  }
})
