import assert from 'node:assert/strict'
import {spawnSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {mkdtemp,rmdir,unlink,writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {test} from 'node:test'
import {fileURLToPath} from 'node:url'
import {captureSupabaseBackups} from '../scripts/supabase-backup-observation.mjs'
import {verifySupabaseBackupTimeline} from '../scripts/supabase-backup-timeline.mjs'

const json=value=>Buffer.from(JSON.stringify(value))
const sha=value=>createHash('sha256').update(value).digest('hex')
const base={format:'sectalk-supabase-backup-approval-v1',sourceProject:'a'.repeat(20),testProject:'b'.repeat(20),
  region:'eu-central-1',workspace:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',keyVersion:9,
  reviewFrom:'2026-10-01T00:00:00Z',reviewThrough:'2026-10-05T00:00:00Z'}
const baselineAt='2026-10-06T12:00:00Z',laterAt='2026-10-10T12:00:00Z'
const event={format:'sectalk-provider-key-evidence-v1',workspace:base.workspace,version:base.keyVersion,
  eventTime:'2026-10-08T00:00:00Z',recordedAt:'2026-10-09T00:00:00Z',eventSha256:'e'.repeat(64),pinCommitment:'d'.repeat(64)}
const seconds=value=>Date.parse(value)/1000
const row=(id,status,fields={})=>({id,status,is_physical_backup:true,inserted_at:'2026-10-04T00:00:00Z',...fields})
const before={region:base.region,walg_enabled:true,pitr_enabled:true,
  backups:[row(100001,'COMPLETED'),row(100002,'ARCHIVED'),row(100003,'COMPLETED'),row(100004,'REMOVED')],
  physical_backup_data:{earliest_physical_backup_date_unix:seconds('2026-10-01T00:00:00Z'),
    latest_physical_backup_date_unix:seconds('2026-10-05T00:00:00Z')}}
const after={region:base.region,walg_enabled:true,pitr_enabled:false,
  backups:[row(100001,'ARCHIVED'),row(100002,'REMOVED'),row(100004,'REMOVED'),row(100005,'COMPLETED')],
  physical_backup_data:{earliest_physical_backup_date_unix:seconds('2026-10-02T00:00:00Z'),
    latest_physical_backup_date_unix:seconds('2026-10-04T00:00:00Z')}}

function approve(items){
  const comparisonRaw=json({format:'sectalk-supabase-backup-timeline-approval-v1',
    ...Object.fromEntries(Object.entries(items).map(([name,raw])=>[name+'Sha256',sha(raw)]))})
  return {...items,comparisonRaw,comparisonSha256:sha(comparisonRaw)}
}

async function fixture({laterScope={},laterBody=after,provider=event}={}){
  const baselineApproval=json({...base,observeFrom:'2026-10-06T00:00:00Z',observeThrough:'2026-10-07T00:00:00Z'})
  const laterApproval=json({...base,observeFrom:'2026-10-10T00:00:00Z',observeThrough:'2026-10-11T00:00:00Z',...laterScope})
  const capture=(approvalRaw,providerBody,at)=>captureSupabaseBackups({
    approvalRaw,approvalSha256:sha(approvalRaw),captureConfirmed:true,token:'synthetic-scoped-read-token',now:()=>new Date(at),
    fetcher:async()=>Response.json(providerBody),
  })
  return approve({baselineApproval,laterApproval,baselineInventory:await capture(baselineApproval,before,baselineAt),
    laterInventory:await capture(laterApproval,laterBody,laterAt),providerReceipt:json(provider)})
}

test('distinguishes stable backup IDs, explicit Removed transitions, omissions and shifted reported physical bounds',async()=>{
  const bundle=await fixture()
  const report=verifySupabaseBackupTimeline(bundle)
  assert.deepEqual(report.catalog,{
    state:'reported_catalogs_compared',baselineState:'entries_reported',laterState:'entries_reported',stillListed:3,
    firstListed:1,notListedLater:1,changedStatus:2,changedToRemoved:1,laterRemovedStatus:2,
    laterCompletedOrArchivedStatus:2,baselineUnknownStatus:0,laterUnknownStatus:0,
  })
  assert.equal(report.physicalBounds.earliestMovement,'moved_later')
  assert.equal(report.physicalBounds.latestMovement,'moved_earlier')
  assert.equal(report.physicalBounds.baselineReviewRelation,'bounds_span_interval')
  assert.equal(report.physicalBounds.laterReviewRelation,'bounds_intersect_interval')
  assert.equal(report.physicalBounds.laterPitr,'reported_disabled')
  assert.equal(report.providerDeletion,'unverified')
  assert.equal(report.backupErasure,'unverified')
  for(const privateValue of [base.workspace,base.testProject,base.sourceProject,'100001',event.pinCommitment]){
    assert.ok(!JSON.stringify(report).includes(privateValue))
  }
})

test('keeps omitted or potentially incomplete observations unknown and never treats empty lists as erasure',async()=>{
  const partial=verifySupabaseBackupTimeline(await fixture({laterBody:{region:base.region,has_more:true,pitr_enabled:true}}))
  assert.deepEqual(partial.catalog,{state:'comparison_unknown',baselineState:'entries_reported',laterState:'possibly_incomplete'})
  assert.equal(partial.physicalBounds.state,'comparison_unknown')
  const empty=verifySupabaseBackupTimeline(await fixture({laterBody:{...after,backups:[]}}))
  assert.equal(empty.catalog.notListedLater,4)
  assert.equal(empty.catalog.laterRemovedStatus,0)
  assert.equal(empty.backupErasure,'unverified')
})

test('rejects borrowed scope, overlapping approvals, reordered event windows and changed immutable backup identity',async()=>{
  const borrowed=await fixture({laterScope:{testProject:'c'.repeat(20)}})
  assert.throws(()=>verifySupabaseBackupTimeline(borrowed),/same exact test scope/)
  const wrongEvent=await fixture({provider:{...event,version:10}})
  assert.throws(()=>verifySupabaseBackupTimeline(wrongEvent),/different workspace or key version/)
  const overlapping=await fixture({laterScope:{observeFrom:'2026-10-06T13:00:00Z'}})
  assert.throws(()=>verifySupabaseBackupTimeline(overlapping),/disjoint approved/)
  const wrongWindow=await fixture({provider:{...event,eventTime:'2026-10-06T00:00:00Z'}})
  assert.throws(()=>verifySupabaseBackupTimeline(wrongWindow),/must bracket/)
  const altered=await fixture({laterBody:{...after,backups:[row(100001,'ARCHIVED',{is_physical_backup:false})]}})
  assert.throws(()=>verifySupabaseBackupTimeline(altered),/repeated backup identifier/)
  const valid=await fixture()
  assert.throws(()=>verifySupabaseBackupTimeline({...valid,laterInventory:Buffer.from('{}')}),/independently recorded digest/)
})

test('offline CLI joins independently pinned files and returns redacted counts without a token',async()=>{
  const bundle=await fixture()
  const directory=await mkdtemp(join(tmpdir(),'sectalk-backup-timeline-'))
  const files=[]
  try{
    for(const [name,raw] of Object.entries({
      'timeline-approval.json':bundle.comparisonRaw,'provider-key-evidence.json':bundle.providerReceipt,
      'baseline-approval.json':bundle.baselineApproval,'baseline-inventory.json':bundle.baselineInventory,
      'later-approval.json':bundle.laterApproval,'later-inventory.json':bundle.laterInventory,
    })){
      const path=join(directory,name)
      await writeFile(path,raw,{mode:0o600,flag:'wx'})
      files.push(path)
    }
    const command=fileURLToPath(new URL('../scripts/supabase-backup-timeline.mjs',import.meta.url))
    const result=spawnSync(process.execPath,[command,'--bundle',directory,'--approval-sha256',bundle.comparisonSha256],
      {encoding:'utf8',windowsHide:true,timeout:6000,env:{...process.env,SECTALK_BACKUP_OBSERVER_TOKEN:''}})
    assert.equal(result.status,0,result.stderr)
    assert.equal(JSON.parse(result.stdout).catalog.changedToRemoved,1)
    assert.equal(result.stdout.includes(base.testProject),false)
  }finally{
    for(const path of files)await unlink(path)
    await rmdir(directory)
  }
})
