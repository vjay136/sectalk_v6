import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash,randomBytes,randomUUID } from 'node:crypto'
import { mkdir,mkdtemp,readFile,rmdir,unlink,writeFile } from 'node:fs/promises'
import { join,resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { openTenantRecord,sealTenantRecord,wrapFreshTenantKey } from '../apps/web/lib/tenant-artifact-keys.ts'

assert.equal(process.env.SECTALK_DR_SYNTHETIC_LOCAL,'yes')
const container='supabase_db_v4-auth-qa'
const workspace=randomUUID(), externalWorkspace=randomUUID(), absentWorkspace=randomUUID()
const database='sectalk_restore_evidence_'+randomBytes(8).toString('hex')
const directory=await mkdtemp(join(tmpdir(),'sectalk-key-evidence-'))
const providerFile=join(directory,'provider-key-evidence.json')
const filenames=['project.pgdump','private-inventory.jsonl','objects/storage-manifest.json','project-manifest.json']
const before=join(directory,'pre-destruction'),after=join(directory,'post-destruction')
const cli=resolve('scripts/backup-key-evidence.mjs')
const hash=bytes=>createHash('sha256').update(bytes).digest('hex')
const docker=(tool,args,input,encoding)=>execFileSync('docker',['exec','-i',container,tool,...args],{input,encoding,windowsHide:true})
const sql=statement=>docker('psql',['-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',database],statement,'utf8').trim()
let created=false

async function capture(root) {
  await mkdir(join(root,'objects'),{recursive:true})
  const dump=docker('pg_dump',['--format=custom','-U','postgres','-d',database])
  const inventory='\n', storage='{"version":1,"objects":[]}\n'
  await writeFile(join(root,filenames[0]),dump)
  await writeFile(join(root,filenames[1]),inventory)
  await writeFile(join(root,filenames[2]),storage)
  const manifest=JSON.stringify({version:1,capturedAt:new Date().toISOString(),files:{
    [filenames[0]]:hash(dump),[filenames[1]]:hash(inventory),[filenames[2]]:hash(storage),
  }})+'\n'
  await writeFile(join(root,filenames[3]),manifest)
  return {digest:hash(manifest),dump}
}
function audit(root,scope,digest,...options) {
  return JSON.parse(execFileSync(process.execPath,[cli,'--archive',root,'--workspace',scope,'--manifest-sha256',digest,
    '--pg-restore-container',container,...options],{encoding:'utf8',windowsHide:true,timeout:30000}))
}

async function providerEvidence(workspace,version,pin) {
  const eventTime=new Date().toISOString(),eventSha256=hash('Synthetic verified lifecycle event')
  const pinCommitment=hash('sectalk-provider-pin-commitment-v1:'+workspace+':'+version+':'+pin)
  const receipt=JSON.stringify({format:'sectalk-provider-key-evidence-v1',workspace,version,eventTime,
    eventSha256,recordedAt:eventTime,pinCommitment})
  await writeFile(providerFile,receipt)
  const receiptSha256=hash(receipt)
  return {receiptSha256,eventSha256,eventTime,options:['--provider-evidence',providerFile,'--provider-evidence-sha256',receiptSha256]}
}

try {
  const wrapRoot=randomBytes(32).toString('base64url')
  process.env.SECTALK_KMS_WRAPPING_KEY=wrapRoot
  const key=await wrapFreshTenantKey(workspace,1,'managed')
  const channel=randomUUID(),post=randomUUID(),actor=randomUUID()
  const plaintext=Buffer.from('Synthetic record retained under a historical managed key')
  const sealed=await sealTenantRecord({workspace,version:1,custody:'managed',...key},channel,post,actor,plaintext)
  docker('createdb',['-U','postgres','--template=template0',database])
  created=true
  const [firstPin,secondPin]=[randomBytes(32).toString('base64url'),randomBytes(32).toString('base64url')]
  const externalMarker=(version,pin,ref)=>'external_v2_'+pin+'_'+createHash('sha256').update(JSON.stringify([
    'sectalk/external-key/v2',pin,externalWorkspace,version,ref,
  ])).digest('base64url')
  const marker=externalMarker(1,firstPin,'fixture')
  const rotated=externalMarker(2,secondPin,'rotated')
  sql(`create schema sectalk_private;
    create table sectalk_private.st_v7_tenant_key_state (workspace uuid primary key,current_version integer not null,destroyed_at timestamptz);
    create table sectalk_private.st_v7_tenant_key_versions (workspace uuid not null,version integer not null,custody text not null,
       provider_ref text,wrapped text not null,created_at timestamptz not null default now(),primary key(workspace,version));
    create schema zz_unrelated;
    create table zz_unrelated.archive_rows (value text not null);
    insert into zz_unrelated.archive_rows select md5(random()::text)||md5(random()::text) from generate_series(1,4800);
    insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values('${workspace}',1),('${externalWorkspace}',2);
    insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped) values
       ('${workspace}',1,'managed',null,'${key.wrapped}'),('${externalWorkspace}',1,'byok','fixture','${marker}'),
       ('${externalWorkspace}',2,'byok','rotated','${rotated}');`)
  const first=await capture(before)
  sql(`delete from sectalk_private.st_v7_tenant_key_versions where workspace='${workspace}';
    update sectalk_private.st_v7_tenant_key_state set destroyed_at=now() where workspace='${workspace}';`)
  assert.equal(sql(`select count(*) from sectalk_private.st_v7_tenant_key_versions where workspace='${workspace}';`),'0')
  const original=audit(before,workspace,first.digest)
  assert.equal(original.backupErasure,'unverified')
  assert.equal(original.finding,'wrapped_managed_keys_retained')
  assert.deepEqual(original.keyState,{currentVersion:1,destructionRecorded:false})
  assert.deepEqual(original.retained,{managedWrappedKeys:1,externalKeyReferences:0,legacyExternalEnvelopes:0})
  assert.ok(!JSON.stringify(original).includes(key.wrapped))
  assert.equal(audit(before,externalWorkspace,first.digest).finding,'external_key_records_retained')
  assert.equal(audit(before,absentWorkspace,first.digest).finding,'no_listed_key_records')
  const exact=audit(before,externalWorkspace,first.digest,'--key-version','1','--provider-pin='+firstPin)
  assert.deepEqual(exact.exactKey,{version:1,record:'external_reference',providerPinMatch:true})
  assert.deepEqual(exact.keyState,{currentVersion:2,destructionRecorded:false})
  assert.equal(exact.backupErasure,'unverified')
  assert.ok(![firstPin,marker,rotated,'fixture'].some(secret=>JSON.stringify(exact).includes(secret)))
  assert.deepEqual(audit(before,externalWorkspace,first.digest,'--key-version','1','--provider-pin='+secondPin).exactKey,
    {version:1,record:'external_reference',providerPinMatch:false})
  assert.deepEqual(audit(before,externalWorkspace,first.digest,'--key-version','2').exactKey,{version:2,record:'external_reference'})
  assert.deepEqual(audit(before,workspace,first.digest,'--key-version','1','--provider-pin='+firstPin).exactKey,
    {version:1,record:'managed_wrapped',providerPinMatch:null})
  assert.deepEqual(audit(before,externalWorkspace,first.digest,'--key-version','3','--provider-pin='+firstPin).exactKey,
    {version:3,record:'absent',providerPinMatch:null})
  assert.throws(()=>audit(before,externalWorkspace,first.digest,'--provider-pin='+firstPin),{stderr:/requires an exact key version/})
  assert.throws(()=>audit(before,externalWorkspace,first.digest,'--key-version','2147483648'),{stderr:/positive PostgreSQL integer/})
  const matchingReceipt=await providerEvidence(externalWorkspace,1,firstPin)
  const correlated=audit(before,externalWorkspace,first.digest,'--key-version','1',...matchingReceipt.options)
  assert.deepEqual(correlated.providerEvidence,{
    receiptSha256:matchingReceipt.receiptSha256,eventSha256:matchingReceipt.eventSha256,eventTime:matchingReceipt.eventTime,
    record:'independent_provider_receipt',archiveBinding:'matches',
  })
  assert.deepEqual(correlated.exactKey,{version:1,record:'external_reference',providerPinMatch:true})
  assert.equal(correlated.sourceDeletion,'unverified')
  assert.equal(correlated.providerDeletion,'unverified')
  assert.equal(correlated.backupErasure,'unverified')
  assert.ok(![firstPin,marker,rotated,'fixture','pinCommitment'].some(secret=>JSON.stringify(correlated).includes(secret)))
  assert.throws(()=>audit(before,absentWorkspace,first.digest,'--key-version','1',...matchingReceipt.options),
    {stderr:/different workspace or key version/})
  assert.throws(()=>audit(before,externalWorkspace,first.digest,'--key-version','2',...matchingReceipt.options),
    {stderr:/different workspace or key version/})
  assert.throws(()=>audit(before,externalWorkspace,first.digest,'--key-version','1','--provider-pin='+firstPin,...matchingReceipt.options),
    {stderr:/Use the provider evidence file/})
  await writeFile(providerFile,'altered evidence')
  assert.throws(()=>audit(before,externalWorkspace,first.digest,'--key-version','1',...matchingReceipt.options),
    {stderr:/provider evidence does not match the independent digest/})
  const differentReceipt=await providerEvidence(externalWorkspace,1,secondPin)
  assert.equal(audit(before,externalWorkspace,first.digest,'--key-version','1',...differentReceipt.options).providerEvidence.archiveBinding,'differs')
  const absentReceipt=await providerEvidence(externalWorkspace,3,firstPin)
  const noArchivedKey=audit(before,externalWorkspace,first.digest,'--key-version','3',...absentReceipt.options)
  assert.equal(noArchivedKey.providerEvidence.archiveBinding,'not_comparable')
  assert.equal(noArchivedKey.backupErasure,'unverified')
  const dumpRows=docker('pg_restore',['--data-only','--schema=sectalk_private','--table=st_v7_tenant_key_versions','--file=-'],first.dump,'utf8')
  const archivedKey=dumpRows.split(/\r?\n/).find(line=>line.startsWith(workspace+'\t')).split('\t')[4]
  assert.deepEqual(await openTenantRecord({workspace,version:1,custody:'managed',ref:null,wrapped:archivedKey},channel,post,actor,sealed),plaintext)

  const newer=await capture(after)
  const current=audit(after,workspace,newer.digest)
  assert.equal(current.finding,'no_listed_key_records')
  assert.equal(current.backupErasure,'unverified')
  assert.equal(current.sourceDeletion,'unverified')
  assert.equal(current.providerDeletion,'unverified')
  assert.deepEqual(current.keyState,{currentVersion:1,destructionRecorded:true})
  assert.throws(()=>audit(after,workspace,first.digest),{stderr:/does not match the independent digest/})
  await writeFile(join(after,filenames[1]),'changed inventory')
  assert.throws(()=>audit(after,workspace,newer.digest),{stderr:/inventory failed its integrity check/})
  await writeFile(join(after,filenames[1]),'\n')
  const corrupted=Buffer.from(await readFile(join(after,filenames[0])))
  corrupted[corrupted.length-1]^=1
  await writeFile(join(after,filenames[0]),corrupted)
  assert.throws(()=>audit(after,workspace,newer.digest),{stderr:/integrity check|inspect the archive key tables/})
  sql(`update sectalk_private.st_v7_tenant_key_versions set provider_ref='stale' where workspace='${externalWorkspace}' and version=1;`)
  const invalid=await capture(after)
  assert.throws(()=>audit(after,externalWorkspace,invalid.digest,'--key-version','1','--provider-pin='+firstPin),
    {stderr:/binding does not match the selected workspace and version/})
  console.log('Verified backup key recovery, exact provider evidence correlation, mismatched and missing keys, tamper rejection and archive checksums.')
} finally {
  if(created)docker('dropdb',['-U','postgres',database])
  for(const root of [before,after]) {
    for(const file of filenames)await unlink(join(root,file)).catch(error=>{if(error.code!=='ENOENT')throw error})
    for(const item of [join(root,'objects'),root])await rmdir(item).catch(error=>{if(error.code!=='ENOENT')throw error})
  }
  await unlink(providerFile).catch(error=>{if(error.code!=='ENOENT')throw error})
  await rmdir(directory)
}
