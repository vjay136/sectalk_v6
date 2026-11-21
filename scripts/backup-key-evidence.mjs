import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { createReadStream } from 'node:fs'
import { lstat,readFile,realpath } from 'node:fs/promises'
import { isAbsolute,relative,resolve,sep } from 'node:path'
import { createInterface } from 'node:readline'
import { pipeline } from 'node:stream/promises'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

const expectedTables={st_v7_tenant_key_state:['workspace','current_version','destroyed_at'],
  st_v7_tenant_key_versions:['workspace','version','custody','provider_ref','wrapped','created_at']}
const digestPattern=/^[a-f0-9]{64}$/
const uuidPattern=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/
const externalMarker=/^external_v2_([A-Za-z0-9_-]{43})_([A-Za-z0-9_-]{43})$/
const pinPattern=/^[A-Za-z0-9_-]{43}$/
const versionPattern=/^[1-9][0-9]{0,9}$/
const archiveFiles=['project.pgdump','private-inventory.jsonl','objects/storage-manifest.json']

function requireValue(condition,message) { if(!condition)throw new Error(message) }

async function archiveFile(root,name) {
  const path=resolve(root,name)
  requireValue(await realpath(path)===path && (await lstat(path)).isFile(),'Use regular files in the selected archive generation.')
  return path
}

async function checksum(path) {
  const hash=createHash('sha256')
  for await (const part of createReadStream(path)) hash.update(part)
  return hash.digest('hex')
}

async function readProviderEvidence(path,expectedDigest,workspace,version) {
  const file=await lstat(path)
  requireValue(file.isFile() && file.size<=8192,'Use a regular provider evidence file of at most 8192 bytes.')
  const raw=await readFile(path)
  requireValue(raw.length<=8192 && createHash('sha256').update(raw).digest('hex')===expectedDigest,
    'The provider evidence does not match the independent digest.')
  const evidence=JSON.parse(raw.toString('utf8'))
  requireValue(evidence?.format==='sectalk-provider-key-evidence-v1' && evidence.workspace===workspace && evidence.version===version &&
    digestPattern.test(evidence.eventSha256??'') && digestPattern.test(evidence.pinCommitment??'') &&
    typeof evidence.eventTime==='string' && typeof evidence.recordedAt==='string' &&
    Number.isFinite(Date.parse(evidence.eventTime)) && Number.isFinite(Date.parse(evidence.recordedAt)) &&
    Date.parse(evidence.eventTime)<=Date.parse(evidence.recordedAt)+30_000,
  'Provider evidence is invalid or belongs to a different workspace or key version.')
  return {receiptSha256:expectedDigest,eventSha256:evidence.eventSha256,eventTime:evidence.eventTime,pinCommitment:evidence.pinCommitment}
}

async function takeInventory(dump,digest,workspace,container,version,expectedPin,providerEvidence) {
  const flags=['--data-only','--schema=sectalk_private','--file=-',...Object.keys(expectedTables).map(table=>'--table='+table)]
  const child=container ? spawn('docker',['exec','-i',container,'pg_restore',...flags],{stdio:['pipe','pipe','ignore'],windowsHide:true}) :
    spawn('pg_restore',flags,{stdio:['pipe','pipe','ignore'],windowsHide:true})
  const completion=new Promise((success,failure)=>{
    child.on('error',()=>failure(new Error('Could not start a compatible pg_restore.')))
    child.on('close',code=>code===0 ? success() : failure(new Error('Could not inspect the archive key tables.')))
  })
  const hash=createHash('sha256')
  const supply=pipeline(createReadStream(dump),async function*(chunks){
    for await (const chunk of chunks) { hash.update(chunk);yield chunk }
  },child.stdin)
  const rows=(async()=>{
    const lines=createInterface({input:child.stdout,crlfDelay:Infinity})
    const seen=new Set(), versions=new Set()
    const retained={managedWrappedKeys:0,externalKeyReferences:0,legacyExternalEnvelopes:0}
    let table,columns,keyState=null,exactKey=null
    try {
      for await (const line of lines) {
        requireValue(line.length<=8192,'An archived key row has an unexpected format.')
        if(!table) {
          const block=/^COPY sectalk_private\.(st_v7_tenant_key_state|st_v7_tenant_key_versions) \(([^)]+)\) FROM stdin;$/.exec(line)
          if(!block) {
            requireValue(!/^\s*(?:COPY|INSERT INTO)\s/i.test(line),'An archived key table uses an unsupported data format.')
            continue
          }
          const names=block[2].split(', ')
          requireValue(!seen.has(block[1]) && names.length===expectedTables[block[1]].length &&
            expectedTables[block[1]].every(name=>names.includes(name)),'Archived key columns differ from the supported format.')
          table=block[1]
          columns=names
          continue
        }
        if(line==='\\.') { seen.add(table);table=undefined;continue }
        const parts=line.split('\t')
        requireValue(parts.length===columns.length && uuidPattern.test(parts[columns.indexOf('workspace')]),'An archived key row is invalid.')
        if(parts[columns.indexOf('workspace')]!==workspace)continue
        const fields=Object.fromEntries(columns.map((name,index)=>[name,parts[index]]))
        if(table==='st_v7_tenant_key_state') {
          requireValue(!keyState && /^[1-9][0-9]*$/.test(fields.current_version),'Archived key state is inconsistent.')
          keyState={currentVersion:Number(fields.current_version),destructionRecorded:fields.destroyed_at!=='\\N'}
          continue
        }
        requireValue(/^[1-9][0-9]*$/.test(fields.version) && !versions.has(fields.version) &&
          /^[A-Za-z0-9_-]{40,2048}$/.test(fields.wrapped) && ['managed','byok'].includes(fields.custody),
        'An archived key version is invalid.')
        versions.add(fields.version)
        const marker=fields.custody==='byok' ? externalMarker.exec(fields.wrapped) : null
        if(fields.custody==='managed')retained.managedWrappedKeys++
        else if(marker)retained.externalKeyReferences++
        else retained.legacyExternalEnvelopes++
        if(Number(fields.version)===version) {
          if(marker) {
            const [,pin,binding]=marker
            const expectedBinding=createHash('sha256').update(JSON.stringify([
              'sectalk/external-key/v2',pin,workspace,version,fields.provider_ref,
            ])).digest('base64url')
            requireValue(/^[A-Za-z0-9_-]{1,96}$/.test(fields.provider_ref) && binding===expectedBinding,
              'The archived external key binding does not match the selected workspace and version.')
          }
          let providerPinMatch=null
          if(marker && providerEvidence) {
            const commitment=createHash('sha256').update('sectalk-provider-pin-commitment-v1:'+workspace+':'+version+':'+marker[1]).digest('hex')
            providerPinMatch=commitment===providerEvidence.pinCommitment
          } else if(marker && expectedPin) providerPinMatch=marker[1]===expectedPin
          exactKey={record:fields.custody==='managed' ? 'managed_wrapped' : marker ? 'external_reference' : 'legacy_external_envelope',
            ...((expectedPin || providerEvidence) && {providerPinMatch})}
        }
      }
      requireValue(!table && seen.size===Object.keys(expectedTables).length,'The archive omits required key data tables.')
      return {keyState,retained,...(version && {exactKey:{version,...(exactKey ?? {record:'absent',
        ...((expectedPin || providerEvidence) && {providerPinMatch:null})})}})}
    } catch(error) {child.kill();throw error}
    finally {lines.close()}
  })()
  const [tool,input,result]=await Promise.allSettled([completion,supply,rows])
  if(result.status==='rejected')throw result.reason
  if(tool.status==='rejected')throw tool.reason
  requireValue(input.status==='fulfilled' && hash.digest('hex')===digest,'The inspected database archive failed its integrity check.')
  return result.value
}

try {
  const {values}=parseArgs({options:{archive:{type:'string'},workspace:{type:'string'},'manifest-sha256':{type:'string'},
    'pg-restore-container':{type:'string'},'key-version':{type:'string'},'provider-pin':{type:'string'},
    'provider-evidence':{type:'string'},'provider-evidence-sha256':{type:'string'}}})
  const manifestSha256=values['manifest-sha256'], workspace=values.workspace, container=values['pg-restore-container']
  const rawVersion=values['key-version'], version=rawVersion===undefined ? undefined : Number(rawVersion)
  const expectedPin=values['provider-pin']
  const evidencePath=values['provider-evidence'], evidenceDigest=values['provider-evidence-sha256']
  requireValue(values.archive && uuidPattern.test(workspace??'') && digestPattern.test(manifestSha256??''),
    'Choose a backup generation, exact workspace UUID and independently recorded manifest SHA-256.')
  requireValue(rawVersion===undefined || (versionPattern.test(rawVersion) && version<=2147483647),
    'Choose a positive PostgreSQL integer key version.')
  requireValue(expectedPin===undefined || (version!==undefined && pinPattern.test(expectedPin)),
    'A provider pin must be a 43-character base64url digest and requires an exact key version.')
  requireValue((evidencePath===undefined && evidenceDigest===undefined) ||
    (evidencePath && version!==undefined && digestPattern.test(evidenceDigest??'') && expectedPin===undefined),
  'Use the provider evidence file, independent receipt SHA-256, and exact key version together.')
  const providerEvidence=evidencePath ? await readProviderEvidence(evidencePath,evidenceDigest,workspace,version) : null
  requireValue(!container || /^supabase_db_sectalk-dr-[a-z0-9-]{1,32}$/.test(container) ||
    container==='supabase_db_v4-auth-qa'&&process.env.SECTALK_DR_SYNTHETIC_LOCAL==='yes',
  'Use a dedicated disposable recovery tool container.')
  const root=await realpath(values.archive)
  const repository=await realpath(fileURLToPath(new URL('../',import.meta.url)))
  const outside=relative(repository,root)
  requireValue(outside && (isAbsolute(outside)||outside==='..'||outside.startsWith('..'+sep)),
    'Use a protected archive path outside the source checkout.')
  const manifestPath=await archiveFile(root,'project-manifest.json')
  requireValue((await lstat(manifestPath)).size<=16384,'The recovery manifest exceeds its size limit.')
  const raw=await readFile(manifestPath)
  requireValue(createHash('sha256').update(raw).digest('hex')===manifestSha256,'The archive manifest does not match the independent digest.')
  const manifest=JSON.parse(raw.toString('utf8'))
  requireValue(manifest?.version===1 && typeof manifest.capturedAt==='string' && Number.isFinite(Date.parse(manifest.capturedAt)) &&
    archiveFiles.every(file=>digestPattern.test(manifest.files?.[file]??'')),'The archive manifest is incomplete or unsupported.')
  for (const file of archiveFiles.slice(1)) {
    requireValue(await checksum(await archiveFile(root,file))===manifest.files[file],'A recovery inventory failed its integrity check.')
  }
  const postgresSha256=manifest.files['project.pgdump']
  const {keyState,retained,exactKey}=await takeInventory(await archiveFile(root,'project.pgdump'),postgresSha256,
    workspace,container,version,expectedPin,providerEvidence)
  const finding=retained.managedWrappedKeys ? 'wrapped_managed_keys_retained' :
    retained.externalKeyReferences || retained.legacyExternalEnvelopes ? 'external_key_records_retained' : 'no_listed_key_records'
  console.log(JSON.stringify({format:'sectalk-backup-key-evidence-v1',workspace,capturedAt:manifest.capturedAt,
    manifestSha256,postgresSha256,keyState,retained,finding,...(exactKey && {exactKey}),
    ...(providerEvidence && {providerEvidence:{receiptSha256:providerEvidence.receiptSha256,eventSha256:providerEvidence.eventSha256,
      eventTime:providerEvidence.eventTime,record:'independent_provider_receipt',
      archiveBinding:exactKey.providerPinMatch===null?'not_comparable':exactKey.providerPinMatch?'matches':'differs'}}),
    sourceDeletion:'unverified',providerDeletion:'unverified',backupErasure:'unverified'}))
} catch(error) {
  console.error(error?.code || error instanceof SyntaxError ? 'The backup evidence check could not read its trusted input.' : error.message)
  process.exitCode=1
}
