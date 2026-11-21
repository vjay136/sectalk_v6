import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join,resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {createClient} from '@supabase/supabase-js'

const source='http://127.0.0.1:56821',target='http://127.0.0.1:56921'
const document='sectalk-vault'
const directory=await mkdtemp(join(tmpdir(),'sectalk-full-recovery-'))
const archive=join(directory,'generation')
const assertions=join(directory,'assertions.sql')
const script=fileURLToPath(new URL('../scripts/supabase-recovery.mjs',import.meta.url))
const clientOptions={auth:{persistSession:false,autoRefreshToken:false}}
let cleanupClient
let filename
const sourceUsers=[]

function keys(project,endpoint) {
  const output=execFileSync(process.env.SECTALK_DR_QA_CLI,['status','-o','env'],{
    cwd:resolve('supabase/.temp/'+project),encoding:'utf8',windowsHide:true,stdio:['ignore','pipe','ignore']})
  const env=Object.fromEntries([...output.matchAll(/^([A-Z_]+)="([^"\r\n]+)"/gm)].map(match=>match.slice(1,3)))
  assert.equal(env.API_URL,endpoint)
  const service=env.SECRET_KEY??env.SERVICE_ROLE_KEY
  const publishable=env.PUBLISHABLE_KEY??env.ANON_KEY
  assert.ok(service&&publishable)
  return {service,publishable}
}
function value(result) {if(result.error)throw result.error;return result.data}
async function person(keys,label) {
  const sourceAdmin=createClient(source,keys.service,clientOptions)
  const handle=label+randomUUID().slice(0,8)
  const email=handle+'@example.invalid',password=randomUUID()+'!Aa4'
  const {user}=value(await sourceAdmin.auth.admin.createUser({email,password,email_confirm:true}))
  sourceUsers.push(user.id)
  const client=createClient(source,keys.publishable,clientOptions)
  value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:handle,p_name:'DR synthetic '+label}))
  return {id:user.id,email,password,client}
}

try {
  const sourceKeys=keys('sectalk-dr-source',source),targetKeys=keys('sectalk-dr-target',target)
  cleanupClient=createClient(source,sourceKeys.service,clientOptions)
  const existing=Number(execFileSync('docker',['exec','supabase_db_sectalk-dr-source','psql','-X','-qAt',
    '-U','postgres','-d','postgres','-c',"select count(*) from storage.objects where bucket_id='sectalk-vault';"],{encoding:'utf8'}).trim())
  const owner=await person(sourceKeys,'drowner'), outsider=await person(sourceKeys,'droutsider')
  const workspace=value(await owner.client.rpc('st_v2_create_workspace',{p_name:'Restored workspace'}))
  filename=owner.id+'/'+randomUUID()+'.stvault'
  const payload=Buffer.from('Independent database, identity, object and policy recovery.')
  value(await owner.client.storage.from(document).upload(filename,payload,{contentType:'application/octet-stream',upsert:false}))
  const receipt=JSON.parse(execFileSync('docker',['exec','supabase_db_sectalk-dr-source','psql','-X','-qAt',
    '-U','postgres','-d','postgres','-c','select sectalk_private.st_v8_audit_checkpoint();'],{encoding:'utf8'}))
  assert.match(receipt.entry,/^\d+$/)
  assert.match(receipt.sha256,/^[a-f0-9]{64}$/)
  await writeFile(assertions,`
    do $$ begin
      if not exists(select from public.st_v2_workspace_audit where workspace_id='${workspace}' and actor='${owner.id}' and event='workspace.created') or
         not has_table_privilege('authenticated','public.st_v2_workspace_audit','SELECT') or
         has_table_privilege('anon','public.st_v2_workspace_audit','SELECT') or
         not exists(select from storage.objects where bucket_id='${document}' and name='${filename}' and owner_id='${owner.id}') or
         not has_function_privilege('sectalk_audit_anchor_reader','sectalk_private.st_v8_audit_checkpoint(text,text)','EXECUTE') or
         (sectalk_private.st_v8_audit_checkpoint('${receipt.entry}','${receipt.sha256}')->>'sha256') is distinct from '${receipt.sha256}'
      then raise exception 'Recovered source audit, grants or Storage ownership diverged'; end if;
    end $$;`)
  const env={...process.env,SECTALK_DR_SYNTHETIC_LOCAL:'yes',SECTALK_DR_SOURCE_FROZEN:'yes',
    SECTALK_DR_SOURCE_API:source,SECTALK_DR_SOURCE_SERVICE:sourceKeys.service,
    SECTALK_DR_TARGET_API:target,SECTALK_DR_TARGET_SERVICE:targetKeys.service,SECTALK_DR_TARGET_PUBLISHABLE:targetKeys.publishable,
    SECTALK_DR_CANARY_BUCKET:document,SECTALK_DR_CANARY_OBJECT:filename,SECTALK_DR_CANARY_WORKSPACE:workspace,
    SECTALK_DR_CANARY_OWNER_ID:owner.id,SECTALK_DR_CANARY_OWNER_EMAIL:owner.email,SECTALK_DR_CANARY_OWNER_PASSWORD:owner.password,
    SECTALK_DR_CANARY_OUTSIDER_ID:outsider.id,SECTALK_DR_CANARY_OUTSIDER_EMAIL:outsider.email,SECTALK_DR_CANARY_OUTSIDER_PASSWORD:outsider.password}
  const invoke=(mode,...options)=>execFileSync(process.execPath,[script,mode,'--archive',archive,...options],{
    env,encoding:'utf8',windowsHide:true,timeout:180000})
  assert.equal(JSON.parse(invoke('capture','--source-container','supabase_db_sectalk-dr-source')).objects,existing+1)
  const manifest=JSON.parse(await readFile(join(archive,'project-manifest.json'),'utf8'))
  assert.equal(manifest.sourceOrigin,source)
  const archived=join(archive,'project.pgdump')
  const bytes=await readFile(archived)
  const tampered=Buffer.from(bytes)
  tampered[0]^=1
  await writeFile(archived,tampered)
  assert.throws(()=>invoke('verify','--target-container','supabase_db_sectalk-dr-target','--assert',assertions),
    {stderr:/artifact failed its integrity check/})
  await writeFile(archived,bytes)
  const result=JSON.parse(invoke('verify','--target-container','supabase_db_sectalk-dr-target','--assert',assertions))
  assert.deepEqual(result.checks,['database','schema_grants','auth','storage','audit'])
  const restored=createClient(target,targetKeys.publishable,clientOptions)
  value(await restored.auth.signInWithPassword({email:owner.email,password:owner.password}))
  const recovered=value(await restored.storage.from(document).download(filename))
  assert.deepEqual(Buffer.from(await recovered.arrayBuffer()),payload)
  assert.throws(()=>invoke('verify','--target-container','supabase_db_sectalk-dr-target','--assert',assertions),{stderr:/contains Auth users or Storage data/})
  console.log('Verified PostgreSQL data, Auth sign-ins, private bytes and ownership, audit/RLS grants, and populated-target refusal in separate local projects.')
} finally {
  if (filename) await cleanupClient.storage.from(document).remove([filename])
  for (const user of sourceUsers) await cleanupClient.auth.admin.deleteUser(user)
  await rm(directory,{recursive:true,force:true})
}
