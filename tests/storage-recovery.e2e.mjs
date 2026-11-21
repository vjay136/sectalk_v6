import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {mkdtemp,readFile,readdir,rmdir,unlink,writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {createClient} from '@supabase/supabase-js'

const bucket='sectalk-vault'
const source='http://127.0.0.1:55321'
const target='http://127.0.0.1:56121'
const sourceKey=process.env.SECTALK_DR_TEST_SOURCE_SERVICE
const targetKey=process.env.SECTALK_DR_TEST_TARGET_SERVICE
const targetPublic=process.env.SECTALK_DR_TEST_TARGET_PUBLISHABLE
const directory=await mkdtemp(join(tmpdir(),'sectalk-dr-storage-'))
const archive=join(directory,'archive')
const inventoryPath=join(directory,'private-inventory.jsonl')
const script=fileURLToPath(new URL('../scripts/storage-recovery.mjs',import.meta.url))
const inventorySql=new URL('../scripts/storage-recovery-inventory.sql',import.meta.url)
const options={auth:{persistSession:false,autoRefreshToken:false}}
const sourceAdmin=createClient(source,sourceKey,options)
const targetAdmin=createClient(target,targetKey,options)
const owner=createClient(target,targetPublic,options)
const outsider=createClient(target,targetPublic,options)
const ownerEmail='storage-restore-'+randomUUID()+'@example.invalid'
const password=randomUUID()+'!5a'
const targetUsers=[]
const filenames=[]

function data(result){if(result.error)throw result.error;return result.data}
function run(mode,url,key){
  const args=[script,mode,'--archive',archive]
  if(mode==='backup')args.push('--inventory',inventoryPath)
  return JSON.parse(execFileSync(process.execPath,args,{env:{...process.env,
    SECTALK_DR_STORAGE_URL:url,SECTALK_DR_STORAGE_KEY:key},encoding:'utf8',windowsHide:true,timeout:30000}))
}

try{
  const {user}=data(await targetAdmin.auth.admin.createUser({email:ownerEmail,password,email_confirm:true}))
  targetUsers.push(user.id)
  const extra=data(await targetAdmin.auth.admin.createUser({email:'outsider-'+ownerEmail,password,email_confirm:true})).user
  targetUsers.push(extra.id)
  data(await owner.auth.signInWithPassword({email:ownerEmail,password}))
  data(await outsider.auth.signInWithPassword({email:extra.email,password}))
  const contents=[Buffer.from('Synthetic standalone private payload'),Buffer.from('Another private recovery object')]
  for(const bytes of contents){
    const filename=`${user.id}/${randomUUID()}.stvault`
    filenames.push(filename)
    data(await sourceAdmin.storage.from(bucket).upload(filename,bytes,{contentType:'application/octet-stream',upsert:false}))
  }
  const query=(await readFile(inventorySql,'utf8')).replace(/\border by\b/,`and o.name in (${filenames.map(name=>"'"+name+"'").join(',')})\norder by`)
  const inventory=execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-A','-t','-q',
    '-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{input:query,encoding:'utf8',windowsHide:true})
  assert.equal(inventory.trim().split(/\r?\n/).length,2)
  await writeFile(inventoryPath,inventory)
  assert.equal(run('backup',source,sourceKey).objects,2)
  assert.equal(run('verify',undefined,undefined).status,'storage_archive_verified')
  assert.throws(()=>run('restore','https://recovery.invalid',targetKey),{stderr:/dedicated loopback/})
  assert.deepEqual(run('restore',target,targetKey),{status:'storage_restore_verified',objects:2,reused:0})
  assert.equal(run('restore',target,targetKey).reused,2)
  for(const [i,filename] of filenames.entries()){
    const recovered=data(await owner.storage.from(bucket).download(filename))
    assert.deepEqual(Buffer.from(await recovered.arrayBuffer()),contents[i])
    assert.ok((await outsider.storage.from(bucket).download(filename)).error)
  }
  const {objects}=JSON.parse(await readFile(join(archive,'storage-manifest.json'),'utf8'))
  const stored=join(archive,objects[0].objectId)
  const changed=await readFile(stored)
  changed[0]^=1
  await writeFile(stored,changed)
  assert.throws(()=>run('restore',target,targetKey),{stderr:/failed integrity verification/})
  console.log('Passed real private Storage backup, byte integrity, scoped recovery, idempotent replay and outsider denial.')
}finally{
  if(filenames.length)await Promise.allSettled([sourceAdmin.storage.from(bucket).remove(filenames),targetAdmin.storage.from(bucket).remove(filenames)])
  for(const actor of targetUsers)await targetAdmin.auth.admin.deleteUser(actor)
  for(const file of await readdir(archive).catch(()=>[]))await unlink(join(archive,file))
  await rmdir(archive).catch(()=>{})
  await unlink(inventoryPath).catch(()=>{})
  await rmdir(directory)
}
