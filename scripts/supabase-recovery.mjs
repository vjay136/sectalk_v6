import {createHash} from 'node:crypto'
import {spawn} from 'node:child_process'
import {createReadStream,createWriteStream} from 'node:fs'
import {lstat,mkdir,readFile,realpath,writeFile} from 'node:fs/promises'
import {basename,dirname,isAbsolute,join,relative,resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {PassThrough,Readable} from 'node:stream'
import {pipeline} from 'node:stream/promises'
import {parseArgs} from 'node:util'

const repository=await realpath(fileURLToPath(new URL('../',import.meta.url)))
const directory=dirname(fileURLToPath(import.meta.url))
const tableFilter="n.nspname in ('public','sectalk_private','auth') and c.relkind in ('r','p')"
const inventory=await readFile(join(directory,'storage-recovery-inventory.sql'),'utf8')

function requireValue(condition,message) {if (!condition) throw new Error(message)}

async function run(program,args,{input,output,env=process.env}={}) {
  const child=spawn(program,args,{stdio:['pipe','pipe','ignore'],windowsHide:true,env})
  const completed=new Promise((done,failed)=>{
    child.on('error',()=>failed(new Error('Could not start a recovery tool.')))
    child.on('close',code=>code===0?done():failed(new Error('A recovery tool failed.')))
  })
  let captured=''
  const receiving=output?pipeline(child.stdout,output):(async()=>{
    child.stdout.setEncoding('utf8')
    for await(const chunk of child.stdout) {
      captured+=chunk
      if (captured.length>16*1024*1024) {child.kill();throw new Error('Recovery metadata exceeded the supported limit.')}
    }
  })()
  child.stdin.on('error',()=>{})
  const sending=input&&typeof input!=='string'?pipeline(input,child.stdin):(child.stdin.end(input),Promise.resolve())
  const result=await Promise.allSettled([completed,receiving,sending])
  if (result.some(item=>item.status==='rejected')) throw new Error('A recovery tool failed to produce a complete artifact.')
  return captured.trim()
}
function pg(instance,program,parameters,io={}) {
  const args=['--no-password',...parameters]
  if (instance.service) {
    const env={...process.env,PGCONNECT_TIMEOUT:'10'}
    for (const key of Object.keys(env)) if (/^PG/i.test(key)&&!['PGSERVICEFILE','PGPASSFILE','PGCONNECT_TIMEOUT'].includes(key)) delete env[key]
    return run(program,['--dbname=service='+instance.service,...args],{...io,env})
  }
  requireValue(/^supabase_db_sectalk-dr-[a-z0-9-]{1,32}$/.test(instance.container),'Choose an explicitly disposable Supabase database container.')
  const socket=program==='pg_restore'&&parameters.includes('--file=-')?[]:
    ['--dbname=postgres','--username='+(instance.restore?'supabase_admin':'postgres')]
  return run('docker',['exec','-i',instance.container,program,...socket,...args],io)
}
const psql=(instance,input)=>pg(instance,'psql',['-X','-qAt','-v','ON_ERROR_STOP=1','--file=-'],{input})
async function checksum(path) {
  const info=await lstat(path)
  requireValue(info.isFile(),'An archive artifact is not a regular file.')
  const hash=createHash('sha256')
  for await(const chunk of createReadStream(path))hash.update(chunk)
  return hash.digest('hex')
}
const textHash=value=>createHash('sha256').update(value).digest('hex')
const artifact=(path,name)=>join(path,name)
function storage(mode,path,endpoint,key) {
  const args=[join(directory,'storage-recovery.mjs'),mode,'--archive',artifact(path,'objects')]
  if (mode==='backup') args.push('--inventory',artifact(path,'private-inventory.jsonl'))
  return run(process.execPath,args,{env:{...process.env,SECTALK_DR_STORAGE_URL:endpoint,SECTALK_DR_STORAGE_KEY:key}})
}
function api(endpoint,key,path,options={}) {
  return fetch(new URL(path,endpoint),{...options,redirect:'error',signal:AbortSignal.timeout(15000),
    headers:{apikey:key,Authorization:'Bearer '+key,...options.headers}})
}
function checkedLoopback(raw) {
  const url=new URL(raw)
  requireValue(url.hostname==='127.0.0.1'&&url.protocol==='http:'&&url.port&&url.href===url.origin+'/','Require a dedicated HTTP loopback recovery API.')
  return url
}
async function checkProject(instance,raw,synthetic=false) {
  const endpoint=checkedLoopback(raw)
  const project=instance.container?.slice('supabase_db_'.length)
  const port=await run('docker',['port','supabase_kong_'+project,'8000/tcp'])
  requireValue(port.split(/\r?\n/).some(line=>line==='127.0.0.1:'+endpoint.port||
    (synthetic&&line==='0.0.0.0:'+endpoint.port)),
    'The loopback API does not match the disposable database project.')
  if (!synthetic) {
    const bindings=await run('docker',['port',instance.container])
    requireValue(bindings.split(/\r?\n/).filter(Boolean).every(line=>/ -> (127\.0\.0\.1|\[::1\]):[1-9][0-9]*$/.test(line)),
      'The disposable database publishes a port outside loopback.')
  }
}
async function schemaFingerprint(instance) {
  const sql=await pg(instance,'pg_dump',['--schema-only','--no-comments','--no-publications','--no-subscriptions',
    '--schema=public','--schema=sectalk_private','--schema=auth','--schema=storage'])
  return textHash(sql.replace(/^\\(?:un)?restrict .*$/gm,'').trim())
}
async function counts(instance) {
  return psql(instance,`
    select format('select %L || '':'' || count(*) from %I.%I;', n.nspname||'.'||c.relname,n.nspname,c.relname)
    from pg_class c join pg_namespace n on n.oid=c.relnamespace where ${tableFilter}
    order by n.nspname collate "C",c.relname collate "C";
    \\gexec`)
}
const sourceEnvironment={endpoint:process.env.SECTALK_DR_SOURCE_API,key:process.env.SECTALK_DR_SOURCE_SERVICE}
const targetEnvironment={endpoint:process.env.SECTALK_DR_TARGET_API,key:process.env.SECTALK_DR_TARGET_SERVICE,
  publicKey:process.env.SECTALK_DR_TARGET_PUBLISHABLE}

async function capture(path,source) {
  requireValue(process.env.SECTALK_DR_SOURCE_FROZEN==='yes','Pause source writers and confirm the capture window.')
  requireValue(sourceEnvironment.endpoint&&sourceEnvironment.key,'Configure the private source Storage credentials.')
  if (source.container) await checkProject(source,sourceEnvironment.endpoint,process.env.SECTALK_DR_SYNTHETIC_LOCAL==='yes')
  await mkdir(path,{mode:0o700})
  const before=await psql(source,inventory)
  const rowCounts=await counts(source)
  const schema=await schemaFingerprint(source)
  await writeFile(artifact(path,'private-inventory.jsonl'),before+'\n',{mode:0o600,flag:'wx'})
  await pg(source,'pg_dump',['--format=custom','--lock-wait-timeout=10000','--no-publications','--no-subscriptions',
    '--exclude-table-data=cron.job','--exclude-table-data=cron.job_run_details'],
  {output:createWriteStream(artifact(path,'project.pgdump'),{mode:0o600,flags:'wx'})})
  const objects=JSON.parse(await storage('backup',path,sourceEnvironment.endpoint,sourceEnvironment.key))
  requireValue(before===await psql(source,inventory)&&rowCounts===await counts(source)&&schema===await schemaFingerprint(source),
    'Source metadata changed during capture. Discard this incomplete generation and retry in a new directory.')
  const files={}
  for (const name of ['project.pgdump','private-inventory.jsonl','objects/storage-manifest.json']) files[name]=await checksum(artifact(path,name))
  const manifest={version:1,capturedAt:new Date().toISOString(),schema,counts:textHash(rowCounts),objects:objects.objects,files,
    sourceOrigin:new URL(sourceEnvironment.endpoint).origin,sourceContainer:source.container??null}
  await writeFile(artifact(path,'project-manifest.json'),JSON.stringify(manifest)+'\n',{mode:0o600,flag:'wx'})
  console.log(JSON.stringify({status:'project_backup_created',capturedAt:manifest.capturedAt,objects:manifest.objects}))
}

function comparable(value) {
  return value.split('\n').filter(Boolean).map(line=>{
    const {bucket,key,size,contentType,owner}=JSON.parse(line)
    return {bucket,key,size:Number(size),contentType,owner:owner??null}
  })
}
async function restoreData(target,path) {
  const stream=new PassThrough()
  const generate=pg(target,'pg_restore',['--data-only','--exit-on-error','--file=-',
    '--schema=public','--schema=sectalk_private','--schema=auth'],
    {input:createReadStream(artifact(path,'project.pgdump')),output:stream})
    .then(()=>true,()=>false)
  async function* transaction() {
    yield `begin; set local session_replication_role=replica;
      select format('delete from %I.%I;',n.nspname,c.relname) from pg_class c join pg_namespace n on n.oid=c.relnamespace
        where ${tableFilter} and not c.relispartition;
      \\gexec
    `
    for await(const chunk of stream) yield chunk
    requireValue(await generate,'The archive could not produce the application and Auth data stream.')
    yield '\ncommit;\n'
  }
  await psql(target,Readable.from(transaction()))
}
async function restore(path,target,assertions) {
  const started=Date.now()
  requireValue(targetEnvironment.endpoint&&targetEnvironment.key&&targetEnvironment.publicKey,'Configure the disposable QA API credentials.')
  requireValue(sourceEnvironment.endpoint!==targetEnvironment.endpoint,'Source and recovery API origins must differ.')
  const manifest=JSON.parse(await readFile(artifact(path,'project-manifest.json'),'utf8'))
  requireValue(manifest.version===1,'The generation is incomplete or unsupported.')
  requireValue(manifest.sourceOrigin!==new URL(targetEnvironment.endpoint).origin&&manifest.sourceContainer!==target.container,
    'The recovery target must differ from the archived source.')
  await checkProject(target,targetEnvironment.endpoint,Boolean(manifest.sourceContainer)&&process.env.SECTALK_DR_SYNTHETIC_LOCAL==='yes')
  for (const name of ['project.pgdump','private-inventory.jsonl','objects/storage-manifest.json'])
    requireValue(manifest.files[name]===await checksum(artifact(path,name)),'A generation artifact failed its integrity check.')
  await storage('verify',path)
  requireValue(await psql(target,"select not exists(select from auth.users) and not exists(select from storage.objects);")==='t',
    'The disposable project contains Auth users or Storage data.')
  requireValue(await schemaFingerprint(target)===manifest.schema,'The recovery project must have the same migrations, grants and policies.')
  const writer={...target,restore:true}
  requireValue(await psql(writer,'select rolsuper from pg_roles where rolname=current_user;')==='t',
    'The disposable target needs its local Supabase bootstrap administrator.')
  await restoreData(writer,path)
  requireValue(textHash(await counts(target))===manifest.counts,'Restored PostgreSQL and Auth row counts diverged.')
  const objects=JSON.parse(await storage('restore',path,targetEnvironment.endpoint,targetEnvironment.key))
  const original=comparable((await readFile(artifact(path,'private-inventory.jsonl'),'utf8')).trim())
  const patch=Buffer.from(JSON.stringify(original)).toString('hex')
  await psql(writer,`update storage.objects o set owner_id=r.owner, owner=case when r.owner~*'^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'
    then r.owner::uuid else null end
    from jsonb_to_recordset(convert_from(decode('${patch}','hex'),'UTF8')::jsonb) r(bucket text,key text,owner text)
    where o.bucket_id=r.bucket and o.name=r.key;`)
  const actual=comparable(await psql(target,inventory))
  requireValue(JSON.stringify(original)===JSON.stringify(actual),'Restored private Storage metadata diverged.')
  const sql=await readFile(assertions,'utf8')
  requireValue(sql.trim().length>0,'Provide trusted read-only audit and grant checks.')
  await psql(target,'begin read only;\n'+sql+'\nrollback;')
  await verifyAuth()
  console.log(JSON.stringify({status:'project_restore_verified',capturedAt:manifest.capturedAt,
    durationMs:Date.now()-started,objects:objects.objects,checks:['database','schema_grants','auth','storage','audit']}))
}

async function verifyAuth() {
  const {endpoint,publicKey}=targetEnvironment
  const bucket=process.env.SECTALK_DR_CANARY_BUCKET
  const path=process.env.SECTALK_DR_CANARY_OBJECT
  const workspace=process.env.SECTALK_DR_CANARY_WORKSPACE
  requireValue(/^sectalk-[a-z-]+$/.test(bucket??'')&&path&&path.split('/').every(part=>/^[A-Za-z0-9_.-]+$/.test(part)&&!['.','..'].includes(part)),
    'Provide a private, synthetic recovery canary object.')
  requireValue(/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(workspace??''),'Provide the restored audit canary workspace.')
  const objectPath='/storage/v1/object/authenticated/'+bucket+'/'+path.split('/').map(encodeURIComponent).join('/')
  for (const owner of [true,false]) {
    const prefix=owner?'SECTALK_DR_CANARY_OWNER_':'SECTALK_DR_CANARY_OUTSIDER_'
    const id=process.env[prefix+'ID'],email=process.env[prefix+'EMAIL'],password=process.env[prefix+'PASSWORD']
    requireValue(id&&email&&password,'Provide both restored QA identities.')
    const login=await api(endpoint,publicKey,'/auth/v1/token?grant_type=password',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})})
    requireValue(login.ok,'A recovered canary could not sign in.')
    const result=await login.json()
    requireValue(result.user?.id===id&&result.access_token,'The restored Auth identity did not match the recovery canary.')
    const object=await api(endpoint,publicKey,objectPath,{headers:{Authorization:'Bearer '+result.access_token}})
    await object.body?.cancel()
    requireValue(owner?object.ok:[400,401,403,404].includes(object.status),'Recovered private access controls did not match the canary.')
    const audit=await api(endpoint,publicKey,'/rest/v1/st_v2_workspace_audit?select=event&workspace_id=eq.'+workspace+'&event=eq.workspace.created',
      {headers:{Authorization:'Bearer '+result.access_token}})
    requireValue(audit.ok,'Recovered audit grants are unavailable.')
    const rows=await audit.json()
    requireValue(owner?rows.some(row=>row.event==='workspace.created'):rows.length===0,'Recovered audit policy did not match the canary.')
  }
}
try {
  const [mode,...args]=process.argv.slice(2)
  const {values}=parseArgs({args,options:{archive:{type:'string'},'source-service':{type:'string'},
    'source-container':{type:'string'},'target-container':{type:'string'},assert:{type:'string'}}})
  requireValue(['capture','verify'].includes(mode)&&values.archive,'Use capture or verify with an explicit protected --archive path.')
  const requested=resolve(values.archive)
  const parent=await realpath(dirname(requested))
  const relativePath=relative(repository,parent)
  requireValue(relativePath&&(isAbsolute(relativePath)||relativePath==='..'||relativePath.startsWith('..'+(process.platform==='win32'?'\\':'/'))),
    'Use a protected archive path outside the source checkout.')
  const path=join(parent,basename(requested))
  if (mode==='capture') {
    requireValue(Boolean(values['source-service'])!==Boolean(values['source-container'])&&
      (!values['source-service']||/^[A-Za-z0-9_-]{1,63}$/.test(values['source-service'])),'Choose one named backup source.')
    await capture(path,{service:values['source-service'],container:values['source-container']})
  } else {
    requireValue(values.assert&&values['target-container']&&values['target-container']!==values['source-container'],
      'Use trusted assertions and a separate disposable project.')
    await restore(path,{container:values['target-container']},values.assert)
  }
} catch(error) {
  console.error(error?.code||error instanceof SyntaxError?'The recovery generation could not read or write its inputs.':error.message)
  process.exitCode=1
}
