import assert from 'node:assert/strict'
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto'
import { execFileSync, spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { resolve, sep } from 'node:path'
import { setTimeout as wait } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(backend.origin,'http://127.0.0.1:55321')
const app=new URL('http://127.0.0.1:3586')
const appDir=resolve(process.env.SECTALK_TEST_BUILT_APP)
const disposable=resolve('supabase/.temp')+sep
assert.ok(appDir.startsWith(disposable),'Use an isolated local production build.')
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const service=createClient(backend.origin,serviceKey,options)
const password=randomUUID()+'!aA1'
const suffix=randomUUID().slice(0,8)
const reference='fixture-v2'
const keyId='fixture/immutable/'+suffix
const credential=randomBytes(32).toString('base64url')
const nextReference='fixture-v2-rotation'
const nextKeyId='fixture/immutable/rotation/'+suffix
const keys=new Map([
  [reference,{id:keyId,root:randomBytes(32)}],
  [nextReference,{id:nextKeyId,root:randomBytes(32)}],
])
let browser, child, owner, workspace
const assertions=[]
function data(item){if(item.error)throw item.error;return item.data}
function sql(statement){
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input:statement,windowsHide:true,encoding:'utf8'}).trim()
}
const provider=createServer(async(request,response)=>{
  try{
    if(request.url!=='/v1/tenant-dek'||request.headers.authorization!=='Bearer '+credential)
      return response.writeHead(403).end()
    const chunks=[]
    for await(const chunk of request)chunks.push(chunk)
    const input=JSON.parse(Buffer.concat(chunks).toString())
    const {operation,context,value,keyId}=input
    assert.equal(input.workspace,workspace)
    const providerKey=keys.get(input.reference)
    if(!providerKey||providerKey.id!==keyId)return response.writeHead(403).end()
    const aad=Buffer.from(context)
    const bytes=Buffer.from(value,'base64url')
    let result
    if(operation==='wrap'){
      assert.equal(bytes.length,32)
      const nonce=randomBytes(12)
      const cipher=createCipheriv('aes-256-gcm',providerKey.root,nonce).setAAD(aad)
      const body=Buffer.concat([cipher.update(bytes),cipher.final()])
      result=Buffer.concat([Buffer.from('mock-kms'),nonce,cipher.getAuthTag(),body])
    }else{
      assert.equal(operation,'unwrap')
      assert.equal(bytes.subarray(0,8).toString(),'mock-kms')
      const decipher=createDecipheriv('aes-256-gcm',providerKey.root,bytes.subarray(8,20)).setAAD(aad).setAuthTag(bytes.subarray(20,36))
      result=Buffer.concat([decipher.update(bytes.subarray(36)),decipher.final()])
    }
    assertions.push(operation)
    response.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({keyId,context,value:result.toString('base64url')}))
  }catch{response.writeHead(403).end()}
})
await new Promise(resolve=>provider.listen(0,'127.0.0.1',resolve))
async function start(active){
  if(child){
    const stopped=once(child,'exit')
    child.kill()
    await stopped
  }
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','-H','127.0.0.1','-p','3586'],
    {cwd:appDir,windowsHide:true,stdio:'ignore',env:{...process.env,NEXT_PUBLIC_SUPABASE_URL:backend.origin,
      NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,SECTALK_FILE_STORAGE_KEY:serviceKey,SECTALK_APP_URL:app.origin,
      SECTALK_EXTERNAL_KMS_URL:'http://127.0.0.1:'+provider.address().port+'/v1/tenant-dek',
      SECTALK_EXTERNAL_KMS_TOKEN:credential,
      SECTALK_EXTERNAL_KMS_KEYS:JSON.stringify({[workspace]:{active,keys:{[reference]:keyId,[nextReference]:nextKeyId}}}),
    }})
  let ready=false
  for(let attempt=0;attempt<40&&!ready;attempt++){
    ready=(await fetch(app).catch(()=>null))?.ok===true
    if(!ready)await wait(500)
  }
  assert.equal(ready,true,'Isolated app did not become ready')
}
try{
  const handle='kms_'+suffix, email=handle+'@example.invalid'
  owner=data(await service.auth.admin.createUser({email,password,email_confirm:true})).user.id
  const client=createClient(backend.origin,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Synthetic KMS owner'}))
  sql("insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('"+owner+"','enterprise','active',now()+interval '1 day');")
  workspace=data(await client.rpc('st_v2_create_workspace',{p_name:'External custody '+suffix}))
  await start(reference)
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  const btn=(scope,name)=>scope.getByRole('button',{name,exact:true})
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await btn(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  const sections=page.getByRole('group',{name:'Workspace sections'})
  await btn(sections,'Compliance exports').click()
  await verifyStaffPanel(page)
  const custody=page.getByRole('region',{name:'Managed artifact keys',exact:true})
  await custody.getByRole('combobox',{name:'Key custody',exact:true}).selectOption('byok')
  await custody.getByLabel('Key rotation reason').fill('Activate the approved synthetic external key')
  await btn(custody,'Create workspace key').click()
  await custody.getByText('Workspace key version 1 is active.',{exact:true}).waitFor()
  assert.equal(sql("select (wrapped like 'external_v2_%' and char_length(wrapped)=99 and provider_ref='"+reference+"')::int from sectalk_private.st_v7_tenant_key_versions where workspace='"+workspace+"';"),'1')
  await btn(sections,'Channels').click()
  await page.getByText('New channel encryption policy',{exact:true}).click()
  const policy=page.getByRole('region',{name:'New channel encryption policy',exact:true})
  await btn(policy,'Enable managed encryption for new channels').click()
  await policy.getByText('New channels use managed encryption.',{exact:true}).waitFor()
  await page.getByText('New channel',{exact:true}).click()
  await page.getByLabel('Channel name',{exact:true}).fill('external-'+suffix)
  await btn(page,'Create channel').click()
  await page.getByRole('heading',{name:'Managed encryption',exact:true}).waitFor()
  const channel=await page.getByLabel('Channel',{exact:true}).inputValue()
  const plaintext='Synthetic managed message '+suffix
  await page.getByLabel('Channel message',{exact:true}).fill(plaintext)
  const sent=page.waitForResponse(response=>response.url().endsWith('/api/managed-channel/'+channel)&&response.request().method()==='POST')
  await btn(page,'Send message').click()
  const published=await sent
  assert.equal(published.status(),204,published.ok()?'':await published.text())
  await page.getByRole('log',{name:'Channel messages'}).getByText(plaintext,{exact:true}).waitFor()
  const ciphertextSql="select (char_length(wrapped_dek)>80 and key_version=1)::int from sectalk_private.st_v8_channel_payloads e join public.st_v2_posts p on p.id=e.post where p.channel_id='"+channel+"';"
  assert.equal(sql(ciphertextSql),'1')
  const nativeAuthorization=(await published.request().allHeaders()).authorization
  await start(nextReference)
  await page.reload()
  await btn(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await btn(sections,'Compliance exports').click()
  await custody.getByRole('combobox',{name:'Key custody',exact:true}).selectOption('byok')
  await custody.getByLabel('Key rotation reason').fill('Rotate to the separately pinned synthetic key')
  await btn(custody,'Rotate workspace key').click()
  await custody.getByText('Workspace key version 2 is active.',{exact:true}).waitFor()
  assert.equal(sql("select provider_ref from sectalk_private.st_v7_tenant_key_versions where workspace='"+workspace+"' and version=2;"),nextReference)
  const oldRecord=()=>fetch(new URL('/api/managed-channel/'+channel,app),{headers:{Authorization:nativeAuthorization}})
  assert.equal((await oldRecord()).status,200)
  keys.get(reference).root.fill(0)
  keys.delete(reference)
  const read=await fetch(new URL('/api/managed-channel/'+channel,app),{headers:{Authorization:nativeAuthorization}})
  assert.equal(read.status,503)
  assert.equal(sql(ciphertextSql),'1')
  assert.ok(assertions.includes('wrap')&&assertions.includes('unwrap'))
  console.log('Passed Edge owner TOTP, external activation and rotation, older managed reads before synthetic key loss, and preserved ciphertext after loss.')
}finally{
  await browser?.close()
  child?.kill()
  await new Promise(resolve=>provider.close(resolve))
}
