import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'
import {verifyStaffPanel} from './workspace-admin-fixture.mjs'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(backend.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const service=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const password=randomUUID()+'!5a'
const suffix=randomUUID().slice(0,8)
const actors=[]
let workspace
let liveReportUpdates=0

function data(result){if(result.error)throw result.error;return result.data}
function sql(statement){
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-q','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,windowsHide:true})
}

async function account(label){
  const handle=`ch_${label}_${suffix}`
  const email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  actors.push(user.id)
  const client=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label+' channel QA'}))
  return {id:user.id,client,handle,email}
}

const navigation=page=>page.getByRole('navigation',{name:'SecTalk features'})
async function login(actor) {
  const page=await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await navigation(page).getByRole('button',{name:'Workspaces',exact:true}).click()
  await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Channels',exact:true}).click()
  return page
}

try {
  const [owner,member,outsider]=await Promise.all(['owner','member','outside'].map(account))
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Managed channel synthetic '+suffix}))
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${member.id}','member');`)
  const legacy=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'standard-'+suffix}))
  const ownerPage=await login(owner)
  await ownerPage.getByText('New channel encryption policy',{exact:true}).click()
  const policy=ownerPage.getByRole('region',{name:'New channel encryption policy',exact:true})
  await verifyStaffPanel(policy)
  await policy.getByRole('button',{name:'Enable managed encryption for new channels',exact:true}).click()
  await policy.getByText('New channels use managed encryption.',{exact:true}).waitFor()

  await ownerPage.getByText('New channel',{exact:true}).click()
  await ownerPage.getByLabel('Channel name',{exact:true}).fill('managed-'+suffix)
  await ownerPage.getByRole('button',{name:'Create channel',exact:true}).click()
  await ownerPage.getByRole('heading',{name:'Managed encryption',exact:true}).waitFor()
  await ownerPage.getByText('Encryption mode · Server-managed encryption',{exact:true}).waitFor()
  const managed=await ownerPage.getByLabel('Channel',{exact:true}).inputValue()
  assert.match(managed,/^[0-9a-f-]{36}$/)
  await policy.getByRole('button',{name:'Use standard storage for new channels',exact:true}).click()
  await policy.getByText('New channels use standard workspace storage.',{exact:true}).waitFor()
  assert.equal(data(await member.client.from('st_v2_channels').select('encryption_mode').eq('id',managed).single()).encryption_mode,'managed')
  assert.equal(data(await member.client.from('st_v2_channels').select('encryption_mode').eq('id',legacy).single()).encryption_mode,'standard')
  await ownerPage.getByLabel('Channel',{exact:true}).selectOption(legacy)
  await ownerPage.getByText('Encryption mode · Standard workspace storage',{exact:true}).waitFor()

  const memberPage=await login(member)
  await memberPage.getByLabel('Channel',{exact:true}).selectOption(managed)
  await memberPage.getByRole('heading',{name:'Managed encryption',exact:true}).waitFor()
  const plaintext='Explicit synthetic channel message '+suffix
  await memberPage.getByLabel('Channel message',{exact:true}).fill(plaintext)
  const sent=memberPage.waitForResponse(response=>response.url().endsWith('/api/managed-channel/'+managed)
    && response.request().method()==='POST')
  await memberPage.getByRole('button',{name:'Send message',exact:true}).click()
  const response=await sent
  assert.equal(response.status(),204,response.ok()?'':await response.text())
  await memberPage.getByRole('log',{name:'Channel messages'}).getByText(plaintext,{exact:true}).waitFor()
  const post=data(await member.client.from('st_v2_posts').select('id,body').eq('channel_id',managed).single())
  assert.equal(post.body,'Managed encrypted message')
  const sealed=sql(`copy (select body from sectalk_private.st_v8_channel_payloads where post='${post.id}') to stdout;`).toString().trim()
  assert.ok(sealed.length>0)
  assert.notDeepEqual(Buffer.from(sealed,'base64url'),Buffer.from(plaintext))
  assert.equal((await member.client.rpc('st_v2_post',{p_channel:managed,p_id:randomUUID(),p_body:'Plaintext fallback'})).error?.code,'42501')
  assert.equal((await member.client.from('st_v8_channel_payloads').select('body')).error!==null,true)
  await ownerPage.getByLabel('Channel',{exact:true}).selectOption(managed)
  await ownerPage.getByRole('log',{name:'Channel messages'}).getByText(plaintext,{exact:true}).waitFor()
  await ownerPage.getByLabel('Search channel messages',{exact:true}).fill('synthetic channel')
  await ownerPage.getByRole('button',{name:'Search this channel',exact:true}).click()
  await ownerPage.getByRole('list',{name:'Managed channel search results',exact:true}).getByText(plaintext,{exact:true}).waitFor()

  const path='/api/managed-channel/'+managed
  const memberToken=data(await member.client.auth.getSession()).session.access_token
  const ownerToken=await ownerPage.evaluate(()=>{
    const key=Object.keys(localStorage).find(key=>/^sb-.+-auth-token$/.test(key))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
  const outsiderToken=data(await outsider.client.auth.getSession()).session.access_token
  const get=(token,supplied=path)=>fetch(new URL(supplied,app),{headers:{Authorization:'Bearer '+token}})
  assert.equal((await get(outsiderToken)).status,404)
  assert.equal((await get(memberToken,'/api/managed-channel/'+legacy)).status,404)
  assert.equal((await get(memberToken,'/api/managed-channel/'+randomUUID())).status,404)
  try {
    sql(`update sectalk_private.st_v8_channel_payloads set body='${sealed.startsWith('A')?'B':'A'}'||substr(body,2)
      where post='${post.id}';`)
    assert.equal((await get(memberToken)).status,503)
  } finally { sql(`update sectalk_private.st_v8_channel_payloads set body='${sealed}' where post='${post.id}';`) }
  assert.equal((await (await get(memberToken)).json())[0].body,plaintext)
  const search=(token,input)=>fetch(new URL(path,app),{method:'POST',
    headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(input)})
  for(let from=0;from<102;from+=6) {
    await Promise.all(Array.from({length:6},async(_,offset)=>{
      const index=from+offset
      const sent=await search(index%2?ownerToken:memberToken,{id:randomUUID(),body:'Later managed history fixture '+index})
      assert.equal(sent.status,204,sent.ok?'':await sent.text())
    }))
  }
  await memberPage.getByLabel('Search channel messages',{exact:true}).fill('synthetic channel')
  await memberPage.getByRole('button',{name:'Search this channel',exact:true}).click()
  const earlier=memberPage.getByRole('button',{name:'Search earlier messages',exact:true})
  await memberPage.getByText('No matches in this batch.',{exact:true}).waitFor()
  await earlier.click()
  await memberPage.getByText('No matches in this batch.',{exact:true}).waitFor()
  await earlier.click()
  await memberPage.getByRole('list',{name:'Managed channel search results',exact:true}).getByText(plaintext,{exact:true}).waitFor()
  assert.equal(await earlier.count(),0)
  const query={search:'synthetic channel'}
  const initial=await (await search(memberToken,query)).json()
  assert.deepEqual(initial.matches,[])
  assert.match(initial.next.beforeId,/^[a-f0-9-]{36}$/)
  sql(`delete from public.st_v2_members where (workspace_id,user_id)=('${workspace}','${member.id}');`)
  const denied=await search(memberToken,{...query,...initial.next})
  assert.equal(denied.status,404)
  const deniedBody=await denied.json()
  assert.deepEqual(deniedBody,{error:'Managed channel unavailable.'})
  assert.equal((await get(memberToken)).status,404)
  const normal=randomUUID()
  const verifiedOwner=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,
    {...options,global:{headers:{Authorization:'Bearer '+ownerToken}}})
  data(await verifiedOwner.rpc('st_v2_post',{p_channel:legacy,p_id:normal,p_body:'Legacy channel still works.'}))
  assert.equal(data(await verifiedOwner.from('st_v2_posts').select('body').eq('id',normal).single()).body,'Legacy channel still works.')
  console.log('Passed native creation policy, managed send/read, search beyond 100, cursor revocation, ciphertext, legacy compatibility, tamper rejection and outsider denial.')
} finally {
  await browser.close()
  if (workspace) sql(`delete from public.st_v2_workspaces where id='${workspace}';
    begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v7_tenant_key_audit where workspace='${workspace}'; commit;
    delete from sectalk_private.st_v7_tenant_key_versions where workspace='${workspace}';
    delete from sectalk_private.st_v7_tenant_key_state where workspace='${workspace}';`)
  for(const id of actors)sql(`delete from auth.users where id='${id}';`)
}
