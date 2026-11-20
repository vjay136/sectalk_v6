import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout as wait } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const project = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(project.origin, 'http://127.0.0.1:55321')
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(project.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const domain = 'scim-' + suffix + '.example.invalid'
const secondDomain = 'other-' + domain
const core = 'urn:ietf:params:scim:schemas:core:2.0:'
const messages = 'urn:ietf:params:scim:api:messages:2.0:'
const mailbox = 'http://127.0.0.1:55324'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(prefix, email) {
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(project.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: prefix + '_' + suffix, p_name: prefix }))
  return { id: user.id, email, client }
}
async function emailFor(email, subject) {
  const search = new URL('/api/v1/search',mailbox)
  search.searchParams.set('query','to:'+email)
  for (let attempt=0;attempt<25;attempt++) {
    const listing = await fetch(search).then(response=>response.json())
    const mail = listing.messages?.find(row=>row.Subject.toLowerCase().includes(subject))
    if (mail) {
      return fetch(new URL('/api/v1/message/'+mail.ID,mailbox)).then(response=>response.json())
    }
    await wait(400)
  }
  throw new Error('Expected local verification email did not arrive.')
}
function emailLink(message, pattern) {
  const body = message.HTML || message.Text
  const match = Array.from(body.matchAll(/https?:\/\/[^"\s<>]+/g)).map(hit=>hit[0].replaceAll('&amp;','&')).find(url=>pattern.test(url))
  assert.ok(match,'Local email has the expected native verification link.')
  return new URL(match)
}

const owner = await account('scimowner','owner@' + domain)
const second = await account('scimother','owner@' + secondDomain)
const candidate = await account('scimuser','member@' + domain)
const otherCandidate = await account('scimoutside','member@' + secondDomain)
sql([owner,second].map(a => "insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('"+a.id+"','enterprise','active',now()+interval '1 day');").join('\n'))
const workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:'SCIM Enterprise ' + suffix}))
const another = data(await second.client.rpc('st_v2_create_workspace',{p_name:'Other SCIM ' + suffix}))
sql("insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values('"+workspace+"','"+domain+"',now()),('"+another+"','"+secondDomain+"',now());")
assert.equal(data(await candidate.client.rpc('st_v8_scim_settings',{p_workspace:workspace})).access,'none')
assert.equal(data(await owner.client.rpc('st_v8_scim_settings',{p_workspace:workspace})).access,'mfa')
assert.ok((await candidate.client.rpc('st_v8_scim_request',{p_digest:'f'.repeat(64),p_kind:'Users',p_method:'GET',p_id:null})).error)
await fixtureAuthenticator(second.client)
const otherToken = data(await second.client.rpc('st_v8_scim_settings',{p_workspace:another,p_action:'rotate',p_domain:secondDomain})).token

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const page = await browser.newPage()
  const authorizationStates = []
  page.on('response', async response => {
    if (!response.url().endsWith('/rpc/st_v8_scim_settings')) return
    const state = await response.json().catch(() => null)
    authorizationStates.push([response.status(), state?.access, state?.enterprise, state?.domains?.length])
  })
  const btn = (scope,name) => scope.getByRole('button',{name,exact:true})
  await page.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
  await page.getByLabel('Email address',{exact:true}).fill(owner.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await btn(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await btn(page,'Integrations').click()
  await btn(page,'SCIM').click()
  const panel = page.getByRole('region',{name:'Enterprise directory provisioning'})
  await verifyStaffPanel(panel)
  const domainField = panel.getByRole('combobox',{name:/Verified domain/})
  try { await domainField.selectOption(domain,{timeout:10000}) }
  catch {
    const messages = await panel.getByRole('alert').allTextContents()
    throw new Error('Verified domain control did not appear. Panel errors: '+messages.join(' ')+
      '. Authorization states: '+JSON.stringify(authorizationStates))
  }
  await btn(panel,'Create provisioning token').click()
  await panel.getByText('Provisioning token created.',{exact:true}).waitFor()
  let token = await panel.getByLabel('New provisioning token',{exact:true}).inputValue()
  const base = await panel.getByLabel('SCIM base URL',{exact:true}).inputValue()
  assert.equal(base,app.origin+'/api/scim/v2')
  await btn(page,'API keys').click()
  assert.equal(await panel.count(),0)
  await btn(page,'SCIM').click()
  await panel.getByLabel('SCIM base URL',{exact:true}).waitFor()
  assert.equal(await panel.getByLabel('New provisioning token',{exact:true}).count(),0)
  async function send(path, method, body, auth=token) {
    const response = await fetch(base + path,{method,headers:{Authorization:'Bearer '+auth,'Content-Type':'application/scim+json'},
      body:body===undefined?undefined:JSON.stringify(body)})
    return {status:response.status,body:response.status===204?null:await response.json(),type:response.headers.get('content-type')}
  }
  const userBody = (userName, externalId) => ({schemas:[core+'User'],userName,externalId,displayName:'Directory member'})
  const groupBody = (displayName, members=[]) => ({schemas:[core+'Group'],displayName,members})
  const patch = (...Operations) => ({schemas:[messages+'PatchOp'],Operations})
  const config = await send('/ServiceProviderConfig','GET')
  assert.equal(config.status,200)
  assert.ok(config.type.includes('application/scim+json'))
  assert.equal(config.body.bulk.supported,false)
  assert.equal((await send('/Users','POST',userBody(owner.email,'owner'))).status,403)
  assert.equal((await send('/Users','POST',userBody(otherCandidate.email,'outside'))).status,403)
  const unknown = await send('/Users','POST',userBody('unknown@'+domain,'unknown'))
  assert.equal(unknown.status,201)
  assert.equal(unknown.body.active,true)
  assert.equal((await send('/Users/'+unknown.body.id,'DELETE')).status,204)
  const pendingEmail = 'new-starter@'+domain
  const pendingUser = await send('/Users','POST',userBody(pendingEmail,'new-starter'))
  assert.equal(pendingUser.status,201)
  const pendingId = pendingUser.body.id
  const pendingGroup = await send('/Groups','POST',groupBody('New starters '+suffix,[{value:pendingId}]))
  assert.equal(pendingGroup.status,201)
  assert.deepEqual(pendingGroup.body.members,[{value:pendingId}])
  assert.equal(sql("select count(*) from auth.users where email='"+pendingEmail+"';"),'0')
  assert.equal(sql("select count(*) from public.st_v6_workspace_group_members where group_id='"+pendingGroup.body.id+"';"),'0')

  // The current password route creates an unconfirmed Auth user and sends native verification.
  const { user: issued } = data(await admin.auth.admin.createUser({ email:pendingEmail,password,email_confirm:false }))
  const first = createClient(project.origin,publicKey,options)
  assert.ok((await first.auth.signInWithPassword({email:pendingEmail,password})).error)
  data(await first.auth.resend({type:'signup',email:pendingEmail}))
  const confirmation = emailLink(await emailFor(pendingEmail,'verify email'),/token_hash=/)
  const confirmationHash = new URLSearchParams(confirmation.hash.slice(1)).get('token_hash')
  assert.ok(confirmationHash,'Native confirmation token in local QA email.')
  data(await first.auth.verifyOtp({token_hash:confirmationHash,type:'email'}))
  data(await first.auth.signInWithPassword({email:pendingEmail,password}))
  data(await first.rpc('st_save_profile',{p_handle:'new_starter_'+suffix,p_name:'New starter'}))
  assert.equal(data(await first.rpc('st_v8_scim_claim',{p_accept:true})).state,'verify')
  assert.deepEqual(data(await first.from('st_v2_workspaces').select('id').eq('id',workspace)),[])
  const enrollee = await browser.newPage()
  await enrollee.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
  await enrollee.getByLabel('Email address',{exact:true}).fill(pendingEmail)
  await enrollee.getByLabel('Password',{exact:true}).fill(password)
  await enrollee.locator('button.submit-auth').click()
  await btn(enrollee.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await btn(enrollee,'Send workspace verification link').click()
  await enrollee.getByText('Check your email for a workspace verification link.').waitFor()
  const nativeLink = emailLink(await emailFor(pendingEmail,'sign-in link'),/\/verify\?/i)
  assert.ok(['127.0.0.1','localhost'].includes(nativeLink.hostname))
  const redirect = await fetch(nativeLink,{redirect:'manual'})
  assert.equal(redirect.status,303)
  const target = new URL(redirect.headers.get('location'))
  assert.ok(['127.0.0.1','localhost'].includes(target.hostname))
  assert.ok(target.searchParams.has('code'),'Supabase verified email and issued a PKCE authorization code.')
  // The shared local Auth fixture allows its primary app origin. Only its destination
  // is mapped to this isolated loopback build; native verification and exchange stay live.
  await enrollee.goto(new URL('/auth/scim-claim'+target.search,app).href)
  await enrollee.getByText('Your directory membership is ready.').waitFor()
  await enrollee.getByRole('link',{name:'Return to SecTalk',exact:true}).click()
  await btn(enrollee.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await enrollee.getByRole('heading',{name:'SCIM Enterprise '+suffix,exact:true}).waitFor()
  assert.equal(sql("select count(*) from public.st_v6_workspace_group_members where group_id='"+pendingGroup.body.id+"' and user_id='"+issued.id+"';"),'1')
  assert.deepEqual((await send('/Groups/'+pendingGroup.body.id,'GET')).body.members,[{value:pendingId}])
  assert.equal((await send('/Users/'+pendingId,'DELETE')).status,204)
  assert.equal(sql("select count(*) from public.st_v6_workspace_group_members where group_id='"+pendingGroup.body.id+"';"),'0')

  const attempts = await Promise.all([1,2].map(() => send('/Users','POST',userBody(candidate.email,'member'))))
  assert.deepEqual(attempts.map(row=>row.status).sort(),[201,409])
  const user = attempts.find(row=>row.status===201).body
  assert.equal(user.active,true)
  assert.equal(user.userName,candidate.email)
  const filtered = await send('/Users?'+new URLSearchParams({filter:'userName eq "'+candidate.email+'"',count:'1'}),'GET')
  assert.deepEqual(filtered.body.Resources.map(row=>row.id),[user.id])
  assert.equal((await send('/Users/'+user.id,'GET',undefined,otherToken)).status,404)
  assert.equal((await send('/Users/'+user.id,'PATCH',patch({op:'replace',path:'roles',value:['owner']}))).status,400)
  const rowsForCandidate = async () => data(await candidate.client.from('st_v2_workspaces').select('id').eq('id',workspace))
  assert.deepEqual(await rowsForCandidate(),[{id:workspace}])
  const group = await send('/Groups','POST',groupBody('QA directory '+suffix,[{value:user.id}]))
  assert.equal(group.status,201,JSON.stringify(group.body))
  const groupPath = '/Groups/'+group.body.id
  assert.deepEqual(group.body.members,[{value:user.id}])
  assert.equal((await send(groupPath,'DELETE',undefined,otherToken)).status,404)
  const invalidPatch = await send(groupPath,'PATCH',patch(
    {op:'replace',path:'displayName',value:'Should roll back'},
    {op:'add',path:'members',value:[{value:randomUUID()}]},
  ))
  assert.equal(invalidPatch.status,403)
  assert.equal((await send(groupPath,'GET')).body.displayName,group.body.displayName)
  const removed = await send(groupPath,'PATCH',patch({op:'remove',path:'members[value eq "'+user.id+'"]'}))
  assert.deepEqual(removed.body.members,[])
  const attached = await send(groupPath,'PATCH',patch({op:'add',path:'members',value:[{value:user.id}]}))
  assert.deepEqual(attached.body.members,[{value:user.id}])
  const inactive = await send('/Users/'+user.id,'PATCH',patch({op:'replace',path:'active',value:false}))
  assert.equal(inactive.status,200,JSON.stringify(inactive.body))
  assert.equal(inactive.body.active,false)
  assert.deepEqual(await rowsForCandidate(),[])
  assert.deepEqual((await send(groupPath,'GET')).body.members,[])
  const active = await send('/Users/'+user.id,'PATCH',patch({op:'replace',path:'active',value:true}))
  assert.equal(active.body.active,true)
  assert.deepEqual(await rowsForCandidate(),[{id:workspace}])
  assert.equal((await send('/Users/'+user.id,'DELETE')).status,204)
  assert.equal((await send('/Users/'+user.id,'GET')).status,404)
  assert.deepEqual(await rowsForCandidate(),[])
  assert.equal((await send(groupPath,'DELETE')).status,204)
  assert.equal((await send(groupPath,'GET')).status,404)
  assert.equal(sql("select (archived_at is not null)::int from public.st_v6_workspace_groups where id='"+group.body.id+"';"),'1')

  const priorToken=token
  await btn(panel,'Rotate provisioning token').click()
  await panel.getByLabel('New provisioning token',{exact:true}).waitFor()
  token = await panel.getByLabel('New provisioning token',{exact:true}).inputValue()
  assert.notEqual(token, priorToken)
  assert.equal((await send('/Users','GET',undefined,priorToken)).status,401)
  assert.equal((await send('/Users','GET')).status,200)
  await btn(panel,'Revoke provisioning token').click()
  await panel.getByText('Provisioning token revoked.',{exact:true}).waitFor()
  assert.equal((await send('/Users','GET')).status,401)
  console.log('Passed native Edge SCIM setup, authenticated user and group lifecycle, cross-tenant denial, live RLS, rollback and token rotation/revocation.')
} finally {
  await browser.close()
}
