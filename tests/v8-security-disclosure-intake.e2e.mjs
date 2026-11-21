import assert from 'node:assert/strict'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {spawn,execFileSync} from 'node:child_process'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const db=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const app='http://127.0.0.1:3489'
const origin='https://disclosure-qa.example.invalid'
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const details='Synthetic private report '+suffix+'\n<em data-qa-intake="inert">plain text example</em>'
const users=[]
let browser,child,reportId
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
function value(result){if(result.error)throw result.error;return result.data}
async function person(label){
  const handle='sec14_'+label+'_'+suffix,email=handle+'@example.invalid',password=randomUUID()+'!4aS'
  const {user}=value(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Disclosure '+label}))
  const stale=value(await client.auth.getSession()).session
  await fixtureAuthenticator(client)
  return {id:user.id,client,stale,session:value(await client.auth.getSession()).session}
}
function queue(session,body){
  return fetch(app+'/api/security/disclosure/queue',{method:'POST',headers:{Authorization:'Bearer '+session.access_token,
    'Content-Type':'application/json'},body:JSON.stringify(body)})
}
try {
  const operator=await person('operator'),outsider=await person('staff')
  sql(`insert into sectalk_private.staff(user_id) values('${operator.id}'),('${outsider.id}');
    insert into sectalk_private.st_v8_disclosure_operators(account) values('${operator.id}');`)
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_APP_URL:origin,
      SECTALK_SECURITY_CONTACT:undefined,SECTALK_SECURITY_CONTACT_EXPIRES:new Date(Date.now()+86400000).toISOString().replace('.000Z','Z').replace(/\.\d{3}Z$/,'Z'),
      SECTALK_DISCLOSURE_TEST_LOOPBACK:'yes',
      SECTALK_DISCLOSURE_SERVICE_KEY:service,SECTALK_DISCLOSURE_ENCRYPTION_KEY:randomBytes(32).toString('base64url')},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  const text=await fetch(app+'/.well-known/security.txt')
  assert.equal(text.status,200)
  assert.match(await text.text(),/Contact: https:\/\/disclosure-qa\.example\.invalid\/security\/report/)
  const crossSite=await fetch(app+'/api/security/disclosure',{method:'POST',
    headers:{Origin:'https://unrelated.example.invalid','Content-Type':'application/json'},body:'{}'})
  assert.equal(crossSite.status,403)
  assert.equal((await fetch(app+'/api/security/disclosure/queue',{method:'POST'})).status,401)
  const invalid=await fetch(app+'/api/security/disclosure',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({title:'Too large',feature:'QA',details:'s'.repeat(13000)})})
  assert.equal(invalid.status,413)
  assert.equal((await queue(operator.stale,{action:'list',state:'received'})).status,403)
  assert.equal((await queue(outsider.session,{action:'list',state:'received'})).status,403)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  await page.goto(app+'/security')
  assert.equal(await page.getByRole('link',{name:'Submit a private report'}).getAttribute('href'),origin+'/security/report')
  await page.goto(app+'/security/report')
  await page.getByLabel('Title').fill('Disclosure QA '+suffix)
  await page.getByLabel('Affected feature or version').fill('Synthetic UI')
  await page.getByLabel('Report details').fill(details)
  await page.getByLabel('Reply email (optional)').fill('synthetic@example.invalid')
  await page.getByRole('button',{name:'Submit private report'}).click()
  await page.getByText('Report received. Save this receipt for your records.').waitFor()
  const receipt=(await page.getByRole('status').locator('code').textContent()).trim()
  assert.match(receipt,/^[-_A-Za-z0-9]{32}$/)
  const hash=createHash('sha256').update(receipt).digest('hex')
  reportId=sql(`select id from sectalk_private.st_v8_disclosure_intake where receipt_hash='${hash}';`)
  assert.match(reportId,/^[0-9a-f-]{36}$/)
  const envelope=sql(`select envelope from sectalk_private.st_v8_disclosure_intake where id='${reportId}';`)
  assert.match(envelope,/^v1\./)
  assert.ok(!envelope.includes(suffix)&&!envelope.includes(receipt))
  const denied=await queue(outsider.session,{action:'open',id:reportId})
  assert.equal(denied.status,403)
  assert.equal((await queue(outsider.session,{action:'move',id:reportId,state:'reviewing'})).status,403)
  assert.equal((await queue(operator.session,{action:'move',id:reportId,state:'resolved'})).status,409)
  const direct=await outsider.client.rpc('st_v8_disclosure_queue',{p_action:'open',p_id:reportId})
  assert.equal(direct.error?.code,'42501')
  const insert=await operator.client.rpc('st_v8_disclosure_submit',{p_id:randomUUID(),p_receipt:hash,p_envelope:envelope})
  assert.ok(insert.error)

  const staff=await browser.newPage()
  await staff.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:operator.session})
  await staff.goto(app)
  await staff.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Safety',exact:true}).click()
  await staff.getByRole('button',{name:'Vulnerability disclosures',exact:true}).click()
  const open=staff.getByRole('button',{name:'Open disclosure '+reportId.slice(0,8),exact:true})
  await open.click()
  await staff.getByRole('heading',{name:'Disclosure QA '+suffix,exact:true}).waitFor()
  assert.equal(await staff.locator('[data-qa-intake]').count(),0)
  const report=staff.getByRole('article',{name:'Private disclosure'})
  assert.ok((await report.textContent()).includes('<em data-qa-intake="inert">'))
  await staff.getByRole('button',{name:'Begin review'}).click()
  await staff.getByText('Report moved to in review.').waitFor()

  const parts=envelope.split('.')
  parts[3]=(parts[3][0]==='A'?'B':'A')+parts[3].slice(1)
  sql(`update sectalk_private.st_v8_disclosure_intake set envelope='${parts.join('.')}' where id='${reportId}';`)
  const corrupted=await queue(operator.session,{action:'open',id:reportId})
  assert.equal(corrupted.status,503)
  assert.ok(!(await corrupted.text()).includes(suffix))
  assert.equal((await queue(operator.session,{action:'move',id:reportId,state:'resolved'})).status,503)
  sql(`update sectalk_private.st_v8_disclosure_intake set envelope='${envelope}' where id='${reportId}';`)
  await staff.getByLabel('Report state').selectOption('reviewing')
  await open.click()
  await staff.getByRole('button',{name:'Resolve report'}).click()
  await staff.getByText('Report moved to resolved.').waitFor()
  const actions=sql(`select string_agg(distinct action,',' order by action)
    from sectalk_private.st_v8_disclosure_audit where report='${reportId}';`)
  assert.equal(actions,'opened,received,resolved,reviewing')
  sql(`update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes'
    where authentication_method='totp' and session_id in(select id from auth.sessions where user_id='${operator.id}');`)
  assert.equal((await queue(operator.session,{action:'open',id:reportId})).status,403)
  console.log('Public first-party intake, encrypted reports, receipt, fresh scoped operator, inert text, tamper and write denials passed')
} finally {
  await browser?.close()
  child?.kill()
  if (reportId) sql(`delete from sectalk_private.st_v8_disclosure_intake where id='${reportId}';`)
  for(const id of users)await admin.auth.admin.deleteUser(id)
}
