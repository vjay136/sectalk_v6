import assert from 'node:assert/strict'
import {execFileSync,spawn} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(backend.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const checkSourcePause=process.env.SECTALK_RESIDENCY_SOURCE_PAUSE_QA==='1'
const checkRouting=process.env.SECTALK_RESIDENCY_ROUTING_QA==='1'
const targetRoute=process.env.SECTALK_RESIDENCY_ROUTING_TARGET_APP
if(checkRouting)assert.ok(checkSourcePause&&targetRoute&&new URL(targetRoute).hostname==='127.0.0.1')
const suffix=randomUUID().slice(0,8), password=randomUUID()+'!5a'
const cell=randomUUID(), foreignCell=randomUUID(), plannedCell=randomUUID(), nonce=randomUUID()
const project=checkRouting?'sectalk-routing-rehearsal-qa':'residency-fixture-'+suffix
const plannedProject='r'+[...randomUUID().replaceAll('-','').slice(0,19)].map(value=>'abcdefghijklmnop'[parseInt(value,16)]).join('')
const actors=[],workspaces=[]
let canary
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-q','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true})
function data(result) {if(result.error)throw result.error;return result.data}
async function account(label) {
  const handle='rr_'+label+'_'+suffix, email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  actors.push(user.id)
  const client=createClient(backend.href,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label+' residency QA'}))
  return {id:user.id,email,client}
}
const button=(scope,name)=>scope.getByRole('button',{name,exact:true})

try {
  const [owner,reviewer,outsider]=await Promise.all(['owner','reviewer','outside'].map(account))
  const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Residency synthetic '+suffix}))
  const foreign=data(await outsider.client.rpc('st_v2_create_workspace',{p_name:'Residency outsider '+suffix}))
  workspaces.push(workspace,foreign)
  sql(`insert into public.st_v2_subscriptions(user_id,plan,catalog_version,status,period_end)
      values('${owner.id}','enterprise',1,'active',now()+interval '90 days');
    insert into sectalk_private.st_v7_org_preferences(workspace,requested_region) values('${workspace}','us');
    insert into sectalk_private.st_v8_residency_cells(id,region,project_reference,label,environment) values
      ('${cell}','eu','${project}','Synthetic dedicated target','fixture'),
      ('${foreignCell}','apac','foreign-${suffix}','Foreign private target','fixture'),
      ('${plannedCell}','apac','${plannedProject}','Planned target','deployment');
    insert into sectalk_private.st_v8_residency_provider_bindings values('${plannedCell}','ap-south-1','synthetic-local-provider');
    insert into sectalk_private.st_v8_residency_installation(cell,installation_nonce) values('${cell}','${nonce}');
    insert into sectalk_private.st_v8_residency_cell_authorizations(workspace,cell) values
      ('${workspace}','${cell}'),('${workspace}','${plannedCell}'),('${foreign}','${foreignCell}');
    insert into sectalk_private.st_v8_residency_verifiers values('${workspace}','${reviewer.id}');`)
  if(checkRouting)sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${reviewer.id}','member');`)
  const tenant={p_workspace:workspace}
  assert.equal(data(await owner.client.rpc('st_v8_workspace_residency',tenant)).cells.some(target=>target.id===cell),true)
  assert.equal((await outsider.client.rpc('st_v8_workspace_residency',tenant)).error?.code,'42501')
  assert.equal((await owner.client.rpc('st_v8_workspace_residency_change',{...tenant,p_cell:foreignCell})).error?.code,'42501')
  assert.deepEqual(data(await outsider.client.rpc('st_v8_workspace_residency',{p_workspace:foreign})).cells,[])
  const page=await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(owner.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await button(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await button(page,'Organization settings').click()
  const org=page.getByRole('region',{name:'Organization settings'})
  const panel=org.getByRole('region',{name:'Enterprise data residency',exact:true})
  const picker=panel.getByLabel('Authorized residency target',{exact:true})
  await panel.waitFor({timeout:15000}).catch(async cause=>{
    throw new Error((await org.innerText({timeout:5000})).slice(0,1100),{cause})
  })
  await picker.selectOption(cell,{timeout:15000}).catch(async cause=>{
    throw new Error((await panel.innerText()).slice(0,1100),{cause})
  })
  assert.equal(await picker.getByRole('option',{name:/Foreign private target/}).count(),0)
  assert.equal(await org.getByLabel('Preferred data region').inputValue(),'us')
  await button(panel,'Request dedicated placement').click()
  const pending=panel.getByText('Target verification pending',{exact:true})
  const verify=org.getByRole('form',{name:'Verify current sign-in'})
  await pending.or(verify).first().waitFor()
  if(await verify.isVisible()) {
    await verify.getByLabel('Current password',{exact:true}).fill(password)
    await button(verify,'Verify and continue').click()
  }
  await pending.waitFor()
  console.log('Owner selected only a tenant-authorized target and preserved the separate preference.')
  const current=data(await owner.client.rpc('st_v8_workspace_residency',tenant))
  assert.equal(current.request.state,'pending_verification')
  assert.ok(!JSON.stringify(current).includes(project))
  assert.ok(!JSON.stringify(current).includes(nonce))
  const review={p_request:current.request.id}
  const probe={...review,p_project:project,p_installation_nonce:nonce}
  if(checkSourcePause)assert.equal((await owner.client.rpc('st_v8_residency_source_pause',{
    ...tenant,...review,p_action:'pause',p_confirmation:workspace,
  })).error?.code,'42501')
  assert.equal((await owner.client.rpc('st_v8_observe_residency_fixture',probe)).error?.code,'42501')
  assert.equal((await reviewer.client.rpc('st_v8_review_residency_fixture',review)).error?.code,'42501')
  await fixtureAuthenticator(reviewer.client)
  assert.equal(data(await reviewer.client.rpc('st_v8_review_residency_fixture',review)),false)
  assert.equal(data(await service.rpc('st_v8_observe_residency_fixture',probe)),false)
  const contents=JSON.stringify({fixture:current.request.id,scope:'synthetic probe only'})
  canary='residency-fixture/'+current.request.id
  const storage=service.storage.from('sectalk-exports')
  data(await storage.upload(canary,Buffer.from(contents),{contentType:'application/json'}))
  const bytes=data(await storage.download(canary))
  assert.equal(await bytes.text(),contents)
  assert.ok((await owner.client.storage.from('sectalk-exports').download(canary)).error)
  assert.equal(data(await service.rpc('st_v8_observe_residency_fixture',{...probe,p_project:'foreign-'+suffix})),false)
  assert.equal(data(await service.rpc('st_v8_observe_residency_fixture',{...probe,p_installation_nonce:randomUUID()})),false)
  assert.equal(data(await service.rpc('st_v8_observe_residency_fixture',probe)),true)
  console.log('Actual private Storage bytes, installation marker and exact project checks passed.')
  await button(panel,'Refresh placement status').click()
  await panel.getByText('Independent review pending',{exact:true}).waitFor()
  assert.equal(data(await reviewer.client.rpc('st_v8_review_residency_fixture',review)),true)
  await button(panel,'Refresh placement status').click()
  await panel.getByText('Synthetic target verified',{exact:true}).waitFor()
  await panel.getByText(/The current deployment continues to serve this workspace/).waitFor()
  assert.equal(await org.getByLabel('Preferred data region').inputValue(),'us')
  const stages=sql(`copy(select string_agg(action,',' order by id) from sectalk_private.st_v8_residency_audit where request='${current.request.id}') to stdout;`).trim()
  assert.equal(stages,'requested,observed,reviewed')
  if(checkSourcePause){
    const channel=data(await owner.client.rpc('st_v2_create_channel',{...tenant,p_name:'migration-pause'}))
    const unrelated=data(await outsider.client.rpc('st_v2_create_channel',{p_workspace:foreign,p_name:'migration-control'}))
    const room=randomUUID(), existingPost=randomUUID()
    data(await owner.client.rpc('st_v6_room_create',{...tenant,p_id:room,p_name:'Migration pause fixture',p_kind:'private',p_template:'blank'}))
    data(await owner.client.rpc('st_v2_post',{p_channel:channel,p_id:existingPost,p_body:'Source content stays readable'}))
    const proof=await fixtureAuthenticator(owner.client)
    const pause=(client,action='status',extra={})=>client.rpc('st_v8_residency_source_pause',{
      ...tenant,...review,p_action:action,...(action==='status'?{}:{p_confirmation:workspace}),...extra,
    })
    const verifiedOwner=createClient(backend.href,publicKey,{...options,accessToken:async()=>proof.session.access_token})
    assert.equal((await pause(reviewer.client,'pause')).error?.code,'42501')
    assert.equal((await pause(verifiedOwner,'pause',{p_request:randomUUID()})).error?.code,'42501')
    assert.equal((await pause(verifiedOwner,'pause',{p_confirmation:'wrong-workspace'})).error?.code,'42501')

    const {session}=data(await owner.client.auth.getSession())
    await page.evaluate(session=>localStorage.setItem('sb-127-auth-token',JSON.stringify(session)),session)
    await page.reload()
    await button(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
    await button(page,'Organization settings').click()
    const source=panel.getByRole('region',{name:'Source workspace writes',exact:true})
    const confirmation=source.getByLabel('Confirm source workspace ID',{exact:true})
    await confirmation.fill(workspace)
    await button(source,'Pause workspace writes for 30 minutes').click()
    await source.getByRole('status').getByText('Workspace writes are paused until',{exact:false}).waitFor()
    const first=data(await pause(verifiedOwner))
    assert.equal(first.paused,true)
    assert.ok(Date.parse(first.until)>Date.now())
    assert.deepEqual(data(await pause(verifiedOwner,'pause')),first)
    assert.deepEqual(data(await verifiedOwner.rpc('st_v7_workspace_payment_state',tenant)),{mode:'read_only',reason:'residency'})
    if(checkRouting){
      const state=(client,action='status',id=null)=>client.rpc('st_v8_residency_routing_rehearsal',{
        ...tenant,p_action:action,p_rehearsal:id,p_confirmation:workspace,
      })
      const token=(await reviewer.client.auth.getSession()).data.session.access_token
      const link=access=>fetch(new URL('/api/workspaces/residency/route-link?'+new URLSearchParams({workspace}),app),{
        headers:{Authorization:'Bearer '+access},redirect:'manual',
      })
      assert.equal(data(await state(verifiedOwner)).status,'ready')
      assert.equal((await state(outsider.client)).error?.code,'42501')
      assert.equal((await link(proof.session.access_token)).status,404)
      const holder=page.getByRole('region',{name:'Workspace routing rehearsal',exact:true})
      await holder.getByLabel('Confirm workspace ID',{exact:true}).fill(workspace)
      await button(holder,'Request routing rehearsal').click()
      await holder.getByText('Waiting for independent review.',{exact:true}).waitFor()
      const reviewState=data(await state(reviewer.client))
      assert.equal(reviewState.status,'pending')
      assert.equal((await state(verifiedOwner,'approve',reviewState.rehearsal)).error?.code,'42501')
      assert.equal((await state(reviewer.client,'end',reviewState.rehearsal)).error?.code,'42501')
      assert.equal((await state(reviewer.client,'approve',randomUUID())).error?.code,'42501')
      const reviewPage=await browser.newPage()
      const session=(await reviewer.client.auth.getSession()).data.session
      await reviewPage.addInitScript(({origin,session})=>{
        if(location.origin===origin)localStorage.setItem('sb-127-auth-token',JSON.stringify(session))
      },{origin:app.origin,session})
      await reviewPage.goto(new URL('/?workspace='+workspace,app).href)
      const panel=reviewPage.getByRole('region',{name:'Workspace routing rehearsal',exact:true})
      await panel.getByLabel('Confirm workspace ID',{exact:true}).fill(workspace)
      await button(panel,'Approve routing rehearsal').click()
      await panel.getByText('The rehearsal is active until',{exact:false}).waitFor()
      const approved=await link(token)
      assert.equal(approved.status,200)
      assert.equal(approved.headers.get('cache-control'),'private, no-store')
      assert.equal(approved.headers.get('referrer-policy'),'no-referrer')
      assert.deepEqual(await approved.json(),{url:new URL('/?workspace='+workspace,targetRoute).href})
      await button(holder,'Open the destination workspace').waitFor()
      const outsiderToken=(await outsider.client.auth.getSession()).data.session.access_token
      assert.equal((await link(outsiderToken)).status,404)
      await button(panel,'Open the destination workspace').click()
      await reviewPage.waitForURL(new URL('/?workspace='+workspace,targetRoute).href)
      await reviewPage.getByLabel('Email address',{exact:true}).waitFor()
      await reviewPage.close()
      await holder.getByLabel('Confirm workspace ID',{exact:true}).fill(workspace)
      await button(holder,'End routing rehearsal').click()
      await button(holder,'Request routing rehearsal').waitFor()
      assert.equal((await link(token)).status,404)
      assert.equal(data(await pause(verifiedOwner)).paused,true)
      console.log('Edge verified independent approval, isolated destination sign-in and immediate link withdrawal during a source write pause.')
    }
    assert.equal((await verifiedOwner.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:'Blocked source write'})).error?.code,'PT423')
    assert.equal((await verifiedOwner.rpc('st_v6_task_create',{p_id:randomUUID(),p_room:room,p_chat:null,p_title:'Blocked source task'})).error?.code,'PT423')
    assert.equal(data(await verifiedOwner.from('st_v2_posts').select('body').eq('id',existingPost).single()).body,'Source content stays readable')
    data(await outsider.client.rpc('st_v2_post',{p_channel:unrelated,p_id:randomUUID(),p_body:'Unrelated workspace keeps accepting writes'}))
    for(const [path,scope] of [['workspace-files',{workspace}],['room-files',{room} ]]){
      const result=await fetch(new URL('/api/'+path+'?'+new URLSearchParams({...scope,file:randomUUID()}),app),{
        method:'POST',body:'Blocked source attachment',headers:{Authorization:'Bearer '+proof.session.access_token,
          'Content-Type':'text/plain','X-SecTalk-File-Name':'pause.txt'},
      })
      assert.equal(result.status,423)
      assert.equal((await result.json()).error,'Workspace writes are paused for migration.')
    }
    await confirmation.fill(workspace)
    await button(source,'Resume workspace writes').click()
    await source.getByRole('status').getByText('The temporary migration pause is inactive.',{exact:true}).waitFor()
    data(await verifiedOwner.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:'Source writes resumed'}))
    const inFlight=randomUUID()
    const writerLabel='sectalk-pause-writer-'+suffix
    const claims=Buffer.from(proof.session.access_token.split('.')[1],'base64url').toString('utf8').replaceAll("'","''")
    const writer=spawn('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
      {stdio:['pipe','pipe','ignore'],windowsHide:true})
    const exited=new Promise(resolve=>writer.once('close',resolve))
    const {promise:ready,resolve:release}=Promise.withResolvers()
    let written=''
    writer.stdout.setEncoding('utf8').on('data',chunk=>{written+=chunk;if(written.includes('write-at-barrier'))release()})
    let pendingPause
    try {
      writer.stdin.write(`begin; set local application_name='${writerLabel}'; set local role authenticated;
        select set_config('request.jwt.claims','${claims}',true) is not null;
        select public.st_v2_post('${channel}','${inFlight}','Admitted in-flight workspace write');
        \\echo write-at-barrier\n`)
      await Promise.race([ready,exited.then(()=>{throw new Error('The native writer stopped before the barrier')}),
        setTimeout(5000,null,{ref:false}).then(()=>{throw new Error('The native writer did not reach the barrier')})])
      pendingPause=Promise.resolve(pause(verifiedOwner,'pause'))
      const deadline=Date.now()+5000
      let waited=false
      do {
        waited=sql(`copy(select exists(select 1 from pg_locks h join pg_stat_activity a on a.pid=h.pid
          join pg_locks w using(locktype,database,classid,objid,objsubid)
          where a.application_name='${writerLabel}' and h.locktype='advisory' and h.granted and not w.granted)) to stdout;`).trim()==='t'
        if(!waited)await setTimeout(50)
      } while(!waited&&Date.now()<deadline)
      assert.ok(waited,'The source pause must wait for an already admitted write')
    } finally {
      if(!writer.stdin.destroyed)writer.stdin.end('commit;\n\\q\n')
      assert.equal(await exited,0)
    }
    assert.equal(data(await pendingPause).paused,true)
    assert.equal(data(await verifiedOwner.from('st_v2_posts').select('body').eq('id',inFlight).single()).body,'Admitted in-flight workspace write')
    sql(`update sectalk_private.st_v8_residency_source_pauses set started_at=clock_timestamp()-interval '31 minutes',
      ends_at=clock_timestamp()-interval '1 minute' where workspace='${workspace}';`)
    assert.deepEqual(data(await pause(verifiedOwner)),{paused:false,until:null})
    data(await verifiedOwner.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:'Source writes resumed after expiry'}))
    sql(`delete from sectalk_private.st_v8_residency_verifiers where workspace='${workspace}' and actor='${reviewer.id}';`)
    assert.equal((await pause(verifiedOwner,'pause')).error?.code,'PT409')
    sql(`insert into sectalk_private.st_v8_residency_verifiers values('${workspace}','${reviewer.id}');`)
    assert.equal(sql(`copy(select string_agg(event,',' order by id) from public.st_v2_workspace_audit where target='${current.request.id}'
      and event in ('workspace.residency_writes_paused','workspace.residency_writes_resumed')) to stdout;`).trim(),
      'workspace.residency_writes_paused,workspace.residency_writes_resumed,workspace.residency_writes_paused')
    console.log('Paused scoped source writes and uploads, preserved reads and another workspace, then verified resume, automatic expiry and fresh reviewer authority.')
  }
  sql(`update sectalk_private.st_v8_residency_installation set installation_nonce='${randomUUID()}' where cell='${cell}';`)
  await button(panel,'Refresh placement status').click()
  await panel.getByText('Target needs fresh verification',{exact:true}).waitFor()
  await button(panel,'Withdraw residency request').click()
  await picker.selectOption(plannedCell)
  await button(panel,'Request dedicated placement').click()
  await pending.waitFor()
  const deployment=data(await owner.client.rpc('st_v8_workspace_residency',tenant)).request
  assert.equal(data(await service.rpc('st_v8_observe_residency_fixture',{...probe,p_request:deployment.id})),false)
  const verifyEndpoint=async client=>{
    const {session}=data(await client.auth.getSession())
    return fetch(new URL('/api/workspaces/residency/verify',app),{method:'POST',
      headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},
      body:JSON.stringify({request:deployment.id})})
  }
  assert.equal((await verifyEndpoint(owner.client)).status,404)
  const missingConfig=await verifyEndpoint(reviewer.client)
  assert.equal(missingConfig.status,202)
  assert.deepEqual(await missingConfig.json(),{status:'pending_verification'})
  await button(panel,'Refresh placement status').click()
  await pending.waitFor()
  console.log('Passed current owner target selection, tenant isolation, actual private Storage canary, independent TOTP verification, stale-marker invalidation, and pending deployment state.')
} finally {
  await browser.close()
  if(canary)await service.storage.from('sectalk-exports').remove([canary])
  for(const workspace of workspaces)sql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v8_residency_audit where workspace='${workspace}'; set local session_replication_role=origin;
    delete from public.st_v2_workspaces where id='${workspace}'; commit;`)
  sql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v8_residency_provider_bindings where cell='${plannedCell}';
    set local session_replication_role=origin;
    delete from sectalk_private.st_v8_residency_installation where cell='${cell}';
    delete from sectalk_private.st_v8_residency_cells where id in ('${cell}','${foreignCell}','${plannedCell}'); commit;`)
  for(const actor of actors)sql(`delete from auth.users where id='${actor}';`)
}
