// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const admin = createClient(supabase.origin, serviceKey, options)
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)
const fileSsoBody = Buffer.from('SecTalk file SSO fixture '+suffix)
const fileSsoObjects = []
const complianceSsoObjects = []
const recordingSsoObjects = []
let participantLookups=0
const mediaParticipants=new Map()
const removedMedia=[]

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function observeChannelChanges(page, token, accountId) {
  await page.addScriptTag({path:'node_modules/@supabase/supabase-js/dist/umd/supabase.js'})
  await page.evaluate(async ({origin, publicKey, token, topic, accountId})=>{
    const client = window.supabase.createClient(origin, publicKey, {accessToken: async ()=>token})
    await client.realtime.setAuth(token)
    window.ssoFeedEvents=[]
    window.ssoAnnouncements=[]
    const feed = client.channel(topic)
      .on('postgres_changes', {event:'*',schema:'public',table:'st_v2_posts'}, event=>window.ssoFeedEvents.push(event))
    const subscribe=channel=>new Promise((resolve,reject)=>{
      const timeout=setTimeout(()=>reject(new Error('Realtime subscription did not join')),15000)
      channel.subscribe((status,error)=>{
        if(status==='SUBSCRIBED' || status==='CHANNEL_ERROR' || status==='TIMED_OUT'){
          clearTimeout(timeout)
          if(status==='SUBSCRIBED')resolve()
          else reject(error ?? new Error(status))
        }
      })
    })
    await subscribe(feed)
    if(accountId){
      const announcements=client.channel('st:account:'+accountId,{config:{private:true}})
        .on('broadcast',{event:'channel_activity'},event=>window.ssoAnnouncements.push(event.payload))
      await subscribe(announcements)
    }
    window.closeSsoFeed=()=>client.removeAllChannels()
  },{origin:supabase.origin,publicKey,token,topic:'sso-feed-'+randomUUID(),accountId})
  return {events:()=>page.evaluate(()=>window.ssoFeedEvents),
    announcements:()=>page.evaluate(()=>window.ssoAnnouncements),close:()=>page.evaluate(()=>window.closeSsoFeed())}
}

async function waitForChannelChanges(check, label) {
  const deadline=Date.now()+15000
  while(!await check()){
    if(Date.now()>=deadline)throw new Error('Expected native Realtime change did not arrive: '+label)
    await new Promise(resolve=>setTimeout(resolve,100))
  }
}

async function account(handlePrefix) {
  const handle = handlePrefix + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { id: user.id, handle, email, client }
}
import { createServer } from 'node:http'
import { createHash, createHmac, sign } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { inflateRawSync } from 'node:zlib'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const base = 'http://127.0.0.1:3563'
const entity = base+'/fixture/idp-metadata-'+suffix
const issuer = base+'/fixture/saml'
const namespace = 'urn:oasis:names:tc:SAML:2.0:assertion'
const protocol = 'urn:oasis:names:tc:SAML:2.0:protocol'
const ds = 'http://www.w3.org/2000/09/xmldsig#'
const domain = 'tenant-'+suffix+'.example.invalid'
const email = 'verified@'+domain
const nativeProvider = randomUUID()
const certificate = (await readFile('supabase/.temp/v4-auth-qa/sso-qa-root.pem','utf8')).replace(/-----[^-]+-----|\s/g,'')
const key = await readFile('supabase/.temp/v4-auth-qa/sso-qa-root.key','utf8')
const metadata = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="'+entity+'">'+
  '<IDPSSODescriptor protocolSupportEnumeration="'+protocol+'"><KeyDescriptor use="signing"><KeyInfo xmlns="'+ds+'"><X509Data><X509Certificate>'+
  certificate+'</X509Certificate></X509Data></KeyInfo></KeyDescriptor>'+
  '<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>'+
  '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="'+issuer+'"/></IDPSSODescriptor></EntityDescriptor>'

const escaped=value=>String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;')
let assertions=0
function assertion(requestId,acs,audience){
  const id='_'+randomUUID()
  const issue=new Date().toISOString()
  const end=new Date(Date.now()+180000).toISOString()
  const before=new Date(Date.now()-30000).toISOString()
  const begin='<saml:Assertion xmlns:saml="'+namespace+'" ID="'+id+'" IssueInstant="'+issue+'" Version="2.0"><saml:Issuer>'+entity+'</saml:Issuer>'
  const claims='<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">'+email+'</saml:NameID>'+
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="'+requestId+
    '" NotOnOrAfter="'+end+'" Recipient="'+acs+'"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject>'+
    '<saml:Conditions NotBefore="'+before+'" NotOnOrAfter="'+end+'"><saml:AudienceRestriction><saml:Audience>'+audience+
    '</saml:Audience></saml:AudienceRestriction></saml:Conditions>'+
    '<saml:AuthnStatement AuthnInstant="'+issue+'" SessionIndex="'+id+'"><saml:AuthnContext><saml:AuthnContextClassRef>'+
    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'+
    '<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>'+email+'</saml:AttributeValue></saml:Attribute>'+
    '</saml:AttributeStatement></saml:Assertion>'
  const digest=createHash('sha256').update(begin+claims).digest('base64')
  const c14n='http://www.w3.org/2001/10/xml-exc-c14n#'
  const info='<ds:SignedInfo xmlns:ds="'+ds+'"><ds:CanonicalizationMethod Algorithm="'+c14n+'"></ds:CanonicalizationMethod>'+
    '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>'+
    '<ds:Reference URI="#'+id+'"><ds:Transforms><ds:Transform Algorithm="'+ds+'enveloped-signature"></ds:Transform>'+
    '<ds:Transform Algorithm="'+c14n+'"></ds:Transform></ds:Transforms>'+
    '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>'+
    '<ds:DigestValue>'+digest+'</ds:DigestValue></ds:Reference></ds:SignedInfo>'
  const signature=sign('RSA-SHA256',Buffer.from(info),key).toString('base64')
  const signed='<ds:Signature xmlns:ds="'+ds+'">'+info+'<ds:SignatureValue>'+signature+'</ds:SignatureValue>'+
    '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+certificate+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>'
  return '<samlp:Response xmlns:samlp="'+protocol+'" xmlns:saml="'+namespace+'" ID="_'+randomUUID()+
    '" Version="2.0" IssueInstant="'+issue+'" Destination="'+acs+'" InResponseTo="'+requestId+'"><saml:Issuer>'+entity+
    '</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'+
    begin+signed+claims+'</samlp:Response>'
}
const proxy=createServer(async(request,response)=>{
  const target=new URL(request.url,base)
  try{
    if(target.pathname.startsWith('/auth/v1/')){
      const upstream=new URL('http://127.0.0.1:3565'+target.pathname.slice('/auth/v1'.length)+target.search)
      const headers=new Headers()
      for(const name of ['authorization','apikey','content-type','origin','referer','user-agent']){
        if(typeof request.headers[name]==='string')headers.set(name,request.headers[name])
      }
      const parts=[]
      for await(const part of request)parts.push(part)
      const body=request.method==='GET'||request.method==='HEAD'?undefined:Buffer.concat(parts)
      const result=await fetch(upstream,{method:request.method,headers,body,redirect:'manual'})
      const out={}
      for(const name of ['location','content-type','set-cookie','cache-control']){
        if(result.headers.has(name))out[name]=result.headers.get(name)
      }
      response.writeHead(result.status,out);response.end(Buffer.from(await result.arrayBuffer()));return
    }
    if(target.pathname==='/scan' && (process.env.SECTALK_TEST_SSO_FILES==='1'||process.env.SECTALK_TEST_SSO_ENTRY_FILES==='1')){
      const key=process.env.SECTALK_MALWARE_SCANNER_SECRET
      if(request.method!=='POST'||!key||request.headers.authorization!=='Bearer '+key){
        response.writeHead(401);response.end();return
      }
      const chunks=[]
      let length=0
      for await(const chunk of request){
        length+=chunk.length
        if(length>fileSsoBody.length){response.writeHead(422);response.end();return}
        chunks.push(chunk)
      }
      if(!Buffer.concat(chunks).equals(fileSsoBody)){response.writeHead(422);response.end();return}
      response.writeHead(200,{'Content-Type':'application/json'})
      response.end(JSON.stringify({verdict:'clean',sha256:createHash('sha256').update(fileSsoBody).digest('hex')}))
      return
    }
    const roomOperation=target.pathname.match(/^\/twirp\/livekit\.RoomService\/(ListRooms|ListParticipants|RemoveParticipant)$/)?.[1]
    if(roomOperation && process.env.SECTALK_TEST_SSO_MEDIA_CONVERSION==='1'){
      if(request.method!=='POST'){response.writeHead(405);response.end();return}
      const chunks=[]
      for await(const chunk of request) { if(chunk.length>4096){response.writeHead(413);response.end();return} chunks.push(chunk) }
      const {room,identity}=JSON.parse(Buffer.concat(chunks).toString()||'{}')
      function reply(body){response.writeHead(200,{'Content-Type':'application/json'});response.end(JSON.stringify(body))}
      if(roomOperation==='ListRooms') reply({rooms:[...mediaParticipants.keys()].map(name=>({name}))})
      else if(roomOperation==='ListParticipants'){
        participantLookups++
        reply({participants:mediaParticipants.get(room)??[]})
      }else{
        assert.ok(mediaParticipants.get(room)?.some(person=>person.identity===identity))
        removedMedia.push({room,identity})
        mediaParticipants.set(room,mediaParticipants.get(room).filter(person=>person.identity!==identity))
        reply({})
      }
      return
    }
    if(target.pathname==='/fixture/saml'){
      const req=inflateRawSync(Buffer.from(target.searchParams.get('SAMLRequest'),'base64')).toString('utf8')
      const id=req.match(/\bID="([^"]+)"/)?.[1]
      const acs=req.match(/\bAssertionConsumerServiceURL="([^"]+)"/)?.[1]
      const audience=req.match(/<(?:\w+:)?Issuer[^>]*>([^<]+)<\//)?.[1]
      if(!id||acs!==base+'/auth/v1/sso/saml/acs'||audience!==base+'/auth/v1/sso/saml/metadata')
        throw new Error('Unknown native SAML fixture request')
      const xml=assertion(id,acs,audience)
      assertions++
      response.writeHead(200,{'Content-Type':'text/html'})
      response.end('<form method="POST" action="'+acs+'"><input type="hidden" name="RelayState" value="'+
        escaped(target.searchParams.get('RelayState'))+'"><input type="hidden" name="SAMLResponse" value="'+
        Buffer.from(xml).toString('base64')+'"><button type="submit">Continue with synthetic IdP</button></form>')
      return
    }
    response.writeHead(404);response.end()
  }catch{response.writeHead(503);response.end('Local fixture unavailable')}
})
await new Promise((resolve,reject)=>proxy.once('error',reject).listen(3563,'127.0.0.1',resolve))

function sql(statement){
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input:statement,encoding:'utf8',windowsHide:true}).trim()
}
let browser
const duplicateWarnings=[]
function trackDuplicateKeys(context){
  context.on('console',message=>{
    if(message.text().includes('Encountered two children with the same key')) duplicateWarnings.push(message.text())
  })
}
try{
  const owner=await account('sso_owner')
  sql("insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('"+owner.id+"','enterprise','active',now()+interval '1 day');")
  const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Enterprise SSO '+suffix}))
  sql("insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values('"+workspace+"','"+domain+"',now());\n"+
    "insert into auth.sso_providers(id,disabled,created_at,updated_at) values('"+nativeProvider+"',false,now(),now());\n"+
    "insert into auth.sso_domains(id,sso_provider_id,domain,created_at,updated_at) values(gen_random_uuid(),'"+nativeProvider+"','"+domain+"',now(),now());\n"+
    "insert into auth.saml_providers(id,sso_provider_id,entity_id,metadata_xml,attribute_mapping,created_at,updated_at) values(gen_random_uuid(),'"+
    nativeProvider+"','"+entity+"',$saml$"+metadata+"$saml$,'{}',now(),now());")
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const realtimeTest=process.env.SECTALK_TEST_SSO_REALTIME==='1'
  // Load the installed SDK in the test browser to observe raw events independently of the UI.
  const adminContext=await browser.newContext({bypassCSP:realtimeTest})
  trackDuplicateKeys(adminContext)
  const adminPage=await adminContext.newPage()
  const btn=(scope,name)=>scope.getByRole('button',{name,exact:true})
  const nav=page=>page.getByRole('navigation',{name:'SecTalk features'})
  await adminPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
  await adminPage.getByLabel('Email address',{exact:true}).fill(owner.email)
  await adminPage.getByLabel('Password',{exact:true}).fill(password)
  await adminPage.locator('button.submit-auth').click()
  await btn(nav(adminPage),'Workspaces').click()
  await btn(adminPage,'Integrations').click()
  await btn(adminPage,'Single sign-on').click()
  const config=adminPage.getByRole('region',{name:'Enterprise workspace sign-in'})
  await verifyStaffPanel(config)
  await config.getByRole('combobox',{name:/Verified domain/}).selectOption(domain)
  await config.getByLabel('Identity provider type').selectOption('saml')
  await config.getByRole('checkbox',{name:'Admit new verified domain users as ordinary members'}).check()
  await btn(config,'Save workspace sign-in').click()
  await config.getByText('Workspace sign-in configured.',{exact:true}).waitFor()
  await btn(config,'Manage verified domains').click()
  await adminPage.getByRole('heading',{name:'Verified domains',exact:true}).waitFor()
  assert.equal(await config.count(),0)
  await btn(adminPage,'Integrations').click()
  await btn(adminPage,'Single sign-on').click()
  await btn(config,'Disconnect workspace SSO').waitFor()
  const ownerAccess = await adminPage.evaluate(()=>{
    const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
  const assuredOwner=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+ownerAccess}}})
  if(process.env.SECTALK_TEST_SSO_MEDIA==='1'){
    await btn(config,'Require SSO for new member media').click()
    await config.getByText('Complete a workspace SSO sign-in before requiring it for member media.').waitFor()
  }
  const channelTest=realtimeTest || process.env.SECTALK_TEST_SSO_CHANNEL==='1'
  const channelStructureTest=process.env.SECTALK_TEST_SSO_CHANNEL_STRUCTURE==='1'
  const channelStructurePolicy=config.getByRole('region',{name:'Workspace channel directory sign-in',exact:true})
  const roomTest=process.env.SECTALK_TEST_SSO_ROOM==='1'
  const roomPolicy=config.getByRole('region',{name:'Standard room message sign-in',exact:true})
  const roomStructureTest=process.env.SECTALK_TEST_SSO_ROOM_STRUCTURE==='1'
  const roomStructurePolicy=config.getByRole('region',{name:'Workspace room directory sign-in',exact:true})
  const navigationTest=process.env.SECTALK_TEST_SSO_NAVIGATION==='1'
  if(navigationTest)assert.ok(roomStructureTest,'Navigation SSO verification requires the room structure scenario')
  const managedTest=process.env.SECTALK_TEST_SSO_MANAGED==='1'
  const managedPolicy=config.getByRole('region',{name:'Managed encrypted message sign-in',exact:true})
  const plannerTest=process.env.SECTALK_TEST_SSO_PLANNER==='1'
  const plannerPolicy=config.getByRole('region',{name:'Workspace planning sign-in',exact:true})
  const directoryTest=process.env.SECTALK_TEST_SSO_DIRECTORY==='1'
  const directoryPolicy=config.getByRole('region',{name:'Workspace directory sign-in',exact:true})
  const inviteEntryTest=process.env.SECTALK_TEST_SSO_ENTRY_INVITATIONS==='1'
  const invitationAdminTest=inviteEntryTest||process.env.SECTALK_TEST_SSO_INVITATION_ADMIN==='1'
  const invitationAdminPolicy=config.getByRole('region',{name:'Workspace invitation management sign-in',exact:true})
  const entryIntegrationTest=process.env.SECTALK_TEST_SSO_ENTRY_INTEGRATIONS==='1'
  const entryModerationTest=process.env.SECTALK_TEST_SSO_ENTRY_MODERATION==='1'
  const entryChannelReportsTest=process.env.SECTALK_TEST_SSO_ENTRY_CHANNEL_REPORTS==='1'
  const integrationAdminTest=entryIntegrationTest||process.env.SECTALK_TEST_SSO_INTEGRATION_ADMIN==='1'
  const integrationAdminPolicy=config.getByRole('region',{name:'Workspace integration credential sign-in',exact:true})
  const customRoleAdminTest=process.env.SECTALK_TEST_SSO_CUSTOM_ROLE_ADMIN==='1'
  const customRoleAdminPolicy=config.getByRole('region',{name:'Workspace custom role sign-in',exact:true})
  const entryPolicyAdminTest=process.env.SECTALK_TEST_SSO_ENTRY_POLICY_ADMIN==='1'
  const policyAdminTest=entryPolicyAdminTest||process.env.SECTALK_TEST_SSO_POLICY_ADMIN==='1'
  const policyAdminPolicy=config.getByRole('region',{name:'Workspace policy management sign-in',exact:true})
  const legalHoldTest=process.env.SECTALK_TEST_SSO_LEGAL_HOLD==='1'
  const legalHoldPolicy=config.getByRole('region',{name:'Workspace legal hold sign-in',exact:true})
  const entryComplianceTest=process.env.SECTALK_TEST_SSO_ENTRY_COMPLIANCE==='1'
  const complianceTest=entryComplianceTest||process.env.SECTALK_TEST_SSO_COMPLIANCE==='1'
  const compliancePolicy=config.getByRole('region',{name:'Workspace compliance export sign-in',exact:true})
  const entryTest=process.env.SECTALK_TEST_SSO_ENTRY==='1'
  const entryPolicy=config.getByRole('region',{name:'Workspace entry sign-in',exact:true})
  const auditTest=process.env.SECTALK_TEST_SSO_AUDIT==='1'
  const auditPolicy=config.getByRole('region',{name:'Workspace audit sign-in',exact:true})
  const scheduleTest=process.env.SECTALK_TEST_SSO_SCHEDULE==='1'
  const entryMeetingTest=process.env.SECTALK_TEST_SSO_ENTRY_MEETINGS==='1'
  const entryArtifactTest=process.env.SECTALK_TEST_SSO_ENTRY_MEETING_ARTIFACTS==='1'
  const schedulePolicy=config.getByRole('region',{name:'Workspace meeting schedule sign-in',exact:true})
  const groupsTest=process.env.SECTALK_TEST_SSO_GROUPS==='1'
  const groupsPolicy=config.getByRole('region',{name:'Workspace groups and teams sign-in',exact:true})
  const entryFileTest=process.env.SECTALK_TEST_SSO_ENTRY_FILES==='1'
  const fileTest=entryFileTest||process.env.SECTALK_TEST_SSO_FILES==='1'
  const filePolicy=config.getByRole('region',{name:'Workspace file sign-in',exact:true})
  const entryBillingTest=process.env.SECTALK_TEST_SSO_ENTRY_BILLING==='1'
  const billingTest=entryBillingTest||process.env.SECTALK_TEST_SSO_BILLING==='1'
  const billingPolicy=config.getByRole('region',{name:'Workspace billing sign-in',exact:true})
  const entryOrganizationTest=process.env.SECTALK_TEST_SSO_ENTRY_ORGANIZATION==='1'
  const organizationTest=entryOrganizationTest||process.env.SECTALK_TEST_SSO_ORGANIZATION==='1'
  const organizationPolicy=config.getByRole('region',{name:'Organization settings sign-in',exact:true})
  if(organizationTest){
    const platformPolicy=entryOrganizationTest?entryPolicy:organizationPolicy
    const scope=entryOrganizationTest?'workspace entry':'organization settings'
    await btn(platformPolicy,'Require SSO for '+scope).click()
    await platformPolicy.getByText('Complete a workspace SSO sign-in before requiring it for '+scope+'.').waitFor()
  }
  if(billingTest){
    if(entryBillingTest){
      await btn(entryPolicy,'Require SSO for workspace entry').click()
      await entryPolicy.getByText('Complete a workspace SSO sign-in before requiring it for workspace entry.').waitFor()
    }else{
      await btn(billingPolicy,'Require SSO for workspace billing').click()
      await billingPolicy.getByText('Complete a workspace SSO sign-in before requiring it for workspace billing.').waitFor()
    }
  }
  if(fileTest){
    const scope=entryFileTest?entryPolicy:filePolicy
    const name=entryFileTest?'workspace entry':'workspace and room files'
    await btn(scope,'Require SSO for '+name).click()
    await scope.getByText('Complete a workspace SSO sign-in before requiring it for '+name+'.').waitFor()
  }
  if(groupsTest){
    await btn(groupsPolicy,'Require SSO for groups and teams').click()
    await groupsPolicy.getByText('Complete a workspace SSO sign-in before requiring it for groups and teams.').waitFor()
  }
  if(scheduleTest){
    await btn(schedulePolicy,'Require SSO for workspace meetings').click()
    await schedulePolicy.getByText('Complete a workspace SSO sign-in before requiring it for workspace meetings.').waitFor()
  }
  if(auditTest){
    await btn(auditPolicy,'Require SSO for workspace audit logs').click()
    await auditPolicy.getByText('Complete a workspace SSO sign-in before requiring it for workspace audit logs.').waitFor()
  }
  if(directoryTest){
    await btn(directoryPolicy,'Require SSO for the workspace directory').click()
    await directoryPolicy.getByText('Complete a workspace SSO sign-in before requiring it for the workspace directory.').waitFor()
  }
  if(invitationAdminTest){
    const scope=inviteEntryTest?entryPolicy:invitationAdminPolicy
    const scopeName=inviteEntryTest?'workspace entry':'invitation management'
    await btn(scope,'Require SSO for '+scopeName).click()
    await scope.getByText('Complete a workspace SSO sign-in before requiring it for '+scopeName+'.').waitFor()
  }
  if(integrationAdminTest){
    const scope=entryIntegrationTest?entryPolicy:integrationAdminPolicy
    const scopeName=entryIntegrationTest?'workspace entry':'API keys and webhooks'
    await btn(scope,'Require SSO for '+scopeName).click()
    await scope.getByText('Complete a workspace SSO sign-in before requiring it for '+scopeName+'.').waitFor()
  }
  if(customRoleAdminTest){
    await btn(customRoleAdminPolicy,'Require SSO for custom role management').click()
    await customRoleAdminPolicy.getByText('Complete a workspace SSO sign-in before requiring it for custom role management.').waitFor()
  }
  if(policyAdminTest){
    const policy=entryPolicyAdminTest?entryPolicy:policyAdminPolicy
    const scope=entryPolicyAdminTest?'workspace entry':'policy management'
    await btn(policy,'Require SSO for '+scope).click()
    await policy.getByText('Complete a workspace SSO sign-in before requiring it for '+scope+'.').waitFor()
  }
  if(legalHoldTest){
    await btn(legalHoldPolicy,'Require SSO for legal holds').click()
    await legalHoldPolicy.getByText('Complete a workspace SSO sign-in before requiring it for legal holds.').waitFor()
  }
  if(complianceTest){
    const policy=entryComplianceTest?entryPolicy:compliancePolicy
    const scope=entryComplianceTest?'workspace entry':'compliance exports and evidence'
    await btn(policy,'Require SSO for '+scope).click()
    await policy.getByText('Complete a workspace SSO sign-in before requiring it for '+scope+'.').waitFor()
  }
  if(entryTest){
    await btn(entryPolicy,'Require SSO for workspace entry').click()
    await entryPolicy.getByText('Complete a workspace SSO sign-in before requiring it for workspace entry.').waitFor()
  }
  if(entryMeetingTest||entryArtifactTest){
    await btn(entryPolicy,'Require SSO for workspace entry').click()
    await entryPolicy.getByText('Complete a workspace SSO sign-in before requiring it for workspace entry.').waitFor()
  }
  if(plannerTest){
    await btn(plannerPolicy,'Require SSO for workspace planning').click()
    await plannerPolicy.getByText('Complete a workspace SSO sign-in before requiring it for workspace planning.').waitFor()
  }
  if(managedTest){
    await btn(managedPolicy,'Require SSO for managed messages').click()
    await managedPolicy.getByText('Complete a workspace SSO sign-in before requiring it for managed messages.').waitFor()
  }
  if(channelTest){
    const policy=config.getByRole('region',{name:'Standard channel message sign-in',exact:true})
    await btn(policy,'Require SSO for standard channel messages').click()
    await policy.getByText('Complete a workspace SSO sign-in before requiring it for standard channel messages.').waitFor()
  }
  if(channelStructureTest){
    await btn(channelStructurePolicy,'Require SSO for the channel directory').click()
    await channelStructurePolicy.getByText('Complete a workspace SSO sign-in before requiring it for the channel directory.').waitFor()
  }
  if(roomTest){
    await btn(roomPolicy,'Require SSO for standard room messages').click()
    await roomPolicy.getByText('Complete a workspace SSO sign-in before requiring it for standard room messages.').waitFor()
  }
  if(roomStructureTest){
    await btn(roomStructurePolicy,'Require SSO for the room directory').click()
    await roomStructurePolicy.getByText('Complete a workspace SSO sign-in before requiring it for the room directory.').waitFor()
  }
  const memberContext=await browser.newContext({bypassCSP:realtimeTest})
  trackDuplicateKeys(memberContext)
  const memberPage=await memberContext.newPage()
  await memberPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
  await memberPage.getByText('Sign in with workspace SSO',{exact:true}).click()
  await memberPage.getByLabel('Workspace email domain',{exact:true}).fill(domain)
  await btn(memberPage,'Continue with workspace SSO').click()
  await btn(memberPage,'Continue with synthetic IdP').waitFor()
  const completed=memberPage.waitForResponse(response=>response.url().endsWith('/api/auth/workspace-sso')
    &&response.request().method()==='POST'&&response.request().postDataJSON().action==='complete',{timeout:15000})
  await btn(memberPage,'Continue with synthetic IdP').click()
  const finish=await completed
  assert.equal(finish.status(),200,finish.status()===200?undefined:await finish.text())
  await btn(nav(memberPage),'Workspaces').click()
  await memberPage.getByRole('heading',{name:'Enterprise SSO '+suffix,exact:true}).waitFor()
  assert.equal(assertions,1)
  const session=await memberPage.evaluate(()=>{
    const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
    const {user,access_token}=JSON.parse(localStorage.getItem(key))
    return {user:user.id,token:access_token}
  })
  let scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
  assert.equal(data(await scoped.rpc('st_v7_workspace_uses_sso',{p_workspace:workspace})),true)
  assert.equal(sql("select role from public.st_v2_members where workspace_id='"+workspace+"' and user_id='"+session.user+"';"),'member')
  assert.equal(data(await owner.client.rpc('st_v7_workspace_uses_sso',{p_workspace:workspace})),false)
  const entryBoardTitle='Board item created by a signed member'
  const entryRoomName='Workspace entry room '+suffix
  let entryRoom,entryChannel
  if(entryTest){
    entryRoom=data(await assuredOwner.rpc('st_v6_room_create',{p_id:randomUUID(),p_workspace:workspace,
      p_name:entryRoomName,p_kind:'public',p_template:'blank'}))
    entryChannel=data(await assuredOwner.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'entry-channel-'+suffix}))
    await entryPolicy.getByText(/Enabling it revokes existing room guest message links/).waitFor()
    await btn(entryPolicy,'Require SSO for workspace entry').click()
    const entryGate=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
    await entryGate.getByText('Sign in through your organization to open this workspace.',{exact:true}).waitFor()
    assert.equal(await btn(adminPage,'Board').count(),0)
    assert.equal(await btn(adminPage,'People').count(),0)
    assert.equal(await adminPage.getByLabel('Active workspace').inputValue(),workspace)
    assert.deepEqual(data(await assuredOwner.from('st_v2_workspaces').select('id').eq('id',workspace)),[])
    assert.deepEqual(data(await assuredOwner.rpc('st_v8_workspace_entry_shells',{p_workspaces:[workspace]})),
      [{id:workspace,name:'Enterprise SSO '+suffix}])
    await memberPage.reload()
    await btn(nav(memberPage),'Workspaces').click()
    await memberPage.getByRole('heading',{name:'Enterprise SSO '+suffix,exact:true}).waitFor()
    await btn(memberPage,'Board').click()
    await memberPage.getByText('Add to board',{exact:true}).click()
    await memberPage.getByLabel('Title',{exact:true}).fill(entryBoardTitle)
    await btn(memberPage,'Add item').click()
    await memberPage.getByText(entryBoardTitle,{exact:true}).waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v2_items').select('id').eq('workspace_id',workspace)),[])
    await btn(memberPage.getByRole('group',{name:'Workspace sections'}),'Channels').click()
    await memberPage.getByLabel('Channel',{exact:true}).selectOption(entryChannel)
    const channelBody='Signed workspace entry channel message'
    await memberPage.getByLabel('Channel message',{exact:true}).fill(channelBody)
    await btn(memberPage,'Send message').click()
    await memberPage.getByRole('log',{name:'Channel messages'}).getByText(channelBody,{exact:true}).waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v2_channels').select('id').eq('id',entryChannel)),[])
    assert.deepEqual(data(await assuredOwner.from('st_v2_posts').select('id').eq('channel_id',entryChannel)),[])
    data(await scoped.rpc('st_v6_room_membership',{p_room:entryRoom,p_action:'join'}))
    await btn(nav(memberPage),'Rooms').click()
    await memberPage.getByRole('region',{name:'Room directory',exact:true})
      .getByRole('button',{name:new RegExp(entryRoomName)}).click()
    const memberRoom=memberPage.getByRole('region',{name:entryRoomName,exact:true})
    const roomBody='Signed workspace entry room message'
    await memberRoom.getByLabel('Write a room message',{exact:true}).fill(roomBody)
    await btn(memberRoom,'Send').click()
    await memberRoom.getByText(roomBody,{exact:true}).waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v6_rooms').select('id').eq('id',entryRoom)),[])
    assert.deepEqual(data(await assuredOwner.from('st_v6_room_posts').select('id').eq('room_id',entryRoom)),[])
  }
  let integrationPasswordPage, originalIntegrationKey
  const mutateIntegration=(kind,access,details)=>fetch(new URL('/api/integrations/'+kind,app),{
    method:'POST',headers:{Authorization:'Bearer '+access,'Content-Type':'application/json'},
    body:JSON.stringify({workspace,...details}),
  })
  const integrationRead=()=>fetch(new URL('/api/v1/workspace',app),{
    headers:{Authorization:'Bearer '+originalIntegrationKey},
  })
  if(integrationAdminTest){
    const original=await mutateIntegration('keys',ownerAccess,{action:'create',label:'Original QA integration',lifetime:7,scopes:['workspace:read']})
    assert.equal(original.status,201)
    const credential=await original.json()
    originalIntegrationKey=credential.key
    assert.equal((await integrationRead()).status,200)
    if(entryIntegrationTest){
      await btn(entryPolicy,'Require SSO for workspace entry').click()
      await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    }else{
      await btn(integrationAdminPolicy,'Require SSO for API keys and webhooks').click()
      await integrationAdminPolicy.getByText('Workspace single sign-on is required for API key and webhook management.').waitFor()
    }
    assert.equal(data(await assuredOwner.rpc('st_v6_integration_access',{p_workspace:workspace})),'sso')
    assert.equal((await mutateIntegration('keys',ownerAccess,{action:'revoke',key:credential.id})).status,403)
    assert.equal((await mutateIntegration('webhooks',ownerAccess,{action:'revoke',endpoint:randomUUID()})).status,403)
    assert.equal((await integrationRead()).status,200)
    integrationPasswordPage=await adminContext.newPage()
    await integrationPasswordPage.goto(new URL('/#account',app).href)
    await btn(nav(integrationPasswordPage),'Workspaces').click()
    if(entryIntegrationTest){
      await integrationPasswordPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
      assert.equal(await btn(integrationPasswordPage,'Integrations').count(),0)
    }else{
      await btn(integrationPasswordPage,'Integrations').click()
      const signInMessage='Sign in with workspace single sign-on to manage API keys and webhooks.'
      await integrationPasswordPage.getByText(signInMessage,{exact:true}).waitFor()
      assert.equal(await btn(integrationPasswordPage,'Create API key').count(),0)
      await btn(integrationPasswordPage,'Outbound webhooks').click()
      await integrationPasswordPage.getByText(signInMessage,{exact:true}).waitFor()
      assert.equal(await btn(integrationPasswordPage,'Register webhook').count(),0)
    }

    // Exchange ownership only in the disposable fixture so the real signed
    // account can prove both workspace ownership and its own authenticator.
    const setOwner=(next,previous)=>sql("begin; update public.st_v2_members set role='member' where workspace_id='"+
      workspace+"' and user_id='"+previous+"'; update public.st_v2_members set role='owner' where workspace_id='"+
      workspace+"' and user_id='"+next+"'; update public.st_v2_workspaces set owner='"+next+"' where id='"+workspace+"'; commit;")
    sql("insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('"+session.user+
      "','enterprise','active',now()+interval '1 day') on conflict(user_id) do update set plan=excluded.plan,status=excluded.status,period_end=excluded.period_end;")
    setOwner(session.user,owner.id)
    try{
      await memberPage.reload()
      await btn(nav(memberPage),'Workspaces').click()
      await btn(memberPage,'Integrations').click()
      const integrations=memberPage.getByRole('region',{name:'Workspace integrations',exact:true})
      await verifyStaffPanel(integrations)
      await integrations.getByLabel('Label',{exact:true}).waitFor()
      const integrationAccess=await memberPage.evaluate(()=>{
        const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
        return JSON.parse(localStorage.getItem(key)).access_token
      })
      session.token=integrationAccess
      scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
      const replacement=await mutateIntegration('keys',integrationAccess,{action:'create',label:'Signed QA credential',lifetime:7,scopes:['workspace:read']})
      assert.equal(replacement.status,201)
      const created=await replacement.json()
      assert.equal((await mutateIntegration('keys',integrationAccess,{action:'revoke',key:created.id})).status,204)
    }finally{
      setOwner(owner.id,session.user)
    }
    await adminPage.reload()
    await btn(nav(adminPage),'Workspaces').click()
    if(entryIntegrationTest)await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    else{
      await btn(adminPage,'Integrations').click()
      await btn(adminPage,'Single sign-on').click()
      await btn(config,'Disconnect workspace SSO').waitFor()
    }
  }
  let entryModerationOwnerCase
  if(entryModerationTest){
    const reporter=await account('modr')
    const subject=await account('mods')
    const protectedCase=randomUUID(), ownerCase=randomUUID(), protectedRoom=randomUUID(), ownerRoom=randomUUID()
    entryModerationOwnerCase=ownerCase
    const name='Signed managed moderation '+suffix, ownerName='Password managed moderation '+suffix
    data(await assuredOwner.rpc('st_v8_managed_room_policy',{p_workspace:workspace,p_enabled:true}))
    for(const [room,title] of [[protectedRoom,name],[ownerRoom,ownerName]]){
      data(await assuredOwner.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:title,
        p_kind:'private',p_template:'blank'}))
    }
    sql("update public.st_v2_members set role='admin' where workspace_id='"+workspace+"' and user_id='"+session.user+"';"
      +"insert into public.st_v6_room_members(room_id,user_id,role) values('"+protectedRoom+"','"+session.user+"','moderator');")
    for(const [id,room,reviewer] of [[protectedCase,protectedRoom,session.user],[ownerCase,ownerRoom,owner.id]]){
      sql("insert into sectalk_private.st_v6_room_reports(id,workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace,status,handed_off_at)"
        +" values('"+id+"','"+workspace+"','"+room+"',gen_random_uuid(),'"+reporter.id+"','"+subject.id+"','spam','Private fixture',true,'reviewing',now());"
        +"insert into sectalk_private.st_v6_room_report_stages(report_id,stage,assignee,assigned_at,acknowledge_by,action_by)"
        +" values('"+id+"',3,'"+reviewer+"',now(),now()+interval '1 hour',now()+interval '1 day');")
    }
    assert.ok(data(await assuredOwner.rpc('st_v7_workspace_room_review_queue')).some(row=>row.id===ownerCase))
    await btn(entryPolicy,'Require SSO for workspace entry').click()
    await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    const visitQueue=async page=>{
      await btn(nav(page),'Safety').click()
      await btn(page,'Workspace report review').click()
      return page.getByRole('region',{name:'Workspace room reports',exact:true})
    }
    const blockedQueue=await visitQueue(adminPage)
    await blockedQueue.getByText('No room reports to review.',{exact:true}).waitFor()
    assert.equal(await blockedQueue.getByRole('button',{name:new RegExp(ownerName)}).count(),0)
    const signedQueue=await visitQueue(memberPage)
    await verifyStaffPanel(memberPage)
    await signedQueue.getByRole('button',{name:new RegExp(name)}).click()
    await signedQueue.getByText('Assigned to you',{exact:true}).waitFor()
    for(const [action,reason] of [['acknowledge','Accept signed workspace assignment'],['resolved','Signed workspace review complete']]){
      await signedQueue.getByRole('combobox',{name:'Review action',exact:true}).selectOption(action)
      await signedQueue.getByLabel('Review reason',{exact:true}).fill(reason)
      await btn(signedQueue,'Update room report').click()
      await signedQueue.getByText('Room report updated.',{exact:true}).waitFor()
    }
    const outcomes=data(await reporter.client.rpc('st_v7_my_room_report_status'))
    assert.equal(outcomes.find(row=>row.id===protectedCase)?.status,'resolved')
    assert.equal(outcomes.find(row=>row.id===ownerCase)?.status,'reviewing')
    session.token=await memberPage.evaluate(()=>{
      const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
      return JSON.parse(localStorage.getItem(key)).access_token
    })
    scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
    await btn(nav(adminPage),'Workspaces').click()
    await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    console.log('Passed signed SAML managed-room review, password tab isolation, and independent reporter status.')
  }
  let entryChannelReport
  if(entryChannelReportsTest){
    const reporter=await account('chrpt')
    const subject=await account('chsub')
    const channelName='signed-report-'+suffix
    const channel=data(await assuredOwner.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:channelName}))
    const post=randomUUID()
    sql("update public.st_v2_members set role='admin' where workspace_id='"+workspace+"' and user_id='"+session.user+"';"
      +"insert into public.st_v2_members(workspace_id,user_id,role) values('"+workspace+"','"+reporter.id+"','member'),"
      +"('"+workspace+"','"+subject.id+"','member');")
    const evidence='Synthetic channel moderation evidence'
    data(await subject.client.rpc('st_v2_post',{p_channel:channel,p_id:post,p_body:evidence}))
    entryChannelReport=data(await reporter.client.rpc('st_v7_submit_channel_report',{p_channel:channel,p_post:post,
      p_category:'spam',p_details:'Private channel report note',p_share_with_safety:true,p_share_with_workspace:true}))
    sql("update sectalk_private.st_v7_channel_reports set handed_off_at=now(),state='reviewing' where id='"+entryChannelReport+"';")
    const caseMatches=row=>row.id===entryChannelReport
    assert.ok(data(await assuredOwner.rpc('st_v7_channel_report_queue',{p_scope:'workspace'})).some(caseMatches))
    await btn(entryPolicy,'Require SSO for workspace entry').click()
    await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    for(const page of [adminPage,memberPage]){
      await btn(nav(page),'Safety').click()
      await btn(page,'Workspace report review').click()
    }
    const blocked=adminPage.getByRole('region',{name:'Channel report queue',exact:true})
    await blocked.getByText('No channel reports are available.',{exact:true}).waitFor()
    await verifyStaffPanel(memberPage)
    const review=memberPage.getByRole('region',{name:'Channel report queue',exact:true})
    await review.getByText(new RegExp(channelName)).click()
    await review.getByText(evidence,{exact:true}).waitFor()
    assert.equal(await review.getByText('Private channel report note',{exact:true}).count(),0)
    await review.getByRole('combobox',{name:'Channel review decision',exact:true}).selectOption('resolved')
    await review.getByLabel('Decision reason',{exact:true}).fill('Reviewed through workspace sign-in')
    await btn(review,'Save channel decision').click()
    await review.getByText('Channel report decision saved.',{exact:true}).waitFor()
    assert.equal(data(await reporter.client.rpc('st_v7_my_channel_reports')).find(caseMatches)?.state,'resolved')
    session.token=await memberPage.evaluate(()=>{
      const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
      return JSON.parse(localStorage.getItem(key)).access_token
    })
    scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
    await btn(nav(adminPage),'Workspaces').click()
    await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    console.log('Passed signed SAML channel-report case resolution, password queue isolation, and reporter status.')
  }
  let customRolePasswordPage
  if(customRoleAdminTest){
    const target=randomUUID(), roleId=randomUUID(), roleName='Existing directory delegate'
    const definition={name:roleName,target,scope_type:'group',permissions:['rename'],device:'any',enabled:true}
    data(await assuredOwner.rpc('st_v6_workspace_group_create',{p_workspace:workspace,p_id:target,p_kind:'group',p_name:'SSO role target',p_description:''}))
    const roles=(client,parameters={})=>client.rpc('st_v7_workspace_custom_roles',{p_workspace:workspace,...parameters})
    assert.equal(data(await roles(assuredOwner,{p_action:'save',p_role:roleId,p_revision:0,p_definition:definition})).roles[0].name,roleName)
    await btn(customRoleAdminPolicy,'Require SSO for custom role management').click()
    await customRoleAdminPolicy.getByText('Workspace single sign-on is required for custom role management.').waitFor()
    assert.deepEqual(data(await roles(assuredOwner)),{access:'sso'})
    assert.deepEqual(data(await assuredOwner.rpc('st_v7_custom_role_targets',{p_workspace:workspace})),[])
    customRolePasswordPage=await adminContext.newPage()
    await customRolePasswordPage.goto(new URL('/#account',app).href)
    await btn(nav(customRolePasswordPage),'Workspaces').click()
    await btn(customRolePasswordPage,'Custom roles').click()
    const deniedEditor=customRolePasswordPage.getByRole('region',{name:'Workspace custom roles',exact:true})
    await deniedEditor.getByText('Sign in with workspace single sign-on to manage custom roles.',{exact:true}).waitFor()
    assert.equal(await deniedEditor.getByRole('combobox',{name:/Custom role/}).count(),0)

    const setOwner=(next,previous)=>sql("begin; update public.st_v2_members set role='member' where workspace_id='"+
      workspace+"' and user_id='"+previous+"'; update public.st_v2_members set role='owner' where workspace_id='"+
      workspace+"' and user_id='"+next+"'; update public.st_v2_workspaces set owner='"+next+"' where id='"+workspace+"'; commit;")
    sql("insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('"+session.user+
      "','enterprise','active',now()+interval '1 day') on conflict(user_id) do update set plan=excluded.plan,status=excluded.status,period_end=excluded.period_end;")
    setOwner(session.user,owner.id)
    try{
      await memberPage.reload()
      await btn(nav(memberPage),'Workspaces').click()
      await btn(memberPage,'Custom roles').click()
      const editor=memberPage.getByRole('region',{name:'Workspace custom roles',exact:true})
      await verifyStaffPanel(editor)
      await editor.getByRole('combobox',{name:/Custom role/}).selectOption(roleId)
      await editor.getByLabel('Role name',{exact:true}).fill('Updated signed directory delegate')
      await btn(editor,'Save role revision').click()
      await editor.getByText('Role revision saved.',{exact:true}).waitFor()
      await editor.getByText('Current revision 2',{exact:true}).waitFor()
      session.token=await memberPage.evaluate(()=>{
        const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
        return JSON.parse(localStorage.getItem(key)).access_token
      })
      scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
    }finally{
      setOwner(owner.id,session.user)
    }
    await adminPage.reload()
    await btn(nav(adminPage),'Workspaces').click()
    await btn(adminPage,'Integrations').click()
    await btn(adminPage,'Single sign-on').click()
    await btn(config,'Disconnect workspace SSO').waitFor()
  }
  let policyPasswordPage
  if(policyAdminTest){
    if(entryPolicyAdminTest){
      await btn(entryPolicy,'Require SSO for workspace entry').click()
      await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    }else{
      await btn(policyAdminPolicy,'Require SSO for policy management').click()
      await policyAdminPolicy.getByText('Workspace single sign-on is required for workspace policy management.').waitFor()
    }
    assert.deepEqual(data(await assuredOwner.rpc('st_v7_workspace_policies',{p_workspace:workspace,p_domain:'messaging'})),{access:'sso'})
    assert.equal((await assuredOwner.rpc('st_v6_set_workspace_reactions',{p_workspace:workspace,p_set:'native',p_limit:3})).error?.code,'42501')
    const organization=async(client,days)=>{
      const org=data(await client.rpc('st_v7_org_settings',{p_workspace:workspace}))
      return client.rpc('st_v7_org_settings',{p_workspace:workspace,p_action:'save',p_name:org.name,
        p_accent:org.accent,p_region:org.region,p_days:days})
    }
    policyPasswordPage=await adminContext.newPage()
    await policyPasswordPage.goto(new URL('/#account',app).href)
    await btn(nav(policyPasswordPage),'Workspaces').click()
    if(entryPolicyAdminTest){
      await policyPasswordPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
      assert.equal(await btn(policyPasswordPage,'Policies').count(),0)
      assert.equal(data(await assuredOwner.rpc('st_v6_tenant_feature_state',{p_workspace:workspace})),null)
      assert.equal((await assuredOwner.rpc('st_v6_set_tenant_feature_pause',
        {p_workspace:workspace,p_feature:'task_creation',p_paused:true})).error?.code,'42501')
    }else{
      assert.equal((await organization(assuredOwner,60)).error?.code,'42501')
      assert.equal(data(await organization(assuredOwner,30)).retentionDays,30)
      await btn(policyPasswordPage,'Policies').click()
      const denied='Sign in with workspace single sign-on to manage policies.'
      const editor=policyPasswordPage.getByRole('region',{name:'Workspace policies',exact:true})
      await editor.getByText(denied,{exact:true}).waitFor()
      assert.equal(await btn(editor,'Preview proposed policy').count(),0)
      await btn(policyPasswordPage,'Governance').click()
      await policyPasswordPage.getByText('Policy changes and rollback',{exact:true}).click()
      await policyPasswordPage.getByRole('region',{name:'Policy versions',exact:true}).getByText(denied,{exact:true}).waitFor()
    }

    const setOwner=(next,previous)=>sql("begin; update public.st_v2_members set role='member' where workspace_id='"+
      workspace+"' and user_id='"+previous+"'; update public.st_v2_members set role='owner' where workspace_id='"+
      workspace+"' and user_id='"+next+"'; update public.st_v2_workspaces set owner='"+next+"' where id='"+workspace+"'; commit;")
    sql("insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('"+session.user+
      "','enterprise','active',now()+interval '1 day') on conflict(user_id) do update set plan=excluded.plan,status=excluded.status,period_end=excluded.period_end;")
    setOwner(session.user,owner.id)
    try{
      await memberPage.reload()
      await btn(nav(memberPage),'Workspaces').click()
      await btn(memberPage,'Policies').click()
      const messaging=memberPage.getByRole('region',{name:'Messaging policy',exact:true})
      await verifyStaffPanel(messaging)
      await messaging.getByLabel('Reactions per person',{exact:true}).fill('3')
      const preview=messaging.getByRole('region',{name:'Policy preview',exact:true})
      await btn(messaging,'Preview proposed policy').click()
      await preview.getByText('Preview validated against the live policy. No settings were saved.',{exact:true}).waitFor()
      await btn(preview,'Apply policy').click()
      await messaging.getByText('Policy applied.',{exact:true}).waitFor()
      await messaging.getByText('Current revision 1',{exact:true}).waitFor()
      session.token=await memberPage.evaluate(()=>{
        const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
        return JSON.parse(localStorage.getItem(key)).access_token
      })
      scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
      assert.equal(data(await scoped.rpc('st_v6_workspace_policy_versions',{p_workspace:workspace,p_policy:'notifications'})).version,0)
      assert.equal(data(await organization(scoped,60)).retentionDays,60)
      if(entryPolicyAdminTest){
        data(await scoped.rpc('st_v6_set_tenant_feature_pause',{p_workspace:workspace,p_feature:'task_creation',p_paused:true}))
        const features=data(await scoped.rpc('st_v6_tenant_feature_state',{p_workspace:workspace}))
        assert.equal(features.features.find(feature=>feature.feature==='task_creation')?.paused,true)
      }
    }finally{
      setOwner(owner.id,session.user)
    }
    await adminPage.reload()
    await btn(nav(adminPage),'Workspaces').click()
    if(entryPolicyAdminTest)await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    else{
      await btn(adminPage,'Integrations').click()
      await btn(adminPage,'Single sign-on').click()
      await btn(config,'Disconnect workspace SSO').waitFor()
    }
  }
  let legalHoldPasswordPage
  if(legalHoldTest){
    const original=randomUUID(), room=randomUUID(), rationale='Sensitive synthetic preservation rationale'
    data(await assuredOwner.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:'Legal hold fixture room',
      p_kind:'public',p_template:'blank'}))
    data(await assuredOwner.rpc('st_v6_place_workspace_hold',{p_workspace:workspace,p_id:original,p_room:room,p_member:null,
      p_from:null,p_until:null,p_reason:rationale}))
    await btn(legalHoldPolicy,'Require SSO for legal holds').click()
    await legalHoldPolicy.getByText('Workspace single sign-on is required for legal hold administration.').waitFor()
    const noReceipt=()=>assuredOwner.rpc('st_v6_workspace_hold_state',{p_workspace:workspace})
    assert.deepEqual(data(await noReceipt()),{access:'verified',hold_sso_required:true})
    legalHoldPasswordPage=await adminContext.newPage()
    await legalHoldPasswordPage.goto(new URL('/#account',app).href)
    await btn(nav(legalHoldPasswordPage),'Workspaces').click()
    await btn(legalHoldPasswordPage,'Governance').click()
    const ledger=legalHoldPasswordPage.getByRole('region',{name:'Legal holds',exact:true})
    await ledger.getByText('Sign in with workspace single sign-on to manage legal holds.',{exact:true}).waitFor()
    assert.equal(await ledger.getByText(rationale,{exact:true}).count(),0)
    assert.equal(await ledger.getByText('Place a preservation hold',{exact:true}).count(),0)
    await ledger.getByText('Emergency access approvals',{exact:true}).waitFor()
    await ledger.getByText('Policy changes and rollback',{exact:true}).click()
    await ledger.getByRole('heading',{name:'Version history',exact:true}).waitFor()

    const setOwner=(next,previous)=>sql("begin; update public.st_v2_members set role='member' where workspace_id='"+
      workspace+"' and user_id='"+previous+"'; update public.st_v2_members set role='owner' where workspace_id='"+
      workspace+"' and user_id='"+next+"'; update public.st_v2_workspaces set owner='"+next+"' where id='"+workspace+"'; commit;")
    sql("insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('"+session.user+
      "','enterprise','active',now()+interval '1 day') on conflict(user_id) do update set plan=excluded.plan,status=excluded.status,period_end=excluded.period_end;")
    setOwner(session.user,owner.id)
    try{
      await memberPage.reload()
      await btn(nav(memberPage),'Workspaces').click()
      await btn(memberPage,'Policies').click()
      const policy=memberPage.getByRole('region',{name:'Messaging policy',exact:true})
      await verifyStaffPanel(policy)
      await policy.getByText('Current revision 0',{exact:true}).waitFor()
      await btn(memberPage,'Governance').click()
      const signedLedger=memberPage.getByRole('region',{name:'Legal holds',exact:true})
      await signedLedger.getByText(rationale,{exact:true}).waitFor()
      await signedLedger.getByText('Place a preservation hold',{exact:true}).click()
      await signedLedger.getByLabel('On or after',{exact:true}).fill('2035-01-01T00:00')
      await signedLedger.getByLabel('Preservation reason',{exact:true}).fill('Preserve selected evidence for signed testing')
      await btn(signedLedger,'Place hold').click()
      await signedLedger.getByText('Preservation hold placed.',{exact:true}).waitFor()
      session.token=await memberPage.evaluate(()=>{
        const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
        return JSON.parse(localStorage.getItem(key)).access_token
      })
      scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
      assert.equal(data(await scoped.rpc('st_v6_workspace_hold_state',{p_workspace:workspace})).holds.length,2)
    }finally{
      setOwner(owner.id,session.user)
    }
    await adminPage.reload()
    await btn(nav(adminPage),'Workspaces').click()
    await btn(adminPage,'Integrations').click()
    await btn(adminPage,'Single sign-on').click()
    await btn(config,'Disconnect workspace SSO').waitFor()
  }
  let compliancePasswordPage
  let complianceCase
  const getCompliance=(method,token)=>fetch(new URL('/api/compliance-exports/'+complianceCase,app),{
    method,headers:{Authorization:'Bearer '+token},
  })
  if(complianceTest){
    const name='Signed compliance audit case'
    sql("update public.st_v2_members set role='admin' where workspace_id='"+workspace+"' and user_id='"+session.user+"';")
    await memberPage.reload()
    await btn(nav(memberPage),'Workspaces').click()
    await btn(memberPage,'Compliance exports').click()
    const panel=memberPage.getByRole('region',{name:'Compliance exports',exact:true})
    await verifyStaffPanel(panel)
    await panel.getByText('Request an export',{exact:true}).waitFor()
    session.token=await memberPage.evaluate(()=>{
      const key=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
      return JSON.parse(localStorage.getItem(key)).access_token
    })
    scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
    const source=data(await scoped.rpc('st_v7_compliance_sources',{p_workspace:workspace})).find(row=>row.kind==='audit')
    assert.ok(source)
    complianceCase=data(await scoped.rpc('st_v7_request_compliance_export',{p_workspace:workspace,p_reference:name,
      p_reason:'Approved synthetic audit case for the signed browser fixture',p_sources:[{kind:source.kind,id:source.id}]}))
    data(await assuredOwner.rpc('st_v7_review_compliance_export',{p_case:complianceCase,p_action:'approved',
      p_reason:'Approve the exact audit record for this synthetic browser fixture'}))
    if(entryComplianceTest){
      await btn(entryPolicy,'Require SSO for workspace entry').click()
      await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    }else{
      await btn(compliancePolicy,'Require SSO for compliance exports and evidence').click()
      await compliancePolicy.getByText('Workspace single sign-on is required for compliance exports and evidence.').waitFor()
    }
    assert.equal(data(await assuredOwner.rpc('st_v7_compliance_access',{p_workspace:workspace})),'sso')
    assert.equal((await assuredOwner.rpc('st_v7_compliance_cases',{p_workspace:workspace})).error?.code,'42501')
    compliancePasswordPage=await adminContext.newPage()
    await compliancePasswordPage.goto(new URL('/#account',app).href)
    await btn(nav(compliancePasswordPage),'Workspaces').click()
    if(entryComplianceTest){
      await compliancePasswordPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
      assert.equal(await btn(compliancePasswordPage,'Compliance exports').count(),0)
      assert.deepEqual(data(await assuredOwner.rpc('st_v7_evidence_vault',{p_workspace:workspace})),{access:'sso'})
    }else{
      await btn(compliancePasswordPage,'Compliance exports').click()
      const deniedPanel=compliancePasswordPage.getByRole('region',{name:'Compliance exports',exact:true})
      await deniedPanel.getByText('Sign in with workspace single sign-on to manage compliance exports.',{exact:true}).waitFor()
      assert.equal(await deniedPanel.getByRole('heading',{name,exact:true}).count(),0)
      await btn(compliancePasswordPage,'Governance').click()
      await compliancePasswordPage.getByText('Evidence vault',{exact:true}).click()
      await compliancePasswordPage.getByText('Sign in with workspace single sign-on to access evidence custody.',{exact:true}).waitFor()
    }
    await btn(panel,'Refresh export cases').click()
    const card=panel.getByRole('article').filter({has:memberPage.getByRole('heading',{name,exact:true})})
    await btn(card,'Build private bundle').click()
    await panel.getByText('Private export built.',{exact:true}).waitFor()
    complianceSsoObjects.push(sql("select artifact from sectalk_private.st_v7_compliance_cases where id='"+complianceCase+"';"))
    const exported=await getCompliance('GET',session.token)
    assert.equal(exported.status,200)
    assert.ok((await exported.text()).includes(source.label))
  }
  let invitationPasswordPage
  if(invitationAdminTest){
    const invited=await account('invite_target')
    assert.equal(data(await assuredOwner.rpc('st_v2_invite',{p_workspace:workspace,p_handle:invited.handle})),true)
    const outgoing=()=>assuredOwner.from('st_v2_invites').select('id').eq('workspace_id',workspace).eq('invitee',invited.id)
    assert.equal(data(await outgoing()).length,1)
    if(inviteEntryTest){
      await btn(entryPolicy,'Require SSO for workspace entry').click()
      await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    }else{
      await btn(invitationAdminPolicy,'Require SSO for invitation management').click()
      await invitationAdminPolicy.getByText('Workspace single sign-on is required for workspace invitation management.').waitFor()
    }
    assert.deepEqual(data(await outgoing()),[])
    assert.equal((await assuredOwner.rpc('st_v2_invite',{p_workspace:workspace,p_handle:invited.handle})).error?.code,'42501')
    assert.equal((await assuredOwner.rpc('st_v6_bulk_workspace_invite',{p_workspace:workspace,p_handles:[invited.handle]})).error?.code,'42501')
    assert.equal((await assuredOwner.rpc('st_v6_workspace_link_policy_get',{p_workspace:workspace})).error?.code,'42501')
    if(process.env.SECTALK_TEST_SSO_INVITE_EMAIL_ROUTE==='1'){
      const mail=await fetch(new URL('/api/workspaces/invitations',app),{method:'POST',
        headers:{Authorization:'Bearer '+ownerAccess,'Content-Type':'application/json'},
        body:JSON.stringify({workspace,email:invited.email,hours:24})})
      assert.equal(mail.status,403)
    }
    invitationPasswordPage=await adminContext.newPage()
    await invitationPasswordPage.goto(new URL('/#account',app).href)
    await btn(nav(invitationPasswordPage),'Workspaces').click()
    if(inviteEntryTest)await invitationPasswordPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    else await invitationPasswordPage.getByText('Sign in with workspace single sign-on to manage invitations.').waitFor()
    assert.equal(await invitationPasswordPage.getByText('Email invitation links',{exact:true}).count(),0)
    assert.equal(await invitationPasswordPage.getByLabel('Invite by SecTalk handle').count(),0)

    const invitedPage=await browser.newPage()
    await invitedPage.goto(new URL('/#account',app).href)
    await invitedPage.getByLabel('Email address',{exact:true}).fill(invited.email)
    await invitedPage.getByLabel('Password',{exact:true}).fill(password)
    await invitedPage.locator('button.submit-auth').click()
    await btn(nav(invitedPage),'Workspaces').click()
    const incoming=invitedPage.locator('section').filter({has:invitedPage.getByRole('heading',{name:'Invitations',exact:true})})
    await btn(incoming,'Join').click()
    if(inviteEntryTest)await invitedPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    else await invitedPage.getByRole('heading',{name:'Enterprise SSO '+suffix,exact:true}).waitFor()
    assert.equal(sql("select role from public.st_v2_members where workspace_id='"+workspace+"' and user_id='"+invited.id+"';"),'member')
    assert.equal(data(await invited.client.rpc('st_v7_workspace_uses_sso',{p_workspace:workspace})),false)
    await invitedPage.close()

    // Promote the already verified synthetic member to exercise the normal manager controls.
    sql("update public.st_v2_members set role='admin' where workspace_id='"+workspace+"' and user_id='"+session.user+"';")
    assert.equal(data(await scoped.rpc('st_v8_workspace_invitation_admin_requires_sso',{p_workspace:workspace})),false)
    await memberPage.reload()
    await btn(nav(memberPage),'Workspaces').click()
    await memberPage.getByText('Email invitation links',{exact:true}).click()
    await memberPage.getByLabel('Invited email').fill('link-'+suffix+'@example.invalid')
    await btn(memberPage,'Create single-use link').click()
    await memberPage.getByLabel('Invitation link',{exact:true}).waitFor()
  }
  const structureRoom=randomUUID(), structureRoomName='Structure room '+suffix
  let roomPasswordPage, blockedCatalog
  const openCatalog=async page=>{
    await btn(nav(page),'Profile').click()
    await btn(page,'Security').click()
    const catalog=page.getByRole('region',{name:'Permission catalog',exact:true})
    await btn(catalog,'View my permissions').click()
    await catalog.getByLabel('Workspace for permissions').selectOption(workspace)
    return catalog
  }
  if(roomStructureTest){
    const roomInput={p_id:structureRoom,p_workspace:workspace,p_name:structureRoomName,p_kind:'public',p_template:'blank'}
    data(await assuredOwner.rpc('st_v6_room_create',roomInput))
    await btn(roomStructurePolicy,'Require SSO for the room directory').click()
    await roomStructurePolicy.getByText('Workspace single sign-on is required for the room directory and room management.').waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v6_rooms').select('id').eq('id',structureRoom)),[])
    assert.deepEqual(data(await assuredOwner.from('st_v6_room_members').select('user_id').eq('room_id',structureRoom)),[])
    assert.deepEqual(data(await assuredOwner.rpc('st_v6_room_management_audit',{p_room:structureRoom})),[])
    assert.equal((await assuredOwner.rpc('st_v6_room_create',{...roomInput,p_id:randomUUID()})).error?.code,'42501')
    assert.equal((await assuredOwner.rpc('st_v6_manage_room',{p_room:structureRoom,p_action:'archive'})).error?.code,'42501')
    roomPasswordPage=await adminContext.newPage()
    await roomPasswordPage.goto(new URL('/#account',app).href)
    await btn(nav(roomPasswordPage),'Rooms').click()
    await roomPasswordPage.getByText('Sign in with workspace single sign-on to open the room directory.').waitFor()
    assert.equal(await roomPasswordPage.getByText('Create a room',{exact:true}).count(),0)
    await btn(nav(memberPage),'Rooms').click()
    const directory=memberPage.getByRole('region',{name:'Room directory',exact:true})
    await btn(directory,structureRoomName+' Workspace-wide').click()
    await btn(directory,'Join room').click()
    await btn(directory,'Join room').waitFor({state:'hidden'})
    assert.equal(data(await scoped.rpc('st_v6_room_my_role',{p_room:structureRoom})),'member')
    if(navigationTest){
      const hidden=data(await assuredOwner.rpc('st_v7_permission_catalog',{p_workspace:workspace,p_room:structureRoom}))
      assert.equal(hidden.room_requires_sso,true)
      assert.deepEqual([hidden.rooms,hidden.room_role,hidden.room],[[],null,{}])
      assert.equal(data(await assuredOwner.rpc('st_v6_room_permission_state',{p_room:structureRoom})),null)
      const catalogPasswordPage=await adminContext.newPage()
      await catalogPasswordPage.goto(new URL('/#account',app).href)
      blockedCatalog=await openCatalog(catalogPasswordPage)
      await blockedCatalog.getByText('Sign in with workspace single sign-on to view room permissions.',{exact:true}).waitFor()
      assert.equal(await blockedCatalog.getByLabel('Room for permissions').count(),0)
      const allowedCatalog=await openCatalog(memberPage)
      await allowedCatalog.getByLabel('Room for permissions').selectOption(structureRoom)
      await allowedCatalog.getByRole('heading',{name:'Room role: member',exact:true}).waitFor()
    }
    await btn(nav(memberPage),'Workspaces').click()
  }
  let structureChannel, channelPasswordPage
  if(channelStructureTest){
    structureChannel=data(await assuredOwner.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'channel-structure-'+suffix}))
    await btn(channelStructurePolicy,'Require SSO for the channel directory').click()
    await channelStructurePolicy.getByText('Workspace single sign-on is required for the channel directory and channel management.').waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v2_channels').select('id').eq('id',structureChannel)),[])
    assert.equal((await assuredOwner.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'blocked-'+suffix})).error?.code,'42501')
    assert.equal((await assuredOwner.rpc('st_v6_manage_channel',{p_channel:structureChannel,p_action:'archive'})).error?.code,'42501')
    assert.deepEqual(data(await assuredOwner.rpc('st_v6_channel_details',{p_channel:structureChannel})),
      {can_read:false,can_manage:false,structure_sso_required:true})
    channelPasswordPage=await adminContext.newPage()
    await channelPasswordPage.goto(new URL('/#account',app).href)
    await btn(nav(channelPasswordPage),'Workspaces').click()
    await btn(channelPasswordPage,'Channels').click()
    await channelPasswordPage.getByText('Sign in with workspace single sign-on to open the channel directory.').waitFor()
    assert.equal(await channelPasswordPage.getByText('New channel',{exact:true}).count(),0)
    await btn(memberPage,'Channels').click()
    await memberPage.getByRole('combobox',{name:'Channel',exact:true}).selectOption({label:'#channel-structure-'+suffix})
    await memberPage.getByRole('heading',{name:'#channel-structure-'+suffix,exact:true}).waitFor()
    assert.equal(data(await scoped.from('st_v2_channels').select('id').eq('id',structureChannel).single()).id,structureChannel)
  }
  let organizationPasswordPage
  const requestOrganization=(access,action='region',domain)=>fetch(new URL('/api/workspaces/organization',app),{
    method:'POST',headers:{Authorization:'Bearer '+access,'Content-Type':'application/json'},
    body:JSON.stringify({workspace,action,domain}),
  })
  if(organizationTest){
    const pendingDomain='sso-policy-'+suffix+'.example.invalid'
    data(await assuredOwner.rpc('st_v7_org_settings',{p_workspace:workspace,p_action:'domain.start',p_domain:pendingDomain}))
    if(entryOrganizationTest){
      await btn(entryPolicy,'Require SSO for workspace entry').click()
      await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    }else{
      await btn(organizationPolicy,'Require SSO for organization settings').click()
      await organizationPolicy.getByText('Workspace single sign-on is required for organization settings.').waitFor()
    }
    assert.equal((await assuredOwner.rpc('st_v7_org_settings',{p_workspace:workspace})).error?.code,'42501')
    assert.equal((await assuredOwner.rpc('st_v8_workspace_residency',{p_workspace:workspace})).error?.code,'42501')
    assert.equal((await requestOrganization(ownerAccess)).status,403)
    assert.equal((await requestOrganization(ownerAccess,'verify-domain',pendingDomain)).status,403)
    organizationPasswordPage=await adminContext.newPage()
    await organizationPasswordPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
    await btn(nav(organizationPasswordPage),'Workspaces').click()
    const passwordRestriction=async()=>{
      if(entryOrganizationTest){
        await organizationPasswordPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
        assert.equal(await btn(organizationPasswordPage,'Organization settings').count(),0)
      }else{
        await btn(organizationPasswordPage,'Organization settings').click()
        await organizationPasswordPage.getByText('Sign in through your workspace provider to manage organization settings.',{exact:true}).waitFor()
        assert.equal(await organizationPasswordPage.getByRole('region',{name:'Organization domains'}).count(),0)
        await organizationPasswordPage.getByRole('region',{name:'Workspace offboarding'}).waitFor()
      }
    }
    await passwordRestriction()

    const setFixtureOwner=(current,next)=>sql("begin; update public.st_v2_members set role='member' where workspace_id='"+workspace+
      "' and user_id='"+current+"'; update public.st_v2_members set role='owner' where workspace_id='"+workspace+
      "' and user_id='"+next+"'; update public.st_v2_workspaces set owner='"+next+"' where id='"+workspace+"'; commit;")
    sql("insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('"+session.user+"','enterprise','active',now()+interval '1 day');")
    setFixtureOwner(owner.id,session.user)
    try{
      const signedOrganization=await memberContext.newPage()
      await signedOrganization.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
      await btn(nav(signedOrganization),'Workspaces').click()
      await btn(signedOrganization,'Organization settings').click()
      await signedOrganization.getByRole('region',{name:'Organization domains'}).waitFor()
      assert.equal(data(await scoped.rpc('st_v7_org_settings',{p_workspace:workspace})).name,'Enterprise SSO '+suffix)
      assert.equal(data(await scoped.rpc('st_v8_workspace_residency',{p_workspace:workspace})).eligible,true)
      assert.equal((await requestOrganization(session.token)).status,200)
      await signedOrganization.close()
    } finally {
      setFixtureOwner(session.user,owner.id)
    }
    // Restore both owner tabs after the disposable SAML owner fixture changes roles.
    await adminPage.reload({waitUntil:'domcontentloaded'})
    await btn(nav(adminPage),'Workspaces').click()
    if(entryOrganizationTest)await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    else{
      await btn(adminPage,'Integrations').click()
      await btn(adminPage,'Single sign-on').click()
      await btn(config,'Disconnect workspace SSO').waitFor()
    }
    await organizationPasswordPage.reload({waitUntil:'domcontentloaded'})
    await btn(nav(organizationPasswordPage),'Workspaces').click()
    await passwordRestriction()
  }
  let ownerBillingPage
  const billingRequest=(route,token)=>fetch(new URL('/api/billing/'+route+'?workspace='+workspace,app),
    {headers:{Authorization:'Bearer '+token}})
  if(billingTest){
    data(await assuredOwner.rpc('st_v7_billing_admin_manage',{p_workspace:workspace,p_account:session.user,p_enabled:true}))
    if(entryBillingTest){
      await btn(entryPolicy,'Require SSO for workspace entry').click()
      await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    }else{
      await btn(billingPolicy,'Require SSO for workspace billing').click()
      await billingPolicy.getByText('Workspace single sign-on is required for workspace billing administration.').waitFor()
    }
    assert.equal((await assuredOwner.rpc('st_v7_billing_admin_manage',{p_workspace:workspace})).error?.code,'42501')
    assert.equal((await assuredOwner.rpc('st_v7_workspace_usage',{p_workspace:workspace})).error?.code,'42501')
    assert.equal(data(await assuredOwner.from('st_v2_subscriptions').select('plan').eq('user_id',owner.id).single()).plan,'enterprise')
    ownerBillingPage=await adminContext.newPage()
    await ownerBillingPage.goto(new URL('/billing/workspaces',app).href,{waitUntil:'domcontentloaded'})
    await ownerBillingPage.getByLabel('Workspace',{exact:true}).selectOption(workspace)
    await ownerBillingPage.getByText('Sign in through your workspace provider to access billing records.',{exact:true}).waitFor()
    assert.equal(await ownerBillingPage.getByRole('region',{name:'Billing administrator access'}).count(),0)
    const delegatedPage=await memberContext.newPage()
    await delegatedPage.goto(new URL('/billing/workspaces',app).href,{waitUntil:'domcontentloaded'})
    await delegatedPage.getByLabel('Workspace',{exact:true}).selectOption(workspace)
    await delegatedPage.getByRole('region',{name:'Plan, seats and usage'}).waitFor()
    assert.equal(data(await scoped.rpc('st_v7_billing_admin_view',{p_workspace:workspace})).plan,'enterprise')
    assert.equal((await billingRequest('workspace',session.token)).status,200)
    assert.equal((await billingRequest('workspace',ownerAccess)).status,403)
    assert.equal((await billingRequest('invoices',ownerAccess)).status,403)
  }
  const testFile=randomUUID(), testRoomFile=randomUUID(), fileRoom=randomUUID()
  const fileName='workspace-sso-'+suffix+'.txt'
  let filePasswordPage
  const fileRequest=(access,{room,file,action,upload=false}={})=>{
    const route=room?'room-files':'workspace-files'
    const query=new URLSearchParams(room?{room:fileRoom}:{workspace})
    if(file)query.set('file',file)
    if(action)query.set('action',action)
    return fetch(new URL('/api/'+route+'?'+query,app),{
      method:upload||action?'POST':'GET',
      headers:{Authorization:'Bearer '+access,...(upload?{'Content-Type':'text/plain','X-SecTalk-File-Name':fileName}:{})},
      body:upload?fileSsoBody:undefined,
    })
  }
  if(fileTest){
    await assuredOwner.rpc('st_v6_room_create',{p_id:fileRoom,p_workspace:workspace,p_name:'Scoped file fixture',p_kind:'private',p_template:'project'}).then(data)
    sql("insert into public.st_v6_room_members(room_id,user_id,role) values('"+fileRoom+"','"+session.user+"','member');")
    fileSsoObjects.push(workspace+'/'+testFile,workspace+'/rooms/'+fileRoom+'/'+testRoomFile)
    const uploaded=await fileRequest(ownerAccess,{file:testFile,upload:true})
    assert.equal(uploaded.status,200,await uploaded.text())
    const prior=await fileRequest(ownerAccess,{file:testFile,action:'share'})
    assert.equal(prior.status,200)
    const {path}=await prior.json()
    assert.equal(path,'/workspace-file/'+workspace+'/'+testFile)
    if(entryFileTest){
      await btn(entryPolicy,'Require SSO for workspace entry').click()
      await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    }else{
      await btn(filePolicy,'Require SSO for workspace and room files').click()
      await filePolicy.getByText('Workspace single sign-on is required for workspace and room files.').waitFor()
    }
    assert.equal((await fileRequest(ownerAccess,{file:testFile})).status,403)
    assert.equal((await fileRequest(ownerAccess,{room:true})).status,entryFileTest?404:403)
    if(entryFileTest){
      for(const query of ['offboarding','residency-verify']){
        const tried=await fetch(new URL('/api/workspace-files?'+new URLSearchParams({workspace,file:testFile,[query]:randomUUID()}),app),
          {headers:{Authorization:'Bearer '+ownerAccess}})
        assert.equal(tried.status,404)
      }
    }
    const roomUploaded=await fileRequest(session.token,{room:true,file:testRoomFile,upload:true})
    assert.equal(roomUploaded.status,200,await roomUploaded.text())
    const roomDownloaded=await fileRequest(session.token,{room:true,file:testRoomFile})
    assert.equal(roomDownloaded.status,200)
    assert.deepEqual(Buffer.from(await roomDownloaded.arrayBuffer()),fileSsoBody)
    await btn(memberPage.getByRole('group',{name:'Workspace sections'}),'Files').click()
    const signedPanel=memberPage.getByRole('region',{name:'Workspace files',exact:true})
    await signedPanel.getByRole('heading',{name:fileName,exact:true}).waitFor()
    const downloadReady=memberPage.waitForEvent('download')
    await btn(signedPanel,'Download file').click()
    assert.equal((await downloadReady).suggestedFilename(),fileName)
    const oldLink=await adminContext.newPage()
    await oldLink.goto(new URL(path,app).href,{waitUntil:'domcontentloaded'})
    await oldLink.getByText('Sign in through your workspace provider to access files.',{exact:true}).waitFor()
    filePasswordPage=await adminContext.newPage()
    await filePasswordPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
    await btn(nav(filePasswordPage),'Workspaces').click()
    if(entryFileTest)await filePasswordPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    else{
      await btn(filePasswordPage.getByRole('group',{name:'Workspace sections'}),'Files').click()
      await filePasswordPage.getByText('Sign in through your workspace provider to access files.',{exact:true}).waitFor()
    }
    assert.equal(await filePasswordPage.getByLabel('Choose workspace file').count(),0)
  }
  let groupsPasswordPage
  const team=randomUUID()
  const teamName='Workspace team '+suffix
  if(groupsTest){
    data(await assuredOwner.rpc('st_v6_workspace_group_create',{p_workspace:workspace,p_id:team,p_kind:'team',p_name:teamName,p_description:'Signed roster fixture'}))
    data(await assuredOwner.rpc('st_v6_workspace_group_change',{p_workspace:workspace,p_id:team,p_action:'member_added',p_user:session.user}))
    await btn(groupsPolicy,'Require SSO for groups and teams').click()
    await groupsPolicy.getByText('Workspace single sign-on is required for workspace groups and teams.').waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v6_workspace_groups').select('id').eq('id',team)),[])
    assert.deepEqual(data(await assuredOwner.from('st_v6_workspace_group_members').select('user_id').eq('group_id',team)),[])
    assert.equal((await assuredOwner.rpc('st_v6_workspace_group_change',{p_workspace:workspace,p_id:team,p_action:'archive'})).error?.code,'42501')
    assert.equal(data(await scoped.from('st_v6_workspace_group_members').select('user_id').eq('group_id',team).single()).user_id,session.user)
    await btn(memberPage.getByRole('group',{name:'Workspace sections'}),'Groups & teams').click()
    await btn(memberPage,teamName).click()
    await memberPage.getByText('Signed roster fixture',{exact:true}).waitFor()
    groupsPasswordPage=await adminContext.newPage()
    await groupsPasswordPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
    await btn(nav(groupsPasswordPage),'Workspaces').click()
    await btn(groupsPasswordPage.getByRole('group',{name:'Workspace sections'}),'Groups & teams').click()
    await groupsPasswordPage.getByText('Sign in through your workspace provider to view or manage groups and teams.').waitFor()
    assert.equal(await btn(groupsPasswordPage,teamName).count(),0)
    assert.equal(await groupsPasswordPage.getByText('New team',{exact:true}).count(),0)
  }
  let schedulePasswordPage
  const scheduleMeeting=randomUUID()
  const scheduleTitle='Workspace meeting '+suffix
  if(scheduleTest){
    const start=new Date().toISOString(), end=new Date(Date.now()+3600000).toISOString()
    data(await assuredOwner.rpc('st_v3_schedule',{p_workspace:workspace,p_title:scheduleTitle,p_agenda:'SSO fixture',
      p_start:start,p_end:end,p_id:scheduleMeeting}))
    data(await assuredOwner.rpc('st_v3_meeting_state',{p_meeting:scheduleMeeting,p_state:'live'}))
    await btn(schedulePolicy,'Require SSO for workspace meetings').click()
    await schedulePolicy.getByText('Workspace single sign-on is required for workspace meeting schedules and lobbies.').waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v3_meetings').select('id').eq('id',scheduleMeeting)),[])
    assert.deepEqual(data(await assuredOwner.from('st_v3_attendance').select('user_id').eq('meeting_id',scheduleMeeting)),[])
    assert.equal((await assuredOwner.rpc('st_v3_request_admission',{p_meeting:scheduleMeeting})).error?.code,'42501')
    await btn(nav(memberPage),'Meetings').click()
    await btn(memberPage,scheduleTitle).click()
    await btn(memberPage,'Request admission').click()
    await memberPage.getByText('Waiting for the host to admit you',{exact:true}).waitFor()
    assert.equal(data(await scoped.from('st_v3_attendance').select('status').eq('meeting_id',scheduleMeeting).single()).status,'waiting')
    schedulePasswordPage=await adminContext.newPage()
    await schedulePasswordPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
    await btn(nav(schedulePasswordPage),'Meetings').click()
    await schedulePasswordPage.getByText('Sign in through your workspace provider to access meeting schedules and lobbies.').waitFor()
    assert.equal(await btn(schedulePasswordPage,scheduleTitle).count(),0)
    assert.equal(await btn(schedulePasswordPage,'Schedule').count(),0)
    await btn(nav(schedulePasswordPage),'Calendar').click()
    await schedulePasswordPage.getByText('Sign in through your workspace provider to see workspace meeting schedules.').waitFor()
    assert.equal(await schedulePasswordPage.getByText(scheduleTitle,{exact:true}).count(),0)
  }
  let auditPasswordPage
  const artifactMeeting=randomUUID(), artifactRecording=randomUUID(), artifactTitle='Protected meeting artifacts '+suffix
  const recordingAsset=Buffer.from('OggS local synthetic meeting recording '+suffix)
  const artifactDownload=token=>fetch(new URL('/api/meetings/recordings?'+new URLSearchParams({
    meeting:artifactMeeting,recording:artifactRecording,
  }),app),{headers:{Authorization:'Bearer '+token}})
  const artifactAction=(token,route,action)=>fetch(new URL('/api/meetings/'+route,app),{
    method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
    body:JSON.stringify({meeting:artifactMeeting,action}),
  })
  if(entryArtifactTest){
    sql("begin; insert into public.st_v3_meetings(id,workspace_id,host_id,title,status,starts_at,ends_at) values('"+
      artifactMeeting+"','"+workspace+"','"+owner.id+"','"+artifactTitle+"','ended',now()-interval '30 minutes',now()-interval '5 minutes');"+
      "insert into sectalk_private.st_v6_recording(meeting_id,id,status,roster,approvals) values('"+artifactMeeting+"','"+artifactRecording+
      "','ready',jsonb_build_object('"+owner.id+"','PA_fixture_owner','"+session.user+"','PA_fixture_member'),"+
      "jsonb_build_object('"+owner.id+"',true,'"+session.user+"',true));"+
      "insert into sectalk_private.st_v6_caption_session(meeting,source_language,expires_at,line_count) values('"+artifactMeeting+
      "','en',now()+interval '1 day',1);"+
      "insert into sectalk_private.st_v6_caption_consent(meeting,actor,participant_sid) values('"+artifactMeeting+"','"+owner.id+
      "','PA_fixture_owner'),('"+artifactMeeting+"','"+session.user+"','PA_fixture_member');"+
      "insert into sectalk_private.st_v6_caption_line(meeting,actor,sequence,speaker,line) values('"+artifactMeeting+"','"+session.user+
      "',1,'Fixture member','The synthetic project milestone is confirmed.');"+
      "select public.st_v6_meeting_summary_command('"+artifactMeeting+"','"+owner.id+"','policy',true);"+
      "select public.st_v6_meeting_summary_command('"+artifactMeeting+"','"+owner.id+"','opt-in');"+
      "select public.st_v6_meeting_summary_command('"+artifactMeeting+"','"+session.user+"','opt-in'); commit;")
    const object=artifactMeeting+'/'+artifactRecording+'/meeting.ogg'
    data(await admin.storage.from('recordings').upload(object,recordingAsset,{contentType:'audio/ogg'}))
    recordingSsoObjects.push(object)
    assert.equal((await artifactDownload(ownerAccess)).status,200)
    assert.equal((await artifactAction(ownerAccess,'summaries','generate')).status,200)
    await btn(entryPolicy,'Require SSO for workspace entry').click()
    await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    assert.equal((await artifactDownload(ownerAccess)).status,404)
    assert.equal((await artifactAction(ownerAccess,'recordings','view')).status,403)
    assert.equal((await artifactAction(ownerAccess,'summaries','generate')).status,403)
    const signedDownload=await artifactDownload(session.token)
    assert.equal(signedDownload.status,200)
    assert.deepEqual(Buffer.from(await signedDownload.arrayBuffer()),recordingAsset)
    assert.equal((await artifactAction(session.token,'recordings','view')).status,200)
    await memberPage.goto(new URL('/?meeting='+artifactMeeting,app).href)
    const summary=memberPage.getByRole('region',{name:'Meeting summary',exact:true})
    await btn(summary,'Generate summary draft').click()
    assert.equal(await summary.getByLabel('Summary text',{exact:true}).inputValue(),'The synthetic project milestone is confirmed.')
  }
  const entryLobby=randomUUID(),entryMedia=randomUUID()
  const entryLobbyTitle='Protected entry lobby '+suffix
  let entryMediaBinding
  const entryToken=(token)=>fetch(new URL('/api/meetings/token',app),{
    method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
    body:JSON.stringify({meetingId:entryMedia}),
  })
  const admission=(actor,binding)=>admin.rpc('st_v8_livekit_bound_admission',{
    p_kind:'managed',p_room:entryMedia,p_actor:actor,p_generation:null,p_binding:binding,
  })
  async function entryBinding(response){
    assert.equal(response.status,200)
    const {token}=await response.json()
    const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url'))
    assert.equal(claims.video.room,'sectalk-v3-'+entryMedia)
    assert.equal(claims.video.roomJoin,true)
    return claims.attributes['sectalk.media.binding']
  }
  if(entryMeetingTest){
    const start=new Date().toISOString(),end=new Date(Date.now()+3600000).toISOString()
    for(const [id,title] of [[entryLobby,entryLobbyTitle],[entryMedia,'Protected entry media '+suffix]]){
      data(await assuredOwner.rpc('st_v3_schedule',{p_workspace:workspace,p_title:title,p_agenda:'Synthetic QA',
        p_start:start,p_end:end,p_id:id}))
      data(await assuredOwner.rpc('st_v3_meeting_state',{p_meeting:id,p_state:'live'}))
    }
    sql("insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at) values('"+
      entryMedia+"','"+session.user+"','admitted',now());")
    const oldBinding=await entryBinding(await entryToken(ownerAccess))
    await btn(entryPolicy,'Require SSO for workspace entry').click()
    await adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true}).waitFor()
    assert.equal(data(await admission(owner.id,oldBinding)),false)
    assert.equal((await entryToken(ownerAccess)).status,403)
    assert.deepEqual(data(await assuredOwner.from('st_v3_meetings').select('id').eq('id',entryLobby)),[])
    assert.equal((await assuredOwner.rpc('st_v3_request_admission',{p_meeting:entryLobby})).error?.code,'42501')
    await btn(nav(adminPage),'Meetings').click()
    await adminPage.getByText('Sign in through your workspace provider to access meeting schedules and lobbies.').waitFor()
    assert.equal(await btn(adminPage,entryLobbyTitle).count(),0)
    await btn(nav(memberPage),'Meetings').click()
    await btn(memberPage,entryLobbyTitle).click()
    await btn(memberPage,'Request admission').click()
    await memberPage.getByText('Waiting for the host to admit you',{exact:true}).waitFor()
    entryMediaBinding=await entryBinding(await entryToken(session.token))
    assert.equal(data(await admission(session.user,entryMediaBinding)),true)
  }
  if(auditTest){
    sql("update public.st_v2_members set role='admin' where workspace_id='"+workspace+"' and user_id='"+session.user+"';")
    await btn(auditPolicy,'Require SSO for workspace audit logs').click()
    await auditPolicy.getByText('Workspace single sign-on is required for workspace audit logs.').waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v2_workspace_audit').select('id').eq('workspace_id',workspace)),[])
    assert.equal((await assuredOwner.rpc('st_v6_audit_search',{p_workspace:workspace})).error?.code,'42501')
    assert.ok(data(await scoped.rpc('st_v6_audit_search',{p_workspace:workspace})).some(row=>row.event==='workspace.created'))
    const deniedExport=await fetch(new URL('/api/audit/export',app),{
      method:'POST',headers:{Authorization:'Bearer '+ownerAccess,'Content-Type':'application/json'},
      body:JSON.stringify({workspace,query:'workspace created',source:'workspace',from:null,before:null}),
    })
    assert.equal(deniedExport.status,403)
    assert.equal((await deniedExport.json()).error,'Verify workspace administrator access to export.')
    await memberPage.reload({waitUntil:'domcontentloaded'})
    await btn(nav(memberPage),'Workspaces').click()
    await btn(memberPage.getByRole('group',{name:'Workspace sections'}),'Activity').click()
    await memberPage.getByText('workspace created',{exact:true}).waitFor()
    auditPasswordPage=await adminContext.newPage()
    await auditPasswordPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
    await btn(nav(auditPasswordPage),'Workspaces').click()
    await btn(auditPasswordPage.getByRole('group',{name:'Workspace sections'}),'Activity').click()
    await auditPasswordPage.getByText('Sign in through your workspace provider to access audit logs.').waitFor()
    assert.equal(await auditPasswordPage.getByText('workspace created',{exact:true}).count(),0)
  }
  let directoryPasswordPage
  if(directoryTest){
    await btn(directoryPolicy,'Require SSO for the workspace directory').click()
    await directoryPolicy.getByText('Workspace single sign-on is required for the workspace directory.').waitFor()
    assert.deepEqual(data(await assuredOwner.from('st_v2_members').select('user_id').eq('workspace_id',workspace)),[{user_id:owner.id}])
    assert.deepEqual(data(await assuredOwner.from('st_profiles').select('id').eq('id',session.user)),[])
    assert.equal((await assuredOwner.rpc('st_v7_workspace_people',{p_workspace:workspace})).error?.code,'42501')
    const directoryOwner=data(await scoped.from('st_profiles').select('name,handle').eq('id',owner.id).single())
    assert.ok(data(await scoped.rpc('st_v6_search',{p_query:directoryOwner.handle,p_kind:'person',p_filters:{}})).some(row=>row.id===owner.id))
    await btn(memberPage.getByRole('group',{name:'Workspace sections'}),'People').click()
    await memberPage.getByText(directoryOwner.name,{exact:true}).waitFor()
    directoryPasswordPage=await adminContext.newPage()
    await directoryPasswordPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
    await btn(nav(directoryPasswordPage),'Workspaces').click()
    await btn(directoryPasswordPage.getByRole('group',{name:'Workspace sections'}),'People').click()
    await directoryPasswordPage.getByText('Sign in through your workspace provider to view or manage the member directory.').waitFor()
    assert.equal(await directoryPasswordPage.getByRole('region',{name:'Manage workspace members'}).count(),0)
  }
  const plannerTitle='Workspace planning '+suffix
  let plannerItem, plannerPasswordPage
  if(plannerTest){
    await btn(plannerPolicy,'Require SSO for workspace planning').click()
    await plannerPolicy.getByText('Workspace single sign-on is required for workspace planning.').waitFor()
    await btn(memberPage.getByRole('group',{name:'Workspace sections'}),'Board').click()
    await memberPage.getByText('Add to board',{exact:true}).click()
    const form=memberPage.getByRole('form',{name:'Add to board',exact:true})
    await form.getByLabel('Item type').selectOption('note')
    await form.getByLabel('Title',{exact:true}).fill(plannerTitle)
    await btn(form,'Add item').click()
    await memberPage.getByText(plannerTitle,{exact:true}).waitFor()
    plannerItem=data(await scoped.from('st_v2_items').select('id').eq('workspace_id',workspace).eq('title',plannerTitle).single()).id
    assert.deepEqual(data(await assuredOwner.from('st_v2_items').select('id').eq('id',plannerItem)),[])
    assert.equal((await assuredOwner.rpc('st_v2_add_item',{p_workspace:workspace,p_kind:'note',p_title:'Blocked note',p_details:'',p_due:null})).error?.code,'42501')
    plannerPasswordPage=await adminContext.newPage()
    await plannerPasswordPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
    await btn(nav(plannerPasswordPage),'Workspaces').click()
    await btn(plannerPasswordPage.getByRole('group',{name:'Workspace sections'}),'Board').click()
    await plannerPasswordPage.getByText('Sign in through your workspace provider to access workspace boards, tasks, and events.').waitFor()
    assert.equal(await plannerPasswordPage.getByText('Add to board',{exact:true}).count(),0)
  }
  let channel, post
  let room, roomPost
  let managedRoom, managedChannel
  const requestManaged=(route,id,access,payload)=>fetch(new URL('/api/'+route+'/'+id,app),{
    method:payload?'POST':'GET',headers:{Authorization:'Bearer '+access,...(payload?{'Content-Type':'application/json'}:{})},
    body:payload?JSON.stringify(payload):undefined,
  })
  const managedBody='Signed provider managed sentinel '+suffix
  async function containsManagedMessage(response, route, search=false){
    const payload=await response.json()
    const messages=route==='managed-room'?payload.messages:search?payload.matches:payload
    return messages.some(message=>message.body===managedBody)
  }
  if(managedTest){
    data(await assuredOwner.rpc('st_v8_set_channel_mode_policy',{p_workspace:workspace,p_managed:true}))
    managedChannel=data(await assuredOwner.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'managed-sso-'+suffix}))
    data(await assuredOwner.rpc('st_v8_set_channel_mode_policy',{p_workspace:workspace,p_managed:false}))
    data(await assuredOwner.rpc('st_v8_managed_room_policy',{p_workspace:workspace,p_enabled:true}))
    managedRoom=data(await assuredOwner.rpc('st_v6_room_create',{p_id:randomUUID(),p_workspace:workspace,
      p_name:'Managed SSO '+suffix,p_kind:'private',p_template:'blank'}))
    data(await assuredOwner.rpc('st_v8_managed_room_policy',{p_workspace:workspace,p_enabled:false}))
    sql("insert into public.st_v6_room_members(room_id,user_id,role) values('"+managedRoom+"','"+session.user+"','member');")
    await btn(managedPolicy,'Require SSO for managed messages').click()
    await managedPolicy.getByText('Workspace single sign-on is required for managed encrypted messages.').waitFor()
    for(const [route,id,search] of [['managed-channel',managedChannel,{search:managedBody}],
      ['managed-room',managedRoom,{action:'search',query:managedBody}]]){
      const sent=await requestManaged(route,id,session.token,{id:randomUUID(),body:managedBody})
      assert.equal(sent.status,204,sent.status===204?undefined:await sent.text())
      const visible=await requestManaged(route,id,session.token)
      assert.equal(visible.status,200)
      assert.ok(await containsManagedMessage(visible,route))
      const found=await requestManaged(route,id,session.token,search)
      assert.equal(found.status,200)
      assert.ok(await containsManagedMessage(found,route,true))
      assert.equal((await requestManaged(route,id,ownerAccess)).status,404)
      assert.equal((await requestManaged(route,id,ownerAccess,{id:randomUUID(),body:'Blocked managed post'})).status,404)
      assert.equal((await requestManaged(route,id,ownerAccess,search)).status,404)
    }
  }
  const channelName='sso-standard-'+suffix
  const body='Synthetic SSO channel sentinel '+suffix
  if(channelTest){
    channel=data(await assuredOwner.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:channelName}))
    const policy=config.getByRole('region',{name:'Standard channel message sign-in',exact:true})
    await btn(policy,'Require SSO for standard channel messages').click()
    await policy.getByText('Workspace single sign-on is required for standard channel messages.').waitFor()
    const channelNav=page=>page.getByRole('group',{name:'Workspace sections'})
    await btn(channelNav(memberPage),'Channels').click()
    await memberPage.getByLabel('Channel',{exact:true}).selectOption(channel)
    await memberPage.getByLabel('Channel message',{exact:true}).fill(body)
    await btn(memberPage,'Send message').click()
    await memberPage.getByRole('log',{name:'Channel messages'}).getByText(body,{exact:true}).waitFor()
    post=data(await scoped.from('st_v2_posts').select('id,body').eq('channel_id',channel).single())
    assert.equal(post.body,body)
    assert.deepEqual(data(await assuredOwner.from('st_v2_posts').select('id,body').eq('channel_id',channel)),[])
    assert.equal((await assuredOwner.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:'Password-only post'})).error?.code,'42501')
    for(const filters of [{}, {p_filters:{}}]){
      const request={p_query:body,p_kind:'channel',...filters}
      assert.deepEqual(data(await assuredOwner.rpc('st_v6_search',request)),[])
      assert.equal(data(await scoped.rpc('st_v6_search',request)).some(row=>row.id===post.id),true)
    }
    assert.equal((await assuredOwner.rpc('st_v7_submit_channel_report',{p_channel:channel,p_post:post.id,p_category:'other',
      p_details:'Synthetic inaccessible report',p_share_with_safety:true,p_share_with_workspace:false})).error?.code,'42501')
    await btn(channelNav(adminPage),'Channels').click()
    await adminPage.getByLabel('Channel',{exact:true}).selectOption(channel)
    await adminPage.getByText('Sign in with workspace single sign-on to read or send messages in this channel.',{exact:true}).waitFor()
    assert.equal(await adminPage.getByLabel('Channel message',{exact:true}).count(),0)
    assert.equal(await adminPage.getByText(body,{exact:true}).count(),0)
    await btn(adminPage,'Integrations').click()
    await btn(adminPage,'Single sign-on').click()
  }
  if(roomTest){
    const roomName='SSO room '+suffix
    const roomBody='Signed provider room sentinel '+suffix
    room=data(await assuredOwner.rpc('st_v6_room_create',{p_id:randomUUID(),p_workspace:workspace,
      p_name:roomName,p_kind:'public',p_template:'blank'}))
    data(await scoped.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))
    await btn(roomPolicy,'Require SSO for standard room messages').click()
    await roomPolicy.getByText('Workspace single sign-on is required for standard room messages.').waitFor()
    const openRoom=async page=>{
      await btn(nav(page),'Rooms').click()
      const directory=page.getByRole('region',{name:'Room directory'})
      await directory.getByRole('button',{name:new RegExp(roomName)}).click()
      return page.getByRole('region',{name:roomName,exact:true})
    }
    const memberRoom=await openRoom(memberPage)
    await memberRoom.getByLabel('Write a room message',{exact:true}).fill(roomBody)
    const publish=memberPage.waitForResponse(response=>response.url().endsWith('/rpc/st_v6_room_post')
      && response.request().postDataJSON().p_room===room)
    await btn(memberRoom,'Send').click()
    const sent=await publish
    assert.ok(sent.ok(), 'Native signed room post failed with '+sent.status())
    await memberRoom.getByText(roomBody,{exact:true}).waitFor()
    roomPost=data(await scoped.from('st_v6_room_posts').select('id').eq('room_id',room).eq('body',roomBody).single())
    assert.deepEqual(data(await assuredOwner.from('st_v6_room_posts').select('id').eq('room_id',room)),[])
    assert.equal((await assuredOwner.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:'Password-only room post'})).error?.message,'Posting is unavailable')
    const search={p_query:roomBody,p_kind:'room',p_filters:{room}}
    assert.deepEqual(data(await assuredOwner.rpc('st_v6_search',search)),[])
    assert.equal(data(await scoped.rpc('st_v6_search',search)).some(row=>row.id===roomPost.id),true)
    const summary=new URL('/api/rooms/thread-summary',app)
    summary.search=new URLSearchParams({room,thread:roomPost.id,action:'view'}).toString()
    const viewSummary=token=>fetch(summary,{method:'POST',headers:{Authorization:'Bearer '+token}})
    assert.equal((await viewSummary(ownerAccess)).status,403)
    assert.equal((await viewSummary(session.token)).status,200)
    const passwordRoom=await openRoom(adminPage)
    const ownerDirectory=adminPage.getByRole('region',{name:'Room directory'})
    await ownerDirectory.getByText('Room reaction settings',{exact:true}).waitFor()
    await ownerDirectory.getByRole('region',{name:'Managed room policy'}).waitFor()
    await passwordRoom.getByRole('status').filter({hasText:'Workspace single sign-on is required to open this room’s messages.'}).waitFor()
    assert.equal(await passwordRoom.getByLabel('Write a room message',{exact:true}).count(),0)
    assert.equal(await passwordRoom.getByText(roomBody,{exact:true}).count(),0)
    await btn(nav(adminPage),'Workspaces').click()
    await btn(adminPage,'Integrations').click()
    await btn(adminPage,'Single sign-on').click()
  }
  if(realtimeTest){
    const controlWorkspace=data(await assuredOwner.rpc('st_v2_create_workspace',{p_name:'Realtime control '+suffix}))
    const controlChannel=data(await assuredOwner.rpc('st_v2_create_channel',{p_workspace:controlWorkspace,p_name:'realtime-control'}))
    const [passwordObserver,samlObserver]=await Promise.all([
      observeChannelChanges(adminPage,ownerAccess,owner.id),observeChannelChanges(memberPage,session.token),
    ])
    const find=async(observer,id,event)=>(await observer.events()).find(change=>change.eventType===event && change.new.id===id)
    const livePost=randomUUID(), barrier=randomUUID()
    try{
      data(await scoped.rpc('st_v2_post',{p_channel:channel,p_id:livePost,p_body:'Protected live message '+suffix}))
      sql("update public.st_v2_posts set body='Updated protected message "+suffix+"' where id='"+livePost+"';")
      data(await assuredOwner.rpc('st_v2_post',{p_channel:controlChannel,p_id:barrier,p_body:'Unprotected Realtime control'}))
      assert.equal(data(await assuredOwner.from('st_v2_posts').select('id').eq('id',barrier).single()).id,barrier)
      await waitForChannelChanges(()=>find(passwordObserver,barrier,'INSERT'),'password control insert')
      await waitForChannelChanges(()=>find(samlObserver,livePost,'INSERT'),'SAML protected insert')
      await waitForChannelChanges(()=>find(samlObserver,livePost,'UPDATE'),'SAML protected update')
      assert.equal(await find(passwordObserver,livePost,'INSERT'),undefined)
      assert.equal(await find(passwordObserver,livePost,'UPDATE'),undefined)
      assert.equal((await find(samlObserver,livePost,'UPDATE')).new.body,'Updated protected message '+suffix)
      const announcement=async()=>(await passwordObserver.announcements()).find(event=>event.channel_id===channel)
      await waitForChannelChanges(announcement,'existing account channel activity announcement')
      const activity=await announcement()
      assert.deepEqual(Object.keys(activity).sort(),['channel_id','id'])
      assert.match(activity.id,/^[0-9a-f-]{36}$/i)
      assert.notEqual(activity.id,livePost)
      sql("delete from public.st_v2_posts where id='"+livePost+"';")
      for(const observer of [passwordObserver,samlObserver]){
        const deletion=async()=>(await observer.events()).find(change=>change.eventType==='DELETE' && change.old.id===livePost)
        await waitForChannelChanges(deletion,'primary-key-only deletion')
        assert.deepEqual((await deletion()).old,{id:livePost})
      }
      console.log('Passed native Realtime receipt checks, channel-ID announcements and primary-key-only DELETE metadata.')
    }finally{
      await Promise.all([passwordObserver.close(),samlObserver.close()])
    }
  }
  if(process.env.SECTALK_TEST_SSO_MEDIA==='1'){
    const meeting=randomUUID()
    const protectedMeeting=randomUUID()
    const signedConversion=randomUUID()
    const conversionTest=process.env.SECTALK_TEST_SSO_MEDIA_CONVERSION==='1'
    const ownerDevice=randomUUID()
    const memberDevice=randomUUID()
    const nativeSession=token=>JSON.parse(Buffer.from(token.split('.')[1],'base64url')).session_id
    sql("begin; insert into public.st_v3_meetings(id,workspace_id,host_id,title,starts_at,ends_at,status,meeting_locked,media_protection) values("+
      "'"+meeting+"','"+workspace+"','"+owner.id+"','SSO managed fixture',now(),now()+interval '1 hour','live',false,0),"+
      "('"+protectedMeeting+"','"+workspace+"','"+owner.id+"','SSO protected fixture',now(),now()+interval '1 hour','live',false,0);"+
      "insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at) select m.id,u.id,'admitted',now()"+
      " from unnest(array['"+meeting+"','"+protectedMeeting+"']::uuid[]) m(id) cross join unnest(array['"+owner.id+"','"+session.user+"']::uuid[]) u(id);"+
      "select public.st_v6_create_protected_meeting('"+protectedMeeting+"','"+owner.id+"');"+
      "update sectalk_private.st_v6_protected_meeting set envelopes='{}' where meeting='"+protectedMeeting+"';"+
      "insert into sectalk_private.st_v6_protected_meeting_endpoint(meeting,actor,device,session_id,public_key,verified) values("+
      "'"+protectedMeeting+"','"+owner.id+"','"+ownerDevice+"','"+nativeSession(ownerAccess)+"',repeat('a',87),true),"+
      "('"+protectedMeeting+"','"+session.user+"','"+memberDevice+"','"+nativeSession(session.token)+"',repeat('b',87),true); commit;")
    if(conversionTest){
      sql("begin; update public.st_v2_members set role='admin' where workspace_id='"+workspace+"' and user_id='"+session.user+"';"+
        "insert into public.st_v3_meetings(id,workspace_id,host_id,title,starts_at,ends_at,status) values('"+
        signedConversion+"','"+workspace+"','"+session.user+"','SSO conversion fixture',now(),now()+interval '1 hour','live');"+
        "insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at) select '"+signedConversion+"',u.id,'admitted',now()"+
        " from unnest(array['"+owner.id+"','"+session.user+"']::uuid[]) u(id); commit;")
    }
    async function credential(path, bearer, body){
      return fetch(new URL(path,app),{method:'POST',headers:{Authorization:'Bearer '+bearer,'Content-Type':'application/json'},
        body:JSON.stringify(body)})
    }
    const managed=(token,networkCheck=false)=>credential('/api/meetings/token',token,{meetingId:meeting,networkCheck})
    const protectedToken=(token,device)=>credential('/api/meetings/protected',token,{meeting:protectedMeeting,action:'token',device})
    const convert=(token,id)=>credential('/api/meetings/protected',token,{meeting:id,action:'start'})
    async function verifyGrant(response, room){
      assert.equal(response.status,200)
      const {token}=await response.json()
      const [header,payload,mac]=token.split('.')
      assert.equal(mac,createHmac('sha256','secret').update(header+'.'+payload).digest('base64url'))
      const claims=JSON.parse(Buffer.from(payload,'base64url'))
      assert.equal(claims.sub,session.user+'.'+claims.attributes?.['sectalk.media.binding'])
      assert.equal(claims.video.room,room)
      assert.equal(claims.video.roomJoin,true)
      assert.equal(claims.video.canUpdateOwnMetadata,false)
      assert.match(claims.attributes?.['sectalk.media.binding'],/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/)
      assert.notEqual(claims.attributes['sectalk.media.binding'],nativeSession(session.token))
      return token
    }
    assert.equal((await managed(ownerAccess)).status,200)
    assert.equal((await protectedToken(ownerAccess,ownerDevice)).status,200)
    assert.notEqual(data(await owner.client.rpc('st_v8_workspace_member_media_policy',{p_workspace:workspace,p_require:true})).access,'verified')
    await btn(config,'Require SSO for new member media').click()
    await config.getByText('Workspace single sign-on is required for new member media credentials.').waitFor()
    assert.equal((await managed(ownerAccess)).status,403)
    assert.equal((await managed(ownerAccess,true)).status,403)
    assert.equal((await protectedToken(ownerAccess,ownerDevice)).status,403)
    if(conversionTest){
      const previous=participantLookups
      assert.equal((await convert(ownerAccess,meeting)).status,403)
      assert.equal(participantLookups,previous,'Denied conversion must not reach LiveKit')
      assert.equal(sql("select media_protection from public.st_v3_meetings where id='"+meeting+"';"),'0')
      assert.equal((await convert(session.token,signedConversion)).status,200)
      assert.equal(participantLookups,previous+1)
      assert.equal(sql("select media_protection from public.st_v3_meetings where id='"+signedConversion+"';"),'1')
    }
    const managedGrant=await verifyGrant(await managed(session.token),'sectalk-v3-'+meeting)
    const protectedGrant=await verifyGrant(await protectedToken(session.token,memberDevice),'sectalk-protected-'+protectedMeeting)
    const gatewaySecret=process.env.LIVEKIT_SIGNAL_AUTH_SECRET
    const gateway=token=>fetch(new URL('/api/internal/livekit-admission',app),{
      method:'POST',headers:{Authorization:'Bearer '+gatewaySecret,'Content-Type':'text/plain'},body:token,
    })
    const review=secret=>fetch(new URL('/api/internal/livekit-admission',app),{method:'PUT',headers:{Authorization:'Bearer '+secret}})
    function hostedParticipant(token){
      const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url'))
      return {room:claims.video.room,person:{identity:claims.sub,attributes:claims.attributes}}
    }
    if(gatewaySecret){
      assert.equal((await gateway(managedGrant)).status,204)
      assert.equal((await gateway(protectedGrant)).status,204)
      if(conversionTest){
        const managed=hostedParticipant(managedGrant),recovered=hostedParticipant(protectedGrant)
        const stale=randomUUID(),guest=randomUUID()
        mediaParticipants.set(managed.room,[managed.person,{identity:session.user+'.'+stale,attributes:{'sectalk.media.binding':stale}},
          {identity:guest,attributes:{}}])
        mediaParticipants.set(recovered.room,[recovered.person])
        assert.equal((await review('wrong-gateway-bearer')).status,401)
        assert.deepEqual(removedMedia,[])
        assert.equal((await review(gatewaySecret)).status,204)
        assert.deepEqual(removedMedia,[{room:managed.room,identity:session.user+'.'+stale}])
        assert.deepEqual(mediaParticipants.get(managed.room).map(person=>person.identity),[managed.person.identity,guest])
        assert.deepEqual(mediaParticipants.get(recovered.room),[recovered.person])
      }
    }
    await btn(config,'Disconnect workspace SSO').click()
    await config.getByText('Workspace sign-in removed.',{exact:true}).waitFor()
    assert.equal((await managed(session.token)).status,403)
    assert.equal((await protectedToken(session.token,memberDevice)).status,403)
    if(gatewaySecret){
      assert.equal((await gateway(managedGrant)).status,403)
      assert.equal((await gateway(protectedGrant)).status,403)
      if(conversionTest){
        assert.equal((await review(gatewaySecret)).status,204)
        assert.deepEqual(removedMedia.slice(1).map(item=>item.identity).sort(),[
          hostedParticipant(managedGrant).person.identity,hostedParticipant(protectedGrant).person.identity,
        ].sort())
        assert.equal((await review(gatewaySecret)).status,204)
        assert.equal(removedMedia.length,3)
        console.log('Passed exact connected media removal and newer same-account session protection.')
      }
    }
    assert.notEqual(data(await owner.client.rpc('st_v8_workspace_member_media_policy',{p_workspace:workspace,p_require:false})).access,'verified')
    await btn(config,'Allow standard sign-in for new member media').click()
    await btn(config,'Allow standard sign-in for new member media').waitFor({state:'hidden'})
    assert.equal(data(await assuredOwner.rpc('st_v8_workspace_member_media_policy',{p_workspace:workspace})).required,false)
    assert.equal((await managed(ownerAccess)).status,200)
    assert.equal((await protectedToken(ownerAccess,ownerDevice)).status,200)
    if(conversionTest){
      if(gatewaySecret){
        assert.equal((await convert(ownerAccess,meeting)).status,409,'An approved guest still occupies the managed room')
        mediaParticipants.set('sectalk-v3-'+meeting,[])
      }
      assert.equal((await convert(ownerAccess,meeting)).status,200)
      assert.equal(sql("select media_protection from public.st_v3_meetings where id='"+meeting+"';"),'1')
      console.log('Passed protected meeting conversion protected by the native scope, provider bypass denial and owner recovery.')
    }
    console.log('Passed member media credential denial and issuance, stale-provider fail-closed, and verified owner recovery.')
  }else if(entryTest||entryFileTest||inviteEntryTest||entryMeetingTest||entryArtifactTest||entryIntegrationTest||entryModerationTest||entryChannelReportsTest||entryBillingTest||entryOrganizationTest||entryPolicyAdminTest||entryComplianceTest){
    assert.equal(data(await assuredOwner.rpc('st_v7_workspace_sso_settings',{p_workspace:workspace,p_action:'remove'})).setup,null)
  }else{
    await btn(config,'Disconnect workspace SSO').click()
    await config.getByText('Workspace sign-in removed.',{exact:true}).waitFor()
  }
  assert.equal(data(await scoped.rpc('st_v7_workspace_uses_sso',{p_workspace:workspace})),false)
  if(entryModerationTest||entryChannelReportsTest){
    const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
    await locked.getByText('Owner recovery',{exact:true}).click()
    await btn(locked,'Restore standard workspace sign-in').click()
    await locked.waitFor({state:'hidden'})
    if(entryChannelReportsTest){
      assert.ok(data(await assuredOwner.rpc('st_v7_channel_report_queue',{p_scope:'workspace'}))
        .some(row=>row.id===entryChannelReport&&row.state==='resolved'))
      console.log('Passed channel-report review recovery from the verified owner browser.')
    }else{
      assert.ok(data(await assuredOwner.rpc('st_v7_workspace_room_review_queue'))
        .some(row=>row.id===entryModerationOwnerCase&&row.status==='reviewing'))
      console.log('Passed managed-room review recovery from the verified owner browser.')
    }
  }
  if(entryArtifactTest){
    assert.equal((await artifactDownload(session.token)).status,404)
    assert.equal((await artifactAction(session.token,'summaries','generate')).status,403)
    const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
    await locked.getByText('Owner recovery',{exact:true}).click()
    await btn(locked,'Restore standard workspace sign-in').click()
    await locked.waitFor({state:'hidden'})
    assert.equal((await artifactDownload(ownerAccess)).status,200)
    assert.equal((await artifactAction(ownerAccess,'summaries','generate')).status,200)
    console.log('Passed signed workspace entry meeting recording download and summary UI, provider disconnect, and owner recovery.')
  }
  if(entryMeetingTest){
    assert.equal((await entryToken(session.token)).status,403)
    assert.equal(data(await admission(session.user,entryMediaBinding)),false)
    await btn(nav(adminPage),'Workspaces').click()
    const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
    await locked.getByText('Owner recovery',{exact:true}).click()
    await btn(locked,'Restore standard workspace sign-in').click()
    await locked.waitFor({state:'hidden'})
    await btn(nav(adminPage),'Meetings').click()
    await btn(adminPage,entryLobbyTitle).waitFor()
    assert.equal((await entryToken(ownerAccess)).status,200)
    console.log('Passed signed workspace entry meeting lobby, native media tokens and reconnect checks, disconnect, and fresh owner recovery.')
  }
  if(entryTest){
    assert.deepEqual(data(await scoped.from('st_v2_workspaces').select('id').eq('id',workspace)),[])
    assert.deepEqual(data(await scoped.from('st_v2_channels').select('id').eq('id',entryChannel)),[])
    assert.deepEqual(data(await scoped.from('st_v6_rooms').select('id').eq('id',entryRoom)),[])
    await memberPage.reload()
    await btn(nav(memberPage),'Workspaces').click()
    const memberGate=memberPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
    await memberGate.waitFor()
    assert.equal(await memberGate.getByText('Owner recovery',{exact:true}).count(),0)
    assert.notEqual(data(await owner.client.rpc('st_v8_workspace_entry_policy',{p_workspace:workspace,p_require:false})).access,'verified')
    const ownerGate=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
    await ownerGate.getByText('Owner recovery',{exact:true}).click()
    await btn(ownerGate,'Restore standard workspace sign-in').click()
    await ownerGate.waitFor({state:'hidden'})
    await btn(adminPage,'Board').click()
    await adminPage.getByText(entryBoardTitle,{exact:true}).waitFor()
    console.log('Passed signed workspace entry, directories, signed board and room/channel messages, disconnect and fresh owner recovery.')
  }
  if(complianceTest){
    assert.equal((await getCompliance('GET',session.token)).status,404)
    if(entryComplianceTest){
      const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
      await locked.getByText('Owner recovery',{exact:true}).click()
      await btn(locked,'Restore standard workspace sign-in').click()
      await locked.waitFor({state:'hidden'})
    }else{
      await btn(compliancePolicy,'Allow standard sign-in for compliance exports and evidence').click()
      await compliancePolicy.waitFor({state:'hidden'})
    }
    await compliancePasswordPage.reload()
    await btn(nav(compliancePasswordPage),'Workspaces').click()
    await btn(compliancePasswordPage,'Compliance exports').click()
    await compliancePasswordPage.getByRole('heading',{name:'Signed compliance audit case',exact:true}).waitFor()
    assert.equal((await getCompliance('GET',session.token)).status,200)
    console.log('Passed signed native compliance SSO, case and evidence visibility, encrypted export build and download, and fresh owner recovery.')
  }
  if(legalHoldTest){
    const read=()=>assuredOwner.rpc('st_v6_workspace_hold_state',{p_workspace:workspace})
    assert.equal(data(await read()).hold_sso_required,true)
    await btn(legalHoldPolicy,'Allow standard sign-in for legal holds').click()
    await legalHoldPolicy.waitFor({state:'hidden'})
    await legalHoldPasswordPage.reload()
    await btn(nav(legalHoldPasswordPage),'Workspaces').click()
    await btn(legalHoldPasswordPage,'Governance').click()
    await legalHoldPasswordPage.getByText('Sensitive synthetic preservation rationale',{exact:true}).waitFor()
    assert.equal(data(await read()).holds.length,2)
    console.log('Passed signed native legal hold SSO, ledger confidentiality, signed placement, independent governance, and fresh owner recovery.')
  }
  if(policyAdminTest){
    const read=()=>assuredOwner.rpc('st_v7_workspace_policies',{p_workspace:workspace,p_domain:'messaging'})
    assert.deepEqual(data(await read()),{access:'sso'})
    if(entryPolicyAdminTest){
      const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
      await locked.getByText('Owner recovery',{exact:true}).click()
      await btn(locked,'Restore standard workspace sign-in').click()
      await locked.waitFor({state:'hidden'})
    }else{
      await btn(policyAdminPolicy,'Allow standard sign-in for policy management').click()
      await policyAdminPolicy.waitFor({state:'hidden'})
    }
    await policyPasswordPage.reload()
    await btn(nav(policyPasswordPage),'Workspaces').click()
    await btn(policyPasswordPage,'Policies').click()
    await policyPasswordPage.getByRole('region',{name:'Messaging policy',exact:true}).getByText('Current revision 1',{exact:true}).waitFor()
    assert.equal(data(await read()).current.limit,3)
    assert.equal(data(await assuredOwner.rpc('st_v6_workspace_policy_versions',{p_workspace:workspace,p_policy:'notifications'})).version,0)
    console.log('Passed signed native workspace policy SSO, legacy editor denial, protected preview and apply, organization retention, and fresh owner recovery.')
  }
  if(customRoleAdminTest){
    const read=()=>assuredOwner.rpc('st_v7_workspace_custom_roles',{p_workspace:workspace})
    assert.deepEqual(data(await read()),{access:'sso'})
    await btn(customRoleAdminPolicy,'Allow standard sign-in for custom role management').click()
    await customRoleAdminPolicy.waitFor({state:'hidden'})
    await customRolePasswordPage.reload()
    await btn(nav(customRolePasswordPage),'Workspaces').click()
    await btn(customRolePasswordPage,'Custom roles').click()
    const editor=customRolePasswordPage.getByRole('region',{name:'Workspace custom roles',exact:true})
    await editor.getByRole('option',{name:'Updated signed directory delegate',exact:true}).waitFor({state:'attached'})
    assert.equal(data(await read()).access,'verified')
    console.log('Passed signed native custom role administration SSO, fresh owner verification, browser revision, and recovery.')
  }
  if(integrationAdminTest){
    assert.equal(data(await assuredOwner.rpc('st_v6_integration_access',{p_workspace:workspace})),'sso')
    assert.equal((await integrationRead()).status,200)
    if(entryIntegrationTest){
      const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
      await locked.getByText('Owner recovery',{exact:true}).click()
      await btn(locked,'Restore standard workspace sign-in').click()
      await locked.waitFor({state:'hidden'})
    }else{
      await btn(integrationAdminPolicy,'Allow standard sign-in for API keys and webhooks').click()
      await integrationAdminPolicy.waitFor({state:'hidden'})
    }
    await integrationPasswordPage.reload()
    await btn(nav(integrationPasswordPage),'Workspaces').click()
    await btn(integrationPasswordPage,'Integrations').click()
    await btn(integrationPasswordPage,'Create API key').waitFor()
    assert.equal(data(await assuredOwner.rpc('st_v6_integration_access',{p_workspace:workspace})),'verified')
    console.log('Passed signed native API key and webhook SSO, second-factor management, external credential continuity and owner recovery.')
  }
  if(invitationAdminTest){
    assert.equal((await scoped.rpc('st_v6_workspace_link_policy_get',{p_workspace:workspace})).error?.code,'42501')
    if(inviteEntryTest){
      const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
      await locked.getByText('Owner recovery',{exact:true}).click()
      await btn(locked,'Restore standard workspace sign-in').click()
      await locked.waitFor({state:'hidden'})
      await invitationPasswordPage.reload()
      await btn(nav(invitationPasswordPage),'Workspaces').click()
    }else{
      await btn(invitationAdminPolicy,'Allow standard sign-in for invitation management').click()
      await invitationAdminPolicy.waitFor({state:'hidden'})
    }
    await btn(invitationPasswordPage,'Channels').click()
    await btn(invitationPasswordPage,'People').click()
    await invitationPasswordPage.getByLabel('Invite by SecTalk handle').waitFor()
    console.log('Passed signed native invitation administration SSO, standard account bootstrap, provider disconnect and fresh owner recovery.')
  }
  if(roomStructureTest){
    assert.deepEqual(data(await scoped.from('st_v6_rooms').select('id').eq('id',structureRoom)),[])
    assert.equal((await scoped.rpc('st_v6_room_membership',{p_room:structureRoom,p_action:'join'})).error?.code,'42501')
    await btn(roomStructurePolicy,'Allow standard sign-in for the room directory').click()
    await roomStructurePolicy.waitFor({state:'hidden'})
    const directory=roomPasswordPage.getByRole('region',{name:'Room directory',exact:true})
    await btn(directory,structureRoomName+' Workspace-wide').waitFor()
    await roomPasswordPage.getByText('Create a room',{exact:true}).waitFor()
    if(navigationTest){
      await btn(blockedCatalog,'Refresh permissions').click()
      await blockedCatalog.getByLabel('Room for permissions').selectOption(structureRoom)
      await blockedCatalog.getByRole('heading',{name:'Room role: owner',exact:true}).waitFor()
      console.log('Passed signed native permission catalog room selector, direct context denial and fresh owner recovery.')
    }
    console.log('Passed signed native room directory SSO, protected room creation and roster, member join, provider disconnect and owner recovery.')
  }
  if(channelStructureTest){
    assert.deepEqual(data(await scoped.from('st_v2_channels').select('id').eq('id',structureChannel)),[])
    await btn(channelStructurePolicy,'Allow standard sign-in for the channel directory').click()
    await channelStructurePolicy.waitFor({state:'hidden'})
    await btn(channelPasswordPage,'People').click()
    await btn(channelPasswordPage,'Channels').click()
    await channelPasswordPage.getByRole('combobox',{name:'Channel',exact:true}).selectOption({label:'#channel-structure-'+suffix})
    await channelPasswordPage.getByRole('heading',{name:'#channel-structure-'+suffix,exact:true}).waitFor()
    await channelPasswordPage.getByText('New channel',{exact:true}).waitFor()
    console.log('Passed signed native channel directory SSO, hidden roster and management denial, provider disconnect and owner recovery.')
  }
  if(organizationTest){
    assert.equal((await requestOrganization(ownerAccess)).status,403)
    if(entryOrganizationTest){
      const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
      await locked.getByText('Owner recovery',{exact:true}).click()
      await btn(locked,'Restore standard workspace sign-in').click()
      await locked.waitFor({state:'hidden'})
      await organizationPasswordPage.reload({waitUntil:'domcontentloaded'})
      await btn(nav(organizationPasswordPage),'Workspaces').click()
      await btn(organizationPasswordPage,'Organization settings').click()
    }else{
      await btn(organizationPolicy,'Allow standard sign-in for organization settings').click()
      await organizationPolicy.waitFor({state:'hidden'})
    }
    await organizationPasswordPage.getByRole('region',{name:'Organization domains'}).waitFor({timeout:16000})
    assert.equal((await requestOrganization(ownerAccess)).status,200)
    console.log('Passed signed native organization SSO, scope-preserving governance, secured region API and fresh-owner recovery.')
  }
  if(billingTest){
    assert.equal((await billingRequest('workspace',session.token)).status,403)
    assert.equal((await billingRequest('invoices',session.token)).status,403)
    if(entryBillingTest){
      const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
      await locked.getByText('Owner recovery',{exact:true}).click()
      await btn(locked,'Restore standard workspace sign-in').click()
      await locked.waitFor({state:'hidden'})
    }else{
      await btn(billingPolicy,'Allow standard sign-in for workspace billing').click()
      await billingPolicy.waitFor({state:'hidden'})
    }
    await ownerBillingPage.getByRole('region',{name:'Billing administrator access'}).waitFor({timeout:16000})
    assert.equal(data(await assuredOwner.rpc('st_v7_workspace_usage',{p_workspace:workspace})).plan,'enterprise')
    console.log('Passed signed native workspace billing SSO, owner and delegate controls, stale invoice request denial and recovery.')
  }
  if(fileTest){
    assert.equal((await fileRequest(session.token,{file:testFile})).status,403)
    // Workspace entry and standard room SSO can hide the room before the file check.
    assert.equal((await fileRequest(session.token,{room:true,file:testRoomFile})).status,entryFileTest||roomTest?404:403)
    if(entryFileTest){
      const locked=adminPage.getByRole('region',{name:'Workspace sign-in required',exact:true})
      await locked.getByText('Owner recovery',{exact:true}).click()
      await btn(locked,'Restore standard workspace sign-in').click()
      await locked.waitFor({state:'hidden'})
    }else{
      await btn(filePolicy,'Allow standard sign-in for workspace and room files').click()
      await filePolicy.waitFor({state:'hidden'})
    }
    const restored=await fileRequest(ownerAccess,{file:testFile})
    assert.equal(restored.status,200)
    assert.deepEqual(Buffer.from(await restored.arrayBuffer()),fileSsoBody)
    if(entryFileTest){
      await filePasswordPage.reload()
      await btn(nav(filePasswordPage),'Workspaces').click()
      await btn(filePasswordPage.getByRole('group',{name:'Workspace sections'}),'Files').click()
    }
    await filePasswordPage.getByRole('heading',{name:fileName,exact:true}).waitFor({timeout:16000})
    console.log('Passed signed native workspace and room file SSO, binary download, old locator denial, disconnect and owner recovery.')
  }
  if(groupsTest){
    assert.deepEqual(data(await scoped.from('st_v6_workspace_groups').select('id').eq('id',team)),[])
    await btn(groupsPolicy,'Allow standard sign-in for groups and teams').click()
    await groupsPolicy.waitFor({state:'hidden'})
    assert.equal(data(await assuredOwner.from('st_v6_workspace_groups').select('id').eq('id',team).single()).id,team)
    await btn(groupsPasswordPage,teamName).waitFor({timeout:15000})
    console.log('Passed signed native groups SSO, protected directory and roster, provider disconnect and owner recovery.')
  }
  if(scheduleTest){
    assert.deepEqual(data(await scoped.from('st_v3_meetings').select('id').eq('id',scheduleMeeting)),[])
    await btn(schedulePolicy,'Allow standard sign-in for workspace meetings').click()
    await schedulePolicy.waitFor({state:'hidden'})
    assert.equal(data(await assuredOwner.from('st_v3_meetings').select('id').eq('id',scheduleMeeting).single()).id,scheduleMeeting)
    await schedulePasswordPage.getByText(scheduleTitle,{exact:true}).waitFor({timeout:15000})
    console.log('Passed signed native workspace meeting SSO, Calendar and meeting reads, lobby request, provider disconnect and owner recovery.')
  }
  if(auditTest){
    assert.deepEqual(data(await scoped.from('st_v2_workspace_audit').select('id').eq('workspace_id',workspace)),[])
    await btn(auditPolicy,'Allow standard sign-in for workspace audit logs').click()
    await auditPolicy.waitFor({state:'hidden'})
    assert.ok(data(await assuredOwner.rpc('st_v6_audit_search',{p_workspace:workspace})).some(row=>row.event==='workspace.created'))
    await auditPasswordPage.getByText('workspace created',{exact:true}).waitFor({timeout:24000})
    console.log('Passed signed native workspace audit SSO, Activity and Search, signed-export denial, disconnect and owner recovery.')
  }
  if(directoryTest){
    assert.deepEqual(data(await scoped.from('st_v2_members').select('user_id').eq('workspace_id',workspace)),[{user_id:session.user}])
    await btn(directoryPolicy,'Allow standard sign-in for the workspace directory').click()
    await directoryPolicy.waitFor({state:'hidden'})
    assert.ok(data(await assuredOwner.rpc('st_v7_workspace_people',{p_workspace:workspace})).some(person=>person.id===session.user))
    await directoryPasswordPage.getByRole('region',{name:'Manage workspace members'}).waitFor({timeout:24000})
    console.log('Passed signed native workspace directory SSO, own membership, shared profile and Search, provider disconnect and owner recovery.')
  }
  if(plannerTest){
    assert.deepEqual(data(await scoped.from('st_v2_items').select('id').eq('id',plannerItem)),[])
    await btn(plannerPolicy,'Allow standard sign-in for workspace planning').click()
    await plannerPolicy.waitFor({state:'hidden'})
    assert.equal(data(await assuredOwner.from('st_v2_items').select('id').eq('id',plannerItem).single()).id,plannerItem)
    await plannerPasswordPage.getByText(plannerTitle,{exact:true}).waitFor({timeout:15000})
    console.log('Passed signed native workspace planner SSO, board creation, password denial, provider disconnect and owner recovery.')
  }
  if(managedTest){
    for(const [route,id] of [['managed-channel',managedChannel],['managed-room',managedRoom]]){
      assert.equal((await requestManaged(route,id,session.token)).status,404)
    }
    await btn(managedPolicy,'Allow standard sign-in for managed messages').click()
    await managedPolicy.waitFor({state:'hidden'})
    for(const [route,id] of [['managed-channel',managedChannel],['managed-room',managedRoom]]){
      const restored=await requestManaged(route,id,ownerAccess)
      assert.equal(restored.status,200)
      assert.ok(await containsManagedMessage(restored,route))
    }
    console.log('Passed signed native managed content SSO, encrypted reads and sends, search, stale receipt denial and owner recovery.')
  }
  if(channelTest){
    assert.deepEqual(data(await scoped.from('st_v2_posts').select('id').eq('channel_id',channel)),[])
    assert.equal((await scoped.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:'Stale receipt post'})).error?.code,'42501')
    const policy=config.getByRole('region',{name:'Standard channel message sign-in',exact:true})
    await btn(policy,'Allow standard sign-in for standard channel messages').click()
    await policy.waitFor({state:'hidden'})
    assert.equal(data(await assuredOwner.from('st_v2_posts').select('id').eq('channel_id',channel).single()).id,post.id)
    console.log('Passed standard channel SSO UI, read, send, Search, report denial, provider disconnect and owner recovery.')
  }
  if(roomTest){
    assert.deepEqual(data(await scoped.from('st_v6_room_posts').select('id').eq('room_id',room)),[])
    assert.equal((await scoped.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:'Stale room receipt'})).error?.message,'Posting is unavailable')
    await btn(roomPolicy,'Allow standard sign-in for standard room messages').click()
    await roomPolicy.waitFor({state:'hidden'})
    assert.equal(data(await assuredOwner.from('st_v6_room_posts').select('id').eq('room_id',room).eq('id',roomPost.id).single()).id,roomPost.id)
    console.log('Passed standard room SSO UI, reads, sends, Search, thread-summary authorization, provider disconnect and native owner recovery.')
  }
  assert.deepEqual([...new Set(duplicateWarnings)],[],'Workspace views rendered duplicate React keys')
  console.log('Passed real native signed SAML/PKCE, Enterprise config, JIT ordinary membership and scoped session proof.')
}finally{
  await browser?.close()
  if(fileSsoObjects.length)await admin.storage.from('sectalk-workspace-files').remove(fileSsoObjects)
  if(complianceSsoObjects.length)await admin.storage.from('sectalk-exports').remove(complianceSsoObjects)
  if(recordingSsoObjects.length)await admin.storage.from('recordings').remove(recordingSsoObjects)
  await new Promise(resolve=>proxy.close(resolve))
  sql("delete from auth.sso_providers where id='"+nativeProvider+"';")
}
