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

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
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
import { createHash, sign } from 'node:crypto'
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
  const adminPage=await browser.newPage()
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
  const memberPage=await browser.newPage()
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
  const scoped=createClient(supabase.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+session.token}}})
  assert.equal(data(await scoped.rpc('st_v7_workspace_uses_sso',{p_workspace:workspace})),true)
  assert.equal(sql("select role from public.st_v2_members where workspace_id='"+workspace+"' and user_id='"+session.user+"';"),'member')
  assert.equal(data(await owner.client.rpc('st_v7_workspace_uses_sso',{p_workspace:workspace})),false)
  await btn(config,'Disconnect workspace SSO').click()
  await config.getByText('Workspace sign-in removed.',{exact:true}).waitFor()
  assert.equal(data(await scoped.rpc('st_v7_workspace_uses_sso',{p_workspace:workspace})),false)
  console.log('Passed real native signed SAML/PKCE, Enterprise config, JIT ordinary membership and scoped session proof.')
}finally{
  await browser?.close()
  await new Promise(resolve=>proxy.close(resolve))
  sql("delete from auth.sso_providers where id='"+nativeProvider+"';")
}
