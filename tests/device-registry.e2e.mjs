// Local Edge, native GoTrue, browser IndexedDB and WebCrypto integration.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(new URL(app).hostname,'127.0.0.1')
assert.equal(origin,'http://127.0.0.1:55321')
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const password=randomUUID()+'1!Q'
const suffix=randomUUID().slice(0,8)
function data(result) {
  if(result.error)throw new Error(result.error.message)
  return result.data
}
async function account(role) {
  const handle='device_'+role+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(origin,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Device fixture '+role}))
  return {user,email,handle,client}
}
const [owner,peer,outsider]=await Promise.all([account('owner'),account('peer'),account('other')])
const chat=data(await owner.client.rpc('st_request',{p_handle:peer.handle}))
data(await peer.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const registry=page=>page.getByRole('region',{name:'Device trust',exact:true})
const entries=page=>registry(page).getByRole('article')
const own=page=>entries(page).filter({hasText:'This registered device'})
async function openRegistry(page,person) {
  await page.goto(app+'/#account')
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Profile',exact:true}).click()
  await page.getByRole('button',{name:'Devices and sessions',exact:true}).click()
  await registry(page).waitFor()
}
async function register(page) {
  await registry(page).getByRole('button',{name:'Register this device',exact:true}).click()
  await own(page).getByText('Known',{exact:true}).waitFor()
}
async function trust(card) {
  await card.getByRole('button',{name:'Trust device',exact:true}).click()
  await card.getByLabel('Current password',{exact:true}).fill(password)
  await card.getByRole('button',{name:'Confirm trust device',exact:true}).click()
}
async function browserSession(page) {
  return page.evaluate(()=>{
    const storage=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
    if (!storage) throw new Error('Missing local fixture session')
    return JSON.parse(localStorage.getItem(storage))
  })
}
async function lookup(page, person) {
  const session=await browserSession(page)
  const scoped=createClient(origin,key,{...options,global:{headers:{Authorization:'Bearer '+session.access_token}}})
  return data(await scoped.rpc('st_v7_peer_device_bundles',{p_peer:person.user.id}))
}
async function keyInfo(page,ownerId) {
  return page.evaluate(accountId=>new Promise((resolve,reject)=>{
    const open=indexedDB.open('sectalk-device-identity',1)
    open.onerror=()=>reject(open.error)
    open.onsuccess=()=>{
      const database=open.result
      const query=database.transaction('identities').objectStore('identities').get(accountId)
      query.onsuccess=async()=>{
        const {id,signing,agreement}=query.result
        const probes=await Promise.allSettled([
          crypto.subtle.exportKey('jwk',signing.privateKey),crypto.subtle.exportKey('jwk',agreement.privateKey),
        ])
        database.close()
        resolve({id,signing:signing.privateKey.extractable,agreement:agreement.privateKey.extractable,denied:probes.every(p=>p.status==='rejected')})
      }
      query.onerror=()=>reject(query.error)
    }
  }),ownerId)
}

try {
  const [first,second,recipient]=await Promise.all([browser.newPage(),browser.newPage(),browser.newPage()])
  await Promise.all([openRegistry(first,owner),openRegistry(second,owner),openRegistry(recipient,peer)])
  await registry(first).getByText(/This device is unknown/).waitFor()
  await register(first)
  const keyState=await keyInfo(first,owner.user.id)
  assert.equal(keyState.signing,false)
  assert.equal(keyState.agreement,false)
  assert.equal(keyState.denied,true)
  await trust(own(first))
  await own(first).getByText('Trusted',{exact:true}).waitFor()

  await register(second)
  const secondId=(await keyInfo(second,owner.user.id)).id
  assert.notEqual(secondId,keyState.id)
  await trust(own(second))
  await registry(second).getByRole('alert').filter({hasText:'Could not change device trust'}).waitFor()
  await registry(first).getByRole('button',{name:'Refresh device trust',exact:true}).click()
  const known=entries(first).filter({has:first.getByText('Known',{exact:true})})
  await trust(known)
  await registry(first).getByText('Device trust updated.',{exact:true}).waitFor()
  await own(second).getByText('Trusted',{exact:true}).waitFor()

  await register(recipient)
  assert.deepEqual(await lookup(recipient,owner),[])
  await trust(own(recipient))
  await own(recipient).getByText('Trusted',{exact:true}).waitFor()
  const bundles=await lookup(recipient,owner)
  assert.equal(bundles.length,2)
  assert.deepEqual(data(await outsider.client.rpc('st_v7_peer_device_bundles',{p_peer:owner.user.id})),[])
  const bundle=bundles.find(item=>item.device===keyState.id)
  assert.ok(bundle)
  const validator=await crypto.subtle.importKey('raw',Buffer.from(bundle.signing_key,'base64url'),
    {name:'ECDSA',namedCurve:'P-256'},false,['verify'])
  const contract=new TextEncoder().encode(JSON.stringify(['sectalk-device-bundle-v1',owner.user.id,bundle.device,bundle.signing_key,bundle.agreement_key]))
  assert.ok(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},validator,Buffer.from(bundle.bundle_signature,'base64url'),contract))

  const issued=await browserSession(first)
  const extra=await first.evaluate(async ({url,publicKey})=>{
    const storage=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
    const previous=JSON.parse(localStorage.getItem(storage))
    const result=await fetch(url+'/auth/v1/token?grant_type=refresh_token',{method:'POST',
      headers:{'content-type':'application/json',apikey:publicKey},
      body:JSON.stringify({refresh_token:previous.refresh_token})})
    if (!result.ok) return false
    const updated=await result.json()
    localStorage.setItem(storage,JSON.stringify(updated))
    return updated.refresh_token!==previous.refresh_token
  },{url:origin,publicKey:key})
  assert.ok(extra)
  const parse=value=>JSON.parse(Buffer.from(value.access_token.split('.')[1],'base64url')).session_id
  assert.equal(parse(issued),parse(await browserSession(first)))
  assert.equal((await lookup(first,peer)).length,1)
  await first.reload()
  await first.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Profile',exact:true}).click()
  await first.getByRole('button',{name:'Devices and sessions',exact:true}).click()
  await own(first).getByText('Trusted',{exact:true}).waitFor()
  assert.deepEqual(await keyInfo(first,owner.user.id),keyState)

  const forged=data(await outsider.client.rpc('st_v7_begin_device_bundle',{
    p_device:randomUUID(),p_signing:bundle.signing_key,p_agreement:bundle.agreement_key,
  }))
  const outsiderSession=data(await outsider.client.auth.getSession()).session
  const attack=await fetch(app+'/api/account/devices/bundle',{method:'POST',
    headers:{'content-type':'application/json',Authorization:'Bearer '+outsiderSession.access_token},
    body:JSON.stringify({challenge:forged.challenge,signature:bundle.bundle_signature,binding:bundle.bundle_signature})})
  assert.equal(attack.status,403)

  data(await admin.rpc('st_v7_mark_device_managed',{p_owner:owner.user.id,p_device:secondId,p_managed:true,p_reference:'local-verified-provider'}))
  const managed=entries(first).filter({has:first.getByText('Managed',{exact:true})})
  await managed.getByText('Managed',{exact:true}).waitFor()
  await managed.getByRole('button',{name:'Block device',exact:true}).click()
  await managed.getByLabel('Current password',{exact:true}).fill(password)
  await managed.getByRole('button',{name:'Confirm block device',exact:true}).click()
  await registry(first).getByText('Blocked',{exact:true}).waitFor()
  await second.getByLabel('Email address',{exact:true}).waitFor()
  assert.deepEqual((await lookup(recipient,owner)).map(item=>item.device),[keyState.id])
  await openRegistry(second,owner)
  await registry(second).getByRole('button',{name:'Register this device',exact:true}).click()
  await registry(second).getByRole('alert').filter({hasText:'This device is unavailable for registration'}).waitFor()
  console.log('Passed unknown, known, trusted, managed and blocked devices, real private keys, verified peer bundle, fresh trust, rotation and linked session revocation.')
} finally {
  await browser.close()
  assert.match(chat,/^[a-f0-9-]{36}$/)
  execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input:`delete from public.st_chats where id='${chat}';`})
  await Promise.allSettled([owner,peer,outsider].map(person=>admin.auth.admin.deleteUser(person.user.id)))
}
