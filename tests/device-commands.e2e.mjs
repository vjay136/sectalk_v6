// Loopback only. The target browser can be offline after its native session is revoked.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(new URL(app).hostname,'127.0.0.1')
assert.equal(origin,'http://127.0.0.1:55321')
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'!1A'
function data(result) {
  if(result.error)throw new Error(result.error.message)
  return result.data
}
async function account(type) {
  const handle='cmd_'+type+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const api=createClient(origin,publicKey,options)
  data(await api.auth.signInWithPassword({email,password}))
  data(await api.rpc('st_save_profile',{p_handle:handle,p_name:'Command fixture '+type}))
  return {user,email,api}
}
async function until(check, ms=25000) {
  const deadline=Date.now()+ms
  while(Date.now()<deadline) {
    const value=await check()
    if(value)return value
    await setTimeout(250)
  }
  throw new Error('Timed out waiting for remote device state')
}
const [owner,outsider]=await Promise.all([account('owner'),account('stranger')])
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const nav=page=>page.getByRole('navigation',{name:'SecTalk features'})
const trustArea=page=>page.getByRole('region',{name:'Device trust',exact:true})
const ownCard=page=>trustArea(page).getByRole('article').filter({hasText:'This registered device'})
async function logIn(page) {
  await page.getByLabel('Email address',{exact:true}).fill(owner.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
}
async function registry(page) {
  await nav(page).getByRole('button',{name:'Profile',exact:true}).click()
  await page.getByRole('button',{name:'Devices and sessions',exact:true}).click()
  await trustArea(page).waitFor()
}
async function open(page) {
  await page.goto(app+'/#account')
  await logIn(page)
  await registry(page)
}
async function register(page) {
  await trustArea(page).getByRole('button',{name:'Register this device',exact:true}).click()
  await ownCard(page).getByText('Known',{exact:true}).waitFor()
}
async function inspect(page) {
  return page.evaluate(accountId=>new Promise((resolve,reject)=>{
    const request=indexedDB.open('sectalk-device-identity')
    request.onerror=()=>reject(request.error)
    request.onsuccess=()=>{
      const database=request.result
      const tx=database.transaction(['identities','command-receipts'])
      const key=tx.objectStore('identities').get(accountId)
      const receipts=tx.objectStore('command-receipts').count()
      tx.oncomplete=()=>{
        database.close()
        resolve({id:key.result?.id??null,privatePresent:Boolean(key.result?.signing.privateKey&&key.result?.agreement.privateKey),
          persistedReceipt:receipts.result})
      }
      tx.onerror=()=>reject(tx.error)
    }
  }),owner.user.id)
}
const status=async device=>data(await owner.api.rpc('st_v7_list_device_commands')).find(row=>row.device===device)
async function issue(card,label) {
  await card.getByRole('button',{name:label,exact:true}).click()
  await card.getByLabel('Current password',{exact:true}).fill(password)
  await card.getByRole('button',{name:'Confirm '+label.toLowerCase(),exact:true}).click()
}

try {
  const [controller,target]=await Promise.all([browser.newPage(),browser.newPage()])
  await Promise.all([open(controller),open(target)])
  await register(controller)
  await register(target)
  const first=await inspect(target)
  assert.ok(first.privatePresent)
  const device=first.id
  const forged=await fetch(app+'/api/account/devices/commands',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({mode:'poll',owner:owner.user.id,device,nonce:randomUUID(),
      at:new Date().toISOString(),proof:'a'.repeat(86)})})
  assert.equal(forged.status,403)
  const fingerprint=await ownCard(target).locator('code').textContent()
  const targetCard=trustArea(controller).getByRole('article').filter({hasText:fingerprint})
  await trustArea(controller).getByRole('button',{name:'Refresh device trust',exact:true}).click()
  await targetCard.waitFor()
  assert.equal(data(await outsider.api.rpc('st_v7_issue_device_command',{p_device:device,p_action:'wipe'})),false)
  assert.deepEqual(data(await outsider.api.rpc('st_v7_list_device_commands')),[])

  const native=await target.evaluate(()=>{
    const authKey=Object.keys(localStorage).find(key=>key.endsWith('-auth-token'))
    return JSON.parse(localStorage.getItem(authKey)).refresh_token
  })
  await target.context().setOffline(true)
  await issue(targetCard,'Revoke device sessions')
  await until(async()=>{const row=await status(device);return row?.kind==='revoke'&&row.state==='pending'})
  assert.ok((await inspect(target)).privatePresent)
  const refresh=await fetch(origin+'/auth/v1/token?grant_type=refresh_token',{method:'POST',
    headers:{apikey:publicKey,'content-type':'application/json'},body:JSON.stringify({refresh_token:native})})
  assert.ok(refresh.status>=400)
  await issue(targetCard,'Cancel pending command')
  await until(async()=>(await status(device))?.state==='cancelled')

  await issue(targetCard,'Lock device')
  await until(async()=>{const row=await status(device);return row?.kind==='lock'&&row.state==='pending'&&row.locked})
  await target.context().setOffline(false)
  await target.getByLabel('Email address',{exact:true}).waitFor({timeout:30000})
  await logIn(target)
  await target.getByRole('heading',{name:'This registered device is locked',exact:true}).waitFor()
  assert.equal(await nav(target).count(),0)
  assert.equal((await inspect(target)).id,device)
  await target.getByLabel('Current password',{exact:true}).fill(password)
  await target.getByRole('button',{name:'Verify and unlock device',exact:true}).click()
  await nav(target).waitFor()
  assert.equal((await inspect(target)).id,device)
  await until(async()=>{const row=await status(device);return !row?.locked&&row?.state==='acknowledged'})

  await target.context().setOffline(true)
  await issue(targetCard,'Wipe local device keys')
  await until(async()=>{const row=await status(device);return row?.kind==='wipe'&&row.state==='pending'})
  await issue(targetCard,'Cancel pending command')
  await until(async()=>{const row=await status(device);return row?.state==='cancelled'&&!row.locked&&!row.wiped})
  assert.ok((await inspect(target)).privatePresent)
  await issue(targetCard,'Wipe local device keys')
  await until(async()=>{const row=await status(device);return row?.kind==='wipe'&&row.state==='pending'})
  assert.ok((await inspect(target)).privatePresent)

  const url='**/api/account/devices/commands'
  await target.route(url,route=>route.request().postDataJSON()?.mode==='ack' ? route.abort() : route.continue())
  await target.context().setOffline(false)
  await until(async()=>{const row=await status(device);return row?.state==='delivered'&&row.wiped})
  await until(async()=>{const local=await inspect(target);return !local.privatePresent&&local.persistedReceipt===1})
  const pending=await status(device)
  const invalidAck=await fetch(app+'/api/account/devices/commands',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({mode:'ack',device,command:pending.command,receipt:'0'.repeat(64)})})
  assert.equal(invalidAck.status,403)
  assert.equal(data(await owner.api.rpc('st_v7_issue_device_command',{
    p_device:device,p_action:'cancel',p_command:pending.command,
  })),false)
  await target.unroute(url)
  await target.reload()
  await until(async()=>{const row=await status(device);return row?.state==='acknowledged'&&row.wiped})
  await until(async()=>(await inspect(target)).persistedReceipt===0)
  assert.deepEqual(await inspect(target),{id:null,privatePresent:false,persistedReceipt:0})

  await target.getByLabel('Email address',{exact:true}).waitFor()
  await logIn(target)
  await registry(target)
  await register(target)
  assert.notEqual((await inspect(target)).id,device)
  assert.equal((await status(device)).wiped,true)
  console.log('Passed browser-independent revoke, offline cancel, blocked lock access, fresh unlock, pending/dispatched/acknowledged wipe, and new-device recovery.')
} finally {
  await browser.close()
  await Promise.allSettled([owner,outsider].map(person=>admin.auth.admin.deleteUser(person.user.id)))
}
