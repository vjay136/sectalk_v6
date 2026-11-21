// Edge browser device enrollment, roster rotations and encrypted message delivery on disposable services.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const checkReports = process.env.SECTALK_GROUP_REPORTS === '1'
const checkSearch = process.env.SECTALK_GROUP_SEARCH === '1'
const checkQuarantine = process.env.SECTALK_GROUP_QUARANTINE === '1'
const checkFiles = process.env.SECTALK_GROUP_FILES === '1'
const checkHistory = process.env.SECTALK_GROUP_HISTORY === '1'
const checkOlmReadiness=process.env.SECTALK_GROUP_OLM_READINESS==='1'
const checkOlmDirect=process.env.SECTALK_OLM_DIRECT==='1'
const checkSenderKeys=process.env.SECTALK_GROUP_SENDER_KEYS==='1'
const trace = label => { if (process.env.SECTALK_GROUP_QA_TRACE === '1') console.log(label) }
function senderCipher(message) {
  assert.ok(message.payload.startsWith('sk2.'))
  return JSON.parse(Buffer.from(message.payload.slice(4),'base64url')).cipher
}
assert.equal(new URL(app).hostname, '127.0.0.1')
assert.equal(origin, 'http://127.0.0.1:55321')
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const password = randomUUID() + '1!Q'
const users = []
let browser, quarantineCase, attachment
const sql = input => execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At',
  '-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1'],{ input,encoding:'utf8',windowsHide:true }).trim()

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(role, name) {
  const handle = 'group_' + role + '_' + randomUUID().slice(0, 8)
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(origin, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, name, email, handle, client }
}

const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
async function open(person, approver) {
  const page = await browser.newPage({ locale: 'en-US' })
  await page.goto(app)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).getByRole('button', { name: 'Group chats', exact: true }).click()
  await page.getByRole('alert').filter({ hasText: 'An approved browser device is required' }).waitFor()
  await page.getByRole('button', { name: 'Manage approved devices' }).click()
  const registry = page.getByRole('region', { name: 'Device trust', exact: true })
  await registry.getByRole('button', { name: 'Register this device', exact: true }).click()
  const device = registry.getByRole('article').filter({ hasText: 'This registered device' })
  await device.getByText('Known', { exact: true }).waitFor()
  let approval = device
  if (approver) {
    await approver.getByRole('button', { name: 'Manage approved devices' }).click()
    const existingRegistry = approver.getByRole('region', { name: 'Device trust', exact: true })
    await existingRegistry.getByRole('button', { name: 'Refresh device trust', exact: true }).click()
    approval = existingRegistry.getByRole('article').filter({ has: approver.getByText('Known', { exact: true }) })
  }
  await approval.getByRole('button', { name: 'Trust device', exact: true }).click()
  await approval.getByLabel('Current password', { exact: true }).fill(password)
  await approval.getByRole('button', { name: 'Confirm trust device', exact: true }).click()
  if (approver) {
    await approver.getByText('Device trust updated.', { exact: true }).waitFor()
    await nav(approver).getByRole('button', { name: 'Group chats', exact: true }).click()
    await registry.getByRole('button', { name: 'Refresh device trust', exact: true }).click()
  }
  await device.getByText('Trusted', { exact: true }).waitFor()
  await nav(page).getByRole('button', { name: 'Group chats', exact: true }).click()
  return page
}

async function session(page) {
  const token = await accessToken(page)
  return createClient(origin, key, { ...options, global: { headers: { Authorization: 'Bearer ' + token } } })
}

async function accessToken(page) {
  return page.evaluate(() => {
    const storage = Object.keys(localStorage).find(name => name.endsWith('-auth-token'))
    return JSON.parse(localStorage.getItem(storage)).access_token
  })
}

async function requestAs(page, url) {
  return fetch(url,{headers:{Authorization:'Bearer '+await accessToken(page)},signal:AbortSignal.timeout(10000)})
}

async function send(page, message) {
  await page.getByLabel('Group message', { exact: true }).fill(message)
  await page.getByRole('button', { name: 'Send encrypted message', exact: true }).click()
  await page.getByText(message, { exact: true }).waitFor()
}

async function responseConsole(operator) {
  const page = await browser.newPage()
  await page.goto(app)
  await page.getByLabel('Email address',{exact:true}).fill(operator.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).getByRole('button',{name:'Safety',exact:true}).click()
  await page.getByRole('group',{name:'Safety center sections'}).getByRole('button',{name:'Threat triage',exact:true}).click()
  await verifyStaffPanel(page)
  return page.getByRole('region',{name:'SOC response requests',exact:true})
}

try {
  const [owner, peer, newcomer] = await Promise.all([
    account('owner', 'Group Alice'), account('peer', 'Group Bob'), account('new', 'Group Charlie'),
  ])
  let approvedPair
  for (const contact of [peer, newcomer]) {
    const chat = data(await owner.client.rpc('st_request', { p_handle: contact.handle }))
    data(await contact.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
    if(contact===peer)approvedPair=chat
  }
  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const [a, b, c] = await Promise.all([open(owner), open(peer), open(newcomer)])
  const b2 = await open(peer, b)
  trace('Approved browser fixtures ready.')
  if(checkOlmReadiness||checkOlmDirect){
    let successfulUpload
    for(const page of [a,b]){
      await nav(page).getByRole('button',{name:'Profile',exact:true}).click()
      await page.getByRole('button',{name:'Devices and sessions',exact:true}).click()
      const uploaded=page.waitForResponse(response=>response.url()===app+'/api/e2ee/device')
      await page.getByRole('button',{name:'Prepare this browser',exact:true}).click()
      successfulUpload=await uploaded
      assert.equal(successfulUpload.status(),200)
      await page.getByText('This approved browser has published its encryption keys.',{exact:true}).waitFor()
      await nav(page).getByRole('button',{name:'Group chats',exact:true}).click()
    }
    const [ownerBrowser,peerBrowser,outsiderBrowser]=await Promise.all([session(a),session(b),session(c)])
    const pair=data(await ownerBrowser.rpc('st_v8_olm_pair_directory',{p_chat:approvedPair}))
    const receiver=data(await peerBrowser.rpc('st_v8_olm_device_proof'))
    assert.equal(pair.roster.find(entry=>entry.device===receiver.device).bundle.device_id,receiver.device)
    assert.equal(pair.roster.filter(entry=>entry.bundle).length,2)
    assert.ok((await outsiderBrowser.rpc('st_v8_olm_pair_directory',{p_chat:approvedPair})).error)
    const captured=successfulUpload.request().postDataJSON()
    const tampered=await fetch(app+'/api/e2ee/device',{method:'POST',headers:{Authorization:'Bearer '+await accessToken(b),
      'Content-Type':'application/json'},body:JSON.stringify({...captured,bundle:{...captured.bundle,device_id:crypto.randomUUID()}})})
    assert.equal(tampered.status,403)
    console.log('PASS: Edge prepared and published real Olm keys for two approved devices, denied an outsider and rejected a mutated bundle')
    if(checkOlmDirect){
      const screens=[[a,peer.name],[b,owner.name]]
      const numbers=[]
      for(const [page,name] of screens){
        await nav(page).getByRole('button',{name:'Inbox',exact:true}).click()
        await page.getByRole('button',{name:new RegExp(name)}).first().click()
        await page.getByRole('button',{name:'Verify contact keys',exact:true}).click()
        const safety=page.getByLabel('Safety number',{exact:true})
        await safety.waitFor()
        numbers.push(await safety.textContent())
      }
      assert.equal(numbers[0],numbers[1])
      for(const [page] of screens){
        await page.getByLabel('Safety number or scanned QR value',{exact:true}).fill(numbers[0])
        await page.getByRole('button',{name:'Check and verify',exact:true}).click()
        await page.getByText('The current contact keys are verified on this browser.',{exact:true}).waitFor()
        await page.getByRole('button',{name:'Close dialog',exact:true}).click()
        await page.getByRole('button',{name:'Secure direct messages',exact:true}).click()
      }
      await a.getByRole('button',{name:'Enable secure messages',exact:true}).click()
      await a.getByText('Waiting for '+peer.name+' to enable secure messages.',{exact:true}).waitFor()
      await b.getByRole('button',{name:'Enable secure messages',exact:true}).click()
      await a.getByLabel('Write a secure message',{exact:true}).waitFor()
      const firstSecure='Secure pair fixture '+randomUUID()
      const secondSecure='Secure response fixture '+randomUUID()
      for(const [page,other,text] of [[a,b,firstSecure],[b,a,secondSecure]]){
        await page.getByLabel('Write a secure message',{exact:true}).fill(text)
        const sent=page.waitForResponse(response=>response.url().endsWith('/rpc/st_v8_olm_direct_send'),{timeout:20000})
        await page.getByRole('button',{name:'Send secure message',exact:true}).click()
        const received=await sent.catch(async cause=>{
          const alert=await page.getByRole('region',{name:'Secure direct messages',exact:true}).getByRole('alert').textContent({timeout:1000}).catch(()=>null)
          throw alert?new Error(alert,{cause}):cause
        })
        assert.equal(received.status(),200)
        for(const side of [page,other])await side.getByText(text,{exact:true}).waitFor()
      }
      const repeated='Secure delivery with a lost acknowledgement '+randomUUID()
      let acceptedId
      await a.route('**/rpc/st_v8_olm_direct_send',async route=>{
        const response=await route.fetch()
        assert.equal(response.status(),200)
        acceptedId=route.request().postDataJSON().p_message
        await route.fulfill({response,status:503,json:{message:'Synthetic response loss after the native send committed'}})
      },{times:1})
      await a.getByLabel('Write a secure message',{exact:true}).fill(repeated)
      const lost=a.waitForResponse(response=>response.status()===503&&response.url().endsWith('/rpc/st_v8_olm_direct_send'))
      await a.getByRole('button',{name:'Send secure message',exact:true}).click()
      await lost
      await b.getByText(repeated,{exact:true}).waitFor()
      const retried=a.waitForResponse(response=>response.status()===200&&response.url().endsWith('/rpc/st_v8_olm_direct_send'))
      await a.getByRole('button',{name:'Send secure message',exact:true}).click()
      assert.equal((await retried).request().postDataJSON().p_message,acceptedId)
      const ciphertext=data(await peerBrowser.rpc('st_v8_olm_direct_read',{p_chat:approvedPair}))
      assert.equal(ciphertext.events.length,3)
      assert.equal(ciphertext.events.filter(message=>message.id===acceptedId).length,1)
      assert.ok(!JSON.stringify(ciphertext).includes(firstSecure)&&!JSON.stringify(ciphertext).includes(secondSecure))
      assert.ok((await outsiderBrowser.rpc('st_v8_olm_direct_read',{p_chat:approvedPair})).error)
      console.log('PASS: secure direct messages required two opt-ins and verified keys, delivered both directions, prevented duplicate delivery, and denied an outsider')
      for(const [page] of screens)await nav(page).getByRole('button',{name:'Group chats',exact:true}).click()
    }
  }
  const title = 'Encrypted browser fixture'
  await a.getByRole('button', { name: 'New group', exact: true }).click()
  await a.getByLabel('Group name', { exact: true }).fill(title)
  await a.getByRole('checkbox', { name: peer.name, exact: true }).check()
  await a.getByRole('button', { name: 'Create encrypted group', exact: true }).click()
  await a.getByRole('heading', { name: title, exact: true }).waitFor()
  const id = await a.getByLabel('Open group').inputValue()
  assert.match(id, /^[0-9a-f-]{36}$/)
  for (const page of [b, b2]) await page.getByLabel('Open group').selectOption({ label: title })
  const first = 'First private group message ' + randomUUID()
  await send(a, first)
  for (const page of [b, b2]) await page.getByText(first, { exact: true }).waitFor()
  const [ac, bc, b2c, cc] = await Promise.all([session(a), session(b), session(b2), session(c)])
  const group = (client, action, values) => client.rpc('st_group_chat', { p_action: action, p_group: id, p_data: values })
  const before = data(await group(bc, 'read'))
  const beforeSecond = data(await group(b2c, 'read'))
  assert.equal(before.group.epoch, 1)
  assert.equal(before.envelopes.length, 1)
  assert.equal(beforeSecond.envelopes.length, 1)
  assert.notEqual(before.device, beforeSecond.device)
  assert.notEqual(before.envelopes[0].sealed, beforeSecond.envelopes[0].sealed)
  assert.ok(!JSON.stringify(before).includes(first) && before.messages[0].signature.length === 86)
  if(checkSenderKeys){
    const text='Independent approved-device sender '+randomUUID()
    await send(b,text)
    for(const page of [a,b2])await page.getByText(text,{exact:true}).waitFor()
    const other=data(await group(ac,'read')).messages.at(-1)
    assert.notEqual(senderCipher(other).session_id,senderCipher(before.messages[0]).session_id)
    assert.notEqual(senderCipher(other).sender_key,senderCipher(before.messages[0]).sender_key)
    assert.ok(!JSON.stringify(other).includes(text))
  }
  if(checkFiles){
    trace('Beginning encrypted attachment flow.')
    const filename='private-fixture-'+randomUUID().slice(0,8)+'.txt'
    const original=Buffer.from('Synthetic confidential attachment '+randomUUID())
    await a.getByLabel('Encrypted group attachment',{exact:true}).setInputFiles({name:filename,mimeType:'text/plain',buffer:original})
    trace('Encrypted attachment selected in the browser.')
    const [stored,result]=await Promise.all([
      a.waitForResponse(reply=>reply.url().includes('/api/group-files?file=')&&reply.request().method()==='POST',{timeout:15000})
        .then(reply=>{trace('Encrypted upload returned HTTP '+reply.status()+'.');return reply}),
      a.waitForResponse(reply=>new URL(reply.url()).pathname.endsWith('/rpc/st_v7_publish_group_file'),{timeout:18000})
        .then(reply=>{trace('Attachment publication returned HTTP '+reply.status()+'.');return reply}),
      a.getByRole('button',{name:'Send encrypted attachment',exact:true}).click(),
    ]).catch(async cause=>{
      const error=await a.getByRole('alert').first().textContent({timeout:1000}).catch(()=>null)
      if(error)throw new Error(error,{cause})
      throw cause
    })
    attachment={file:new URL(stored.url()).searchParams.get('file'),url:null}
    assert.equal(stored.status(),200)
    const file=attachment.file
    assert.match(file,/^[a-f0-9-]{36}$/)
    assert.equal(result.status(),200)
    const message=result.request().postDataJSON().p_encrypted.id
    assert.match(message,/^[a-f0-9-]{36}$/)
    trace('Ciphertext stored and message published.')
    attachment.url=app+'/api/group-files?file='+file+'&message='+message
    const storedBytes=data(await admin.storage.from('sectalk-encrypted-group-files').download(file))
    const cipher=Buffer.from(await storedBytes.arrayBuffer())
    trace('Stored ciphertext fetched for comparison.')
    assert.equal(cipher.length,original.length+28)
    assert.ok(!cipher.includes(original))
    assert.ok(!JSON.stringify(data(await group(bc,'read'))).includes(filename))
    assert.equal((await requestAs(c,attachment.url)).status,404)
    trace('Outsider attachment API access denied.')
    assert.ok((await bc.storage.from('sectalk-encrypted-group-files').createSignedUrl(file,30)).error)
    trace('Raw Storage signed URL denied.')
    for(const page of [b,b2]){
      const action=page.getByRole('button',{name:'Download '+filename,exact:true})
      const [saved]=await Promise.all([page.waitForEvent('download',{timeout:15000}),action.click()]).catch(async cause=>{
        const error=await action.locator('..').getByRole('alert').textContent({timeout:1000}).catch(()=>null)
        if(error)throw new Error(error,{cause})
        throw cause
      })
      assert.equal(saved.suggestedFilename(),filename)
      assert.deepEqual(await readFile(await saved.path()),original)
      trace('Approved browser downloaded expected clear bytes.')
    }
    const target=attachment.url
    await b.route(target,async route=>{
      const original=await route.fetch()
      const tampered=await original.body()
      tampered[tampered.length-1]^=1
      await route.fulfill({response:original,body:tampered})
    })
    await b.getByRole('button',{name:'Download '+filename,exact:true}).click()
    trace('Attempting tampered ciphertext download.')
    await b.getByRole('alert').filter({hasText:'The encrypted attachment could not be verified.'}).waitFor()
    await b.unroute(target)
    console.log('PASS: private ciphertext upload, two approved browser downloads, raw signed-link denial and tamper rejection')
  }
  if(checkHistory){
    const newBrowser=await open(peer,b)
    await newBrowser.getByLabel('Open group').selectOption({label:title})
    await newBrowser.getByText('Ask the group owner to refresh keys for this approved device.',{exact:true}).waitFor()
    assert.equal(await newBrowser.getByText(first,{exact:true}).count(),0)
    await b.getByLabel('Open group').selectOption({label:title})
    await b.getByText(first,{exact:true}).waitFor()
    const menu=b.locator('details').filter({has:b.getByText('Transfer encrypted history',{exact:true})})
    await menu.locator('summary').click()
    const selector=menu.getByLabel('Approved browser',{exact:true})
    await selector.waitFor()
    assert.equal(await selector.locator('option').count(),1)
    const sourceSession=JSON.parse(Buffer.from((await accessToken(b)).split('.')[1],'base64url')).session_id
    assert.match(sourceSession,/^[a-f0-9-]{36}$/)
    sql(`update auth.mfa_amr_claims set created_at=now()-interval '11 minutes',updated_at=now()-interval '11 minutes' where session_id='${sourceSession}';`)
    await menu.getByRole('button',{name:'Transfer group history',exact:true}).click()
    await menu.getByLabel('Current password',{exact:true}).fill(password)
    const request=b.waitForResponse(response=>response.url().endsWith('/api/group-history')&&response.request().method()==='POST',{timeout:20000})
    await menu.getByRole('button',{name:'Verify and continue',exact:true}).click()
    const completed=await request
    assert.equal(completed.status(),200)
    await menu.getByText('Group history was shared with the selected approved browser.',{exact:true}).waitFor()
    await newBrowser.getByText(first,{exact:true}).waitFor()
    const payload=completed.request().postDataJSON()
    assert.deepEqual(Object.keys(payload).sort(),['envelopes','nonce','signature'])
    assert.ok(!JSON.stringify(payload).includes(first))
    const reject=async(page,data)=>fetch(app+'/api/group-history',{method:'POST',headers:{
      Authorization:'Bearer '+await accessToken(page),'Content-Type':'application/json',
    },body:JSON.stringify(data)})
    assert.equal((await reject(newBrowser,payload)).status,403)
    assert.equal((await reject(b,{...payload,signature:'A'.repeat(86)})).status,403)
    await newBrowser.close()
    console.log('PASS: fresh native proof and source-device signature restored history only to an approved same-account browser')
  }
  if (process.env.SECTALK_GROUP_RICH_TEXT === '1') {
    const watch = []
    const link = 'https://approved-a.example.invalid/start?encrypted-local-only=unique'
    const formatted = '**Encrypted bold** [Encrypted docs](' + link + ')'
    b.on('request', request => {
      if (request.url().includes('url-inspection') || request.url().includes('approved-a.example.invalid') ||
          (request.postData() || '').includes('encrypted-local-only')) watch.push(request.url())
    })
    const settings = b.locator('details.rich-message-formatting')
    await settings.locator('summary').click()
    await settings.getByLabel('Enable link previews on this device').check()
    await a.getByLabel('Group message', { exact: true }).fill(formatted)
    await a.getByRole('button', { name: 'Send encrypted message', exact: true }).click()
    const entry = b.getByRole('list', { name: 'Group messages' }).getByRole('listitem').filter({ hasText: 'Encrypted bold' })
    await entry.locator('strong').filter({ hasText: 'Encrypted bold' }).waitFor()
    await entry.getByText('Link domain approved-a.example.invalid', { exact: true }).waitFor()
    assert.equal(await entry.locator('a[href]').count(), 0, 'encrypted previews do not expose an anchor that can prefetch')
    assert.equal(await entry.getByRole('button', { name: /Encrypted docs/ }).count(), 1)
    assert.ok(!JSON.stringify(data(await group(bc, 'read'))).includes('encrypted-local-only'))
    await settings.getByLabel('Enable link previews on this device').uncheck()
    assert.equal(await entry.getByText('Link domain approved-a.example.invalid', { exact: true }).count(), 0)
    assert.deepEqual(watch, [])
    console.log('Encrypted group rendered Markdown and generated the domain preview locally with zero URL disclosure.')
  }
  assert.equal((await group(cc, 'read')).error?.code, '42501')
  assert.equal((await group(peer.client, 'read')).error?.code, '42501')
  async function search(page, query, count) {
    const area = page.getByRole('region', { name: 'Encrypted group search' })
    await area.getByLabel('Search encrypted messages', { exact: true }).fill(query)
    await area.getByRole('button', { name: 'Search this device', exact: true }).click()
    await area.getByRole('status').filter({ hasText: count ? count + ' matching messages' : 'No matching messages' }).waitFor()
    return area.getByLabel('Encrypted search results', { exact: true })
  }
  const inspectIndex = (page, entry) => page.evaluate(id => new Promise((resolve, reject) => {
    const open = indexedDB.open('sectalk-encrypted-group-search')
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const database = open.result
      const query = database.transaction('records').objectStore('records').getAll()
      query.onerror = () => reject(query.error)
      query.onsuccess = () => {
        database.close()
        resolve(query.result.filter(row => row.id === id).map(row => ({
          keys: Object.keys(row).sort(),
          id: row.id, group: row.group, device: row.device, owner: row.owner,
          ciphertext: Array.from(new Uint8Array(row.sealed)),
        })))
      }
    }
  }), entry)
  if (checkSearch) {
    const request = b.waitForRequest(req => req.url().endsWith('/rpc/st_group_search_metadata'))
    const results = await search(b, 'private group message', 1)
    await results.getByText(first, { exact: true }).waitFor()
    assert.deepEqual((await request).postDataJSON(), { p_group: id })
    const metadata = data(await bc.rpc('st_group_search_metadata', { p_group: id }))
    assert.deepEqual(Object.keys(metadata).sort(), ['device', 'messages'])
    assert.deepEqual(Object.keys(metadata.messages[0]).sort(), ['epoch', 'id', 'sent'])
    assert.equal(metadata.messages[0].id, before.messages[0].id)
    const [local] = await inspectIndex(b, before.messages[0].id)
    const [secondLocal] = await inspectIndex(b2, before.messages[0].id)
    assert.deepEqual(local.keys, ['device', 'epoch', 'group', 'id', 'iv', 'owner', 'sealed', 'sent'])
    assert.equal(local.owner, peer.id)
    assert.equal(local.device, before.device)
    assert.equal(local.group, id)
    assert.equal(local.ciphertext.length, Buffer.byteLength(first) + 16)
    assert.ok(!Buffer.from(local.ciphertext).includes(first))
    assert.notEqual(local.device, secondLocal.device)
    assert.notDeepEqual(local.ciphertext, secondLocal.ciphertext)
    await b.reload()
    await nav(b).waitFor()
    assert.deepEqual(await inspectIndex(b, before.messages[0].id), [local])
    await nav(b).getByRole('button', { name: 'Group chats', exact: true }).click()
    await b.getByLabel('Open group').selectOption({ label: title })
    await (await search(b, first.slice(0, 25), 1)).getByText(first, { exact: true }).waitFor()
    const metadataRoute = '**/rpc/st_group_search_metadata'
    await b.route(metadataRoute, route => route.abort())
    const area = b.getByRole('region', { name: 'Encrypted group search' })
    await area.getByRole('button', { name: 'Search this device', exact: true }).click()
    await area.getByRole('alert').filter({ hasText: 'Could not search recent messages on this device.' }).waitFor()
    assert.equal(await area.getByLabel('Encrypted search results').count(), 0)
    await b.unroute(metadataRoute)
  }
  const oldPeerMessage = 'Second device can sign messages'
  await send(b2, oldPeerMessage)
  await a.getByText(oldPeerMessage, { exact: true }).waitFor()

  await a.getByRole('button', { name: 'Manage members and encryption', exact: true }).click()
  await a.getByRole('checkbox', { name: newcomer.name, exact: true }).check()
  await a.getByRole('button', { name: 'Save members and rotate keys', exact: true }).click()
  await c.getByLabel('Open group').selectOption({ label: title })
  const afterJoin = data(await group(cc, 'read'))
  assert.equal(afterJoin.group.epoch, 2)
  assert.deepEqual(afterJoin.messages, [])
  assert.deepEqual(afterJoin.envelopes.map(envelope => envelope.epoch), [2])
  if (checkSearch) {
    await search(c, 'private group message', 0)
    assert.deepEqual(await inspectIndex(c, before.messages[0].id), [])
    const metadata = data(await cc.rpc('st_group_search_metadata', { p_group: id }))
    assert.ok(metadata.messages.every(message => message.epoch >= 2))
  }
  const newlyJoined = 'Fresh ciphertext after Charlie joined'
  await send(a, newlyJoined)
  await c.getByText(newlyJoined, { exact: true }).waitFor()
  await b.getByText(newlyJoined, { exact: true }).waitFor()
  assert.equal(await c.getByText(first, { exact: true }).count(), 0)

  await a.getByRole('button', { name: 'Manage members and encryption', exact: true }).click()
  await a.getByRole('checkbox', { name: peer.name, exact: true }).uncheck()
  await a.getByRole('button', { name: 'Save members and rotate keys', exact: true }).click()
  await a.getByRole('heading', { name: title, exact: true }).waitFor()
  await a.getByRole('button', { name: 'Save members and rotate keys', exact: true }).waitFor({ state: 'detached' })
  const afterRemoval = data(await group(ac, 'read'))
  assert.equal(afterRemoval.group.epoch, 3)
  assert.notEqual(afterRemoval.envelopes.find(envelope => envelope.epoch === 1).ephemeral,
    afterRemoval.envelopes.find(envelope => envelope.epoch === 3).ephemeral)
  const after = 'Fresh ciphertext after both Bob devices were removed'
  await send(a, after)
  await c.getByText(after, { exact: true }).waitFor()

  const newest = data(await group(ac, 'read')).messages.at(-1)
  assert.equal(newest.epoch, 3)
  if(checkSenderKeys)assert.notEqual(senderCipher(newest).session_id,senderCipher(before.messages[0]).session_id)
  const oldKeyRejected = await b.evaluate(async ({ owner, snapshot, newest }) => {
    const old = snapshot.envelopes[0]
    const decode = text => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), character => character.charCodeAt(0))
    const wire = parts => new TextEncoder().encode(JSON.stringify(['sectalk-group-chat-v1', ...parts]))
    const identity = await new Promise((resolve, reject) => {
      const open = indexedDB.open('sectalk-device-identity')
      open.onerror = () => reject(open.error)
      open.onsuccess = () => {
        const query = open.result.transaction('identities').objectStore('identities').get(owner)
        query.onerror = () => reject(query.error)
        query.onsuccess = () => { resolve(query.result); open.result.close() }
      }
    })
    const publicKey = await crypto.subtle.importKey('raw', decode(old.ephemeral), { name: 'ECDH', namedCurve: 'P-256' }, false, [])
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, identity.agreement.privateKey, 256)
    const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
    const context = wire(['wrap', snapshot.group.id, old.epoch, owner, snapshot.device, old.ephemeral])
    const wrappingKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: context },
      material, { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
    const oldBytes = decode(old.sealed)
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: oldBytes.subarray(0, 12), additionalData: context }, wrappingKey, oldBytes.subarray(12))
    const oldKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt'])
    const senderPacket=newest.payload.startsWith('sk2.')?JSON.parse(new TextDecoder().decode(decode(newest.payload.slice(4)))):null
    const nextBytes=decode(senderPacket?.sealed??newest.payload)
    const nextContext=senderPacket
      ?wire(['sender-export',snapshot.group.id,newest.epoch,newest.actor,newest.device,senderPacket.cipher.session_id])
      :wire(['message',snapshot.group.id,newest.epoch,newest.id,newest.actor,newest.device])
    try {
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nextBytes.subarray(0, 12),
        additionalData: nextContext },
      oldKey, nextBytes.subarray(12))
      return false
    } catch (error) {
      return error.name === 'OperationError'
    }
  }, { owner: peer.id, snapshot: before, newest })
  assert.equal(oldKeyRejected, true)
  for (const [page, client] of [[b, bc], [b2, b2c]]) {
    assert.equal((await group(client, 'read')).error?.code, '42501')
    assert.equal((await group(client, 'send', { ...before.messages[0], id: randomUUID(), epoch: 3 })).error?.code, '42501')
    await page.getByLabel('Open group').getByRole('option', { name: title, exact: true }).waitFor({ state: 'detached' })
    assert.equal(await page.getByText(after, { exact: true }).count(), 0)
    if(checkFiles&&attachment?.url)assert.equal((await requestAs(page,attachment.url)).status,404)
  }
  if (checkSearch) {
    for (const [page, client] of [[b, bc], [b2, b2c]]) {
      assert.equal((await client.rpc('st_group_search_metadata', { p_group: id })).error?.code, '42501')
      assert.deepEqual(await inspectIndex(page, before.messages[0].id), [])
      assert.equal(await page.getByRole('region', { name: 'Encrypted group search' }).count(), 0)
    }
    const ownStored = await inspectIndex(a, before.messages[0].id)
    assert.equal(ownStored.length, 1)
    assert.equal(ownStored[0].owner, owner.id)
    await nav(a).getByRole('button', { name: 'Sign out', exact: true }).click()
    await a.getByLabel('Email address', { exact: true }).fill(newcomer.email)
    await a.getByLabel('Password', { exact: true }).fill(password)
    await a.locator('button.submit-auth').click()
    await nav(a).getByRole('button', { name: 'Group chats', exact: true }).click()
    await a.getByRole('alert').filter({ hasText: 'An approved browser device is required' }).waitFor()
    assert.equal(await a.getByText(first, { exact: true }).count(), 0)
    assert.equal(await a.getByRole('region', { name: 'Encrypted group search' }).count(), 0)
    assert.deepEqual(await inspectIndex(a, before.messages[0].id), ownStored)
    console.log('PASS: IndexedDB persistence with device-specific ciphertext, metadata-only revalidation, offline denial, same-profile account isolation, newcomer isolation, and removal-triggered physical purge')
  }
  if (checkReports) {
    const requests = []
    c.on('request', request => {
      if (request.method() === 'POST') requests.push({ url: request.url(), body: request.postData() })
    })
    const privateText = 'Please send your one-time code so I can verify your account. ' + randomUUID()
    const disclosedText = 'Act now and pay in crypto before this offer goes away. ' + randomUUID()
    for (const text of [privateText, disclosedText]) {
      await send(a, text)
      await c.getByText(text, { exact: true }).waitFor()
    }
    assert.ok(requests.every(request => !request.body?.includes(privateText) && !request.body?.includes(disclosedText)))
    const privateLine = c.getByRole('listitem').filter({ hasText: privateText })
    const disclosedLine = c.getByRole('listitem').filter({ hasText: disclosedText })
    await privateLine.getByText(/may ask for a password.*Checked on this device/).waitFor()
    await disclosedLine.getByText(/may pressure you to send money.*Checked on this device/).waitFor()
    await privateLine.getByText('Report group message', { exact: true }).click()
    await privateLine.getByRole('button', { name: 'Submit report without message text', exact: true }).click()
    await privateLine.getByText('Report submitted to Safety.', { exact: true }).waitFor()
    const privateTicket=await privateLine.getByRole('status').locator('code').textContent()
    assert.match(privateTicket,/^[a-f0-9-]{36}$/)
    const reportRequests = () => requests.filter(request => request.url.endsWith('/rpc/st_report_group_message'))
      .map(request => JSON.parse(request.body))
    const [metadata] = reportRequests()
    assert.equal(metadata.p_share, false)
    assert.equal(metadata.p_evidence, null)
    assert.ok(requests.every(request => !request.body?.includes(privateText)))
    await disclosedLine.getByText('Report group message', { exact: true }).click()
    await disclosedLine.getByRole('checkbox', { name: 'Share this message’s text with verified Safety reviewers' }).check()
    await disclosedLine.locator('blockquote').filter({ hasText: disclosedText }).waitFor()
    await disclosedLine.getByRole('button', { name: 'Submit report with message text', exact: true }).click()
    await disclosedLine.getByText('Report submitted to Safety.', { exact: true }).waitFor()
    const disclosedTicket=await disclosedLine.getByRole('status').locator('code').textContent()
    assert.match(disclosedTicket,/^[a-f0-9-]{36}$/)
    assert.notEqual(disclosedTicket,privateTicket)
    const [, disclosure] = reportRequests()
    assert.equal(disclosure.p_share, true)
    assert.equal(disclosure.p_evidence, disclosedText)
    assert.ok(requests.every(request => !request.body?.includes(privateText)))
    const reports = data(await cc.from('st_reports').select('id,category,status').eq('reporter', newcomer.id))
    assert.equal(reports.length, 2)
    assert.deepEqual(reports.map(report=>report.id).sort(),[privateTicket,disclosedTicket].sort())
    assert.ok(reports.every(report => report.category === 'scam' && report.status === 'open'))
    assert.deepEqual(data(await ac.from('st_reports').select('id').eq('reporter', newcomer.id)), [])
    assert.equal((await cc.from('st_reports').select('evidence').eq('reporter', newcomer.id)).error?.code, '42501')
    assert.equal((await cc.rpc('st_v5_case', { p_report: reports[0].id })).error?.message, 'Staff MFA required')
    console.log('PASS: on-device warnings kept both messages local; Safety received plaintext only for the explicitly shared report')
    if (checkQuarantine) {
      quarantineCase = sql(`select id from public.st_reports where reporter='${newcomer.id}' and group_message_id='${disclosure.p_message}';`)
      assert.match(quarantineCase,/^[a-f0-9-]{36}$/)
      const [requester,reviewer] = await Promise.all([account('qa','Group case requester'),account('qr','Group case reviewer')])
      sql(`insert into sectalk_private.staff values('${requester.id}'),('${reviewer.id}');
        insert into sectalk_private.st_v7_threat_reviewers values('${requester.id}','detection'),('${reviewer.id}','detection');
        insert into sectalk_private.st_v7_soc_response_grants(actor,action,role) values
          ('${requester.id}','quarantine_message','requester'),('${reviewer.id}','quarantine_message','approver');`)
      const requestPanel = await responseConsole(requester)
      await requestPanel.getByLabel('Response action',{exact:true}).selectOption('quarantine_message:')
      await requestPanel.getByLabel('Open report ID',{exact:true}).fill(quarantineCase)
      await requestPanel.getByLabel('Request reason',{exact:true}).fill('Exact reported group message and opt-in evidence reviewed.')
      await requestPanel.getByRole('button',{name:'Request SOC response',exact:true}).click()
      await requestPanel.getByText('Response sent for separate approval.',{exact:true}).waitFor()
      const approvalPanel = await responseConsole(reviewer)
      const card = approvalPanel.getByRole('article').filter({hasText:quarantineCase})
      await card.getByLabel('Response decision',{exact:true}).selectOption('approve')
      await card.getByLabel('Decision reason',{exact:true}).fill('Independent scope and consent verified.')
      await card.getByRole('button',{name:'Apply response decision',exact:true}).click()
      await card.getByText(/Executed/).waitFor()
      await c.getByText('Message quarantined by Safety review.',{exact:true}).waitFor()
      assert.equal(await c.getByText(disclosedText,{exact:true}).count(),0)
      await c.getByText(privateText,{exact:true}).waitFor()
      const read = data(await group(cc,'read'))
      const removed = read.messages.find(message => message.id===disclosure.p_message)
      assert.equal(removed.quarantined,true)
      assert.equal('payload' in removed,false)
      assert.equal(data(await cc.rpc('st_group_search_metadata',{p_group:id})).messages
        .some(message => message.id===disclosure.p_message),false)
      assert.equal(sql(`select evidence is not null from public.st_reports where id='${quarantineCase}';`),'t')
      console.log('PASS: two-person group response produced a live tombstone and preserved only the consented report evidence for staff')
    }
    await nav(c).getByRole('button',{name:'Safety',exact:true}).click()
    await c.getByRole('group',{name:'My report scopes',exact:true}).getByRole('button',{name:'Chat reports',exact:true}).click()
    await c.getByLabel('Filter recent reports by ticket number',{exact:true}).fill(privateTicket)
    const timeline=c.getByRole('region',{name:'My chat reports',exact:true})
    await timeline.getByText(privateTicket,{exact:true}).waitFor()
    assert.equal(await timeline.getByText(disclosedTicket,{exact:true}).count(),0)
    await timeline.getByRole('button',{name:/Scam or fraud/}).click()
    await c.getByRole('heading',{name:'Report timeline',exact:true}).waitFor()
    await c.getByText('Report received',{exact:true}).waitFor()
    assert.equal(await c.getByText('Response from SecTalk Safety',{exact:true}).count(),0)
    console.log('PASS: group report receipts match the private report list and reporter-only action history')
  }
  console.log('PASS: approved-device enrollment, native encryption and signatures across four browser contexts, no old keys on join, and both devices denied after removal')
} finally {
  await browser?.close()
  if(attachment?.file&&/^[0-9a-f-]{36}$/.test(attachment.file)){
    await admin.storage.from('sectalk-encrypted-group-files').remove([attachment.file])
    sql(`delete from sectalk_private.st_v7_group_files where id='${attachment.file}';`)
  }
  if (quarantineCase) sql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v7_group_quarantine where case_id='${quarantineCase}';
    delete from sectalk_private.st_v7_soc_responses where case_id='${quarantineCase}';
    delete from sectalk_private.audit where report_id='${quarantineCase}'; commit;`)
  if (checkReports && users.length) {
    assert.ok(users.every(id => /^[0-9a-f-]{36}$/.test(id)))
    execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-U', 'postgres', '-d', 'postgres',
      '-v', 'ON_ERROR_STOP=1', '-f', '-'], {
      input: "delete from public.st_reports where group_chat_id is not null and reporter in (" +
        users.map(id => "'" + id + "'").join(',') + ");",
    })
  }
  if (checkQuarantine && users.length) sql('delete from sectalk_private.staff where user_id in (' + users.map(id => "'" + id + "'").join(',') + ');')
  await Promise.allSettled(users.map(id => admin.auth.admin.deleteUser(id)))
}
