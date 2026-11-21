// Run against disposable loopback SecTalk, Supabase, and LiveKit services.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')
const { SECTALK_STORAGE_TEST_PUBLIC_KEY: publicKey, SECTALK_STORAGE_TEST_SERVICE_KEY: serviceKey } = process.env
assert.ok(publicKey && serviceKey)
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.href, serviceKey, options)
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '!1Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase().slice(0, 15) + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.href, publicKey, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, client, email, handle, name, token: session.access_token }
}

const [owner, guest, visitor] = await Promise.all([account('ModerationHost'), account('ModerationGuest'), account('ModerationVisitor')])
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Moderator checks' }))
for (const member of [guest, visitor]) {
  data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
  const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
  data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
}
const title = 'Moderator checks ' + suffix
const meeting = data(await owner.client.rpc('st_v6_start_instant_meeting', {
  p_id: randomUUID(), p_workspace: workspace, p_title: title, p_minutes: 15,
}))
data(await guest.client.rpc('st_v3_request_admission', { p_meeting: meeting }))
data(await owner.client.rpc('st_v3_admit', { p_meeting: meeting, p_user: guest.id, p_allow: true }))

const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({
  executablePath: process.env.SECTALK_TEST_BROWSER,
  args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
})
const link = new URL(app.href)
link.searchParams.set('meeting', meeting)
const diagnostics = []
const button = (page, name) => page.getByRole('button', { name, exact: true })
const stage = page => page.locator('.meeting-media')
const microphone = page => stage(page).locator('button[data-lk-source="microphone"]')
const moderation = page => page.getByRole('region', { name: 'Meeting moderation' })
const roster = page => page.getByRole('region', { name: 'Waiting room and attendance' })
const tile = (page, person) => stage(page).locator('[data-lk-participant-name="' + person.name + '"]').first()

async function open(person) {
  const page = await browser.newPage({ locale: 'en-US', permissions: ['microphone', 'camera'] })
  page.on('console', event => {
    if (event.type() === 'error') diagnostics.push(person.name + ' ' + event.text())
  })
  if (person === guest) await page.addInitScript(() => {
    navigator.mediaDevices.getDisplayMedia = async () => {
      const canvas = document.createElement('canvas')
      canvas.width = 320
      canvas.height = 180
      const context = canvas.getContext('2d')
      const stream = canvas.captureStream(8)
      let frames = 0
      const timer = setInterval(() => {
        if (stream.getVideoTracks()[0].readyState === 'ended') clearInterval(timer)
        context.fillStyle = frames++ % 2 ? 'purple' : 'orange'
        context.fillRect(0, 0, 320, 180)
      }, 100)
      return stream
    }
  })
  await page.goto(link.href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('heading', { name: title, exact: true }).waitFor()
  return page
}

async function api(page, person, path, input) {
  return page.request.post(new URL('/api/meetings/' + path, app).href, {
    headers: { Authorization: 'Bearer ' + person.token }, data: { meetingId: meeting, ...input },
  })
}

async function setMicrophone(page, enabled) {
  if ((await microphone(page).getAttribute('aria-pressed')) !== String(enabled)) await microphone(page).click()
  await stage(page).locator('button[data-lk-source="microphone"][aria-pressed="' + enabled + '"]').waitFor()
}

try {
  const [hostPage, guestPage] = await Promise.all([open(owner), open(guest)])
  await moderation(hostPage).waitFor()
  assert.equal(await moderation(guestPage).count(), 0)
  for (const action of ['mute', 'mute_all', 'remove', 'cohost', 'lock', 'chat', 'screen', 'end']) {
    assert.equal((await api(guestPage, guest, 'moderate', { action, target: owner.id, enabled: false })).status(), 403)
  }

  await Promise.all([hostPage, guestPage].map(page => button(page, 'Join audio and video').click()))
  await Promise.all([tile(hostPage, guest).waitFor(), tile(guestPage, owner).waitFor()])
  await setMicrophone(guestPage, true)
  await button(hostPage, 'Mute ' + guest.name).click()
  await stage(guestPage).locator('button[data-lk-source="microphone"][aria-pressed="false"]').waitFor()
  await setMicrophone(guestPage, true)
  await button(hostPage, 'Mute all microphones').click()
  await stage(guestPage).locator('button[data-lk-source="microphone"][aria-pressed="false"]').waitFor()

  await button(hostPage, 'Promote to co-host ' + guest.name).click()
  await moderation(guestPage).waitFor()
  assert.equal(await button(guestPage, 'Remove ' + owner.name).count(), 0)
  for (const action of ['mute', 'remove', 'cohost']) {
    assert.equal((await api(guestPage, guest, 'moderate', { action, target: owner.id, enabled: true })).status(), 403)
  }

  await button(guestPage, 'Lock meeting').click()
  await button(hostPage, 'Unlock meeting').waitFor()
  assert.equal((await visitor.client.rpc('st_v3_request_admission', { p_meeting: meeting })).error?.code, '42501')
  await button(guestPage, 'Unlock meeting').click()
  await button(hostPage, 'Lock meeting').waitFor()
  assert.equal(data(await visitor.client.rpc('st_v3_request_admission', { p_meeting: meeting })), 'waiting')
  await roster(hostPage).getByRole('button', { name: 'Admit', exact: true }).click()

  await button(guestPage, 'In-call chat').click()
  await button(hostPage, 'Disable meeting chat').click()
  await guestPage.getByText('Meeting chat is disabled.', { exact: true }).waitFor()
  assert.equal(await guestPage.getByLabel('Message to meeting').isEnabled(), false)
  assert.equal((await guest.client.rpc('st_v6_send_meeting_chat', {
    p_meeting: meeting, p_id: randomUUID(), p_body: 'Disabled',
  })).error?.code, '42501')
  await button(hostPage, 'Enable meeting chat').click()
  await guestPage.getByText('Meeting chat is disabled.', { exact: true }).waitFor({ state: 'detached' })

  await button(guestPage, 'Share screen').click()
  await button(guestPage, 'Stop sharing screen').waitFor()
  await hostPage.waitForFunction(() => [...document.querySelectorAll('.meeting-media video')].some(video => video.videoWidth > 0))
  await button(hostPage, 'Disable screen sharing').click()
  await guestPage.getByText('Screen sharing is disabled for this meeting.', { exact: true }).waitFor()
  await button(guestPage, 'Stop sharing screen').waitFor({ state: 'detached' })
  assert.equal((await api(guestPage, guest, 'screen-share', { action: 'claim', leaseId: randomUUID() })).status(), 403)
  await button(hostPage, 'Enable screen sharing').click()
  await guestPage.getByText('Screen sharing is disabled for this meeting.', { exact: true }).waitFor({ state: 'detached' })

  const visitorPage = await open(visitor)
  const checkIngress = process.env.SECTALK_TEST_LIVEKIT_SIGNAL === '1'
  const saved = checkIngress ? await (await api(visitorPage, visitor, 'token', {})).json() : null
  async function signaling(path, credential) {
    assert.ok(credential?.token)
    const url = new URL(path,credential.url.replace(/^ws/,'http'))
    assert.equal(url.origin,'http://127.0.0.1:3580')
    url.searchParams.set('access_token',credential.token)
    return (await fetch(url)).status
  }
  async function signalingRejected(path,credential) {
    const url=new URL(path,credential.url)
    url.searchParams.set('access_token',credential.token)
    return new Promise(resolve=>{
      const socket=new WebSocket(url)
      const timeout=setTimeout(()=>{ socket.close(); resolve(false) },5000)
      socket.addEventListener('error',()=>{ clearTimeout(timeout); resolve(true) },{once:true})
      socket.addEventListener('open',()=>{ clearTimeout(timeout); socket.close(); resolve(false) },{once:true})
    })
  }
  if (checkIngress) {
    assert.equal(await signaling('/rtc/validate',saved),200)
    assert.equal((await fetch('http://127.0.0.1:3580/twirp/livekit.RoomService/ListRooms')).status,404)
  }
  await button(visitorPage, 'Join audio and video').click()
  await tile(guestPage, visitor).waitFor()
  assert.equal((await api(guestPage, guest, 'moderate', { action: 'cohost', target: visitor.id, enabled: true })).status(), 403)
  guestPage.once('dialog', dialog => dialog.accept())
  const removing = guestPage.waitForResponse(response => response.url().endsWith('/api/meetings/moderate') &&
    response.request().postDataJSON()?.action === 'remove')
  await button(guestPage, 'Remove ' + visitor.name).click()
  assert.equal((await removing).status(), 200)
  await visitorPage.getByText('A moderator removed you from the meeting.', { exact: true }).waitFor()
  await stage(visitorPage).waitFor({ state: 'detached' })
  assert.equal((await api(visitorPage, visitor, 'token', {})).status(), 403)
  if (checkIngress) {
    for (const path of ['/rtc/validate','/rtc/v1/validate']) assert.equal(await signaling(path,saved),403)
    for (const path of ['/rtc','/rtc/v1']) assert.equal(await signalingRejected(path,saved),true)
  }
  assert.equal((await api(guestPage, guest, 'moderate', { action: 'remove', target: visitor.id })).status(), 200)

  await button(hostPage, 'Revoke co-host access from ' + guest.name).click()
  await moderation(guestPage).waitFor({ state: 'detached' })
  assert.equal((await api(guestPage, guest, 'moderate', { action: 'lock', enabled: true })).status(), 403)
  await button(hostPage, 'Promote to co-host ' + guest.name).click()
  await moderation(guestPage).waitFor()

  guestPage.once('dialog', dialog => dialog.accept())
  const beforeEnd = checkIngress ? await (await api(hostPage,owner,'token',{})).json() : null
  await button(guestPage, 'End meeting').click()
  await Promise.all([hostPage, guestPage].map(page => stage(page).waitFor({ state: 'detached' })))
  assert.equal(data(await owner.client.from('st_v3_meetings').select('status').eq('id', meeting).single()).status, 'ended')
  assert.equal((await api(hostPage, owner, 'token', {})).status(), 403)
  if (checkIngress) assert.equal(await signaling('/rtc/validate',beforeEnd),403)
  assert.equal((await api(guestPage, guest, 'moderate', { action: 'end' })).status(), 200)
} catch (error) {
  if (diagnostics.length) console.error(diagnostics.slice(-10))
  throw error
} finally {
  await browser.close()
}

console.log('Passed meeting moderator authorization, mute and mute-all, lock, chat and screen policy, removal, co-host revocation, and ending for everyone.')
