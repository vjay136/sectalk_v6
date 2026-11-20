// Run against the isolated loopback app, Supabase, and LiveKit with Chromium fake media.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { ConnectionQuality, SignalRequest, SignalResponse, VideoQuality } from '@livekit/protocol'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')
const { SECTALK_STORAGE_TEST_PUBLIC_KEY: key, SECTALK_STORAGE_TEST_SERVICE_KEY: serviceKey } = process.env
assert.ok(key && serviceKey)
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.href, serviceKey, options)
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.href, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, email, handle, name, client }
}

const [host, guest] = await Promise.all([account('CollabHost'), account('CollabGuest')])
const workspace = data(await host.client.rpc('st_v2_create_workspace', { p_name: 'In-call checks' }))
data(await host.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: guest.handle }))
const invite = data(await guest.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await guest.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const title = 'Collaboration ' + suffix
const meeting = data(await host.client.rpc('st_v6_start_instant_meeting', {
  p_id: randomUUID(), p_workspace: workspace, p_title: title, p_minutes: 15,
}))
const link = new URL(app.href)
link.searchParams.set('meeting', meeting)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({
  executablePath: process.env.SECTALK_TEST_BROWSER,
  args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
})

const diagnostics = []
let setHostQuality
const videoSettings = []
const subscriptions = []
async function open(person) {
  const page = await browser.newPage({ locale: 'en-US', permissions: ['microphone', 'camera'] })
  page.on('console', event => {
    if (event.type() === 'error') diagnostics.push(person.name + ' ' + event.text())
  })
  // The short cross-browser assertions below require push updates with the 5-second poll delayed.
  await page.addInitScript(() => {
    const every = window.setInterval.bind(window)
    window.setInterval = (handler, delay, ...args) => every(handler, delay === 5000 ? 30000 : delay, ...args)
  })
  if (person === host) {
    await page.addInitScript(() => {
      const replaceTrack = RTCRtpSender.prototype.replaceTrack
      window.pausedVideoSenders = new Set()
      RTCRtpSender.prototype.replaceTrack = async function (track) {
        const pausingVideo = track === null && this.track?.kind === 'video'
        await replaceTrack.call(this, track)
        if (pausingVideo) window.pausedVideoSenders.add(this)
        else if (track?.kind === 'video') window.pausedVideoSenders.delete(this)
      }
    })
    // Replace the host's own quality updates while forwarding real signaling and media traffic.
    await page.routeWebSocket(/^ws:\/\/127\.0\.0\.1:7880\/rtc(?:[/?]|$)/, client => {
      const server = client.connectToServer()
      let hostSid
      let forced = false
      client.onMessage(message => {
        if (typeof message !== 'string') {
          const request = SignalRequest.fromBinary(message).message
          if (request.case === 'trackSetting') videoSettings.push(request.value)
          if (request.case === 'subscription') subscriptions.push(request.value)
        }
        server.send(message)
      })
      server.onMessage(message => {
        if (typeof message === 'string') return client.send(message)
        const response = SignalResponse.fromBinary(message)
        if (response.message.case === 'join') hostSid = response.message.value.participant?.sid
        if (response.message.case === 'connectionQuality' && forced) {
          response.message.value.updates = response.message.value.updates.filter(update => update.participantSid !== hostSid)
          return client.send(Buffer.from(response.toBinary()))
        }
        client.send(message)
      })
      setHostQuality = quality => {
        assert.ok(hostSid)
        forced = true
        client.send(Buffer.from(new SignalResponse({ message: { case: 'connectionQuality', value: {
          updates: [{ participantSid: hostSid, quality }],
        } } }).toBinary()))
      }
    })
  }
  await page.goto(link.href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('heading', { name: title, exact: true }).waitFor()
  return page
}

const collaboration = page => page.getByRole('region', { name: 'In-call collaboration' })
const roster = page => collaboration(page).getByRole('region', { name: 'Participants', exact: true })
const attendee = (page, name) => roster(page).getByRole('listitem').filter({ hasText: name })
const chat = page => collaboration(page).getByRole('log', { name: 'Meeting messages' })
const stage = page => page.locator('.meeting-media')
const tile = (page, name) => stage(page).locator('.lk-participant-tile').filter({
  has: page.locator('[data-lk-participant-name="' + name + '"]'),
}).first()
const focused = (page, person) => stage(page).locator('[data-focused-participant="' + person.id + '"]')
const button = (page, name) => page.getByRole('button', { name, exact: true })
const realtimeTimeout = 6500
const networkStatus = page => stage(page).getByRole('status').filter({ hasText: 'Network:' })

try {
  const [hostPage, guestPage] = await Promise.all([open(host), open(guest)])
  await button(guestPage, 'Request admission').click()
  await guestPage.getByText('Waiting for the host to admit you', { exact: true }).waitFor()
  assert.equal(await collaboration(guestPage).count(), 0)
  assert.equal((await guest.client.rpc('st_v6_meeting_roster', { p_meeting: meeting })).error?.code, '42501')
  assert.equal((await guest.client.rpc('st_v6_send_meeting_chat', {
    p_meeting: meeting, p_id: randomUUID(), p_body: 'Before admission',
  })).error?.code, '42501')

  await button(hostPage, 'Admit').click()
  await attendee(guestPage, host.name).waitFor({ timeout: realtimeTimeout })
  await attendee(hostPage, guest.name).waitFor({ timeout: realtimeTimeout })
  assert.equal(await roster(guestPage).getByRole('button', { name: /Spotlight/ }).count(), 0)

  await Promise.all([hostPage, guestPage].map(page => button(page, 'In-call chat').click()))
  await collaboration(hostPage).getByLabel('Message to meeting').fill('A message from the host')
  await button(hostPage, 'Send message').click()
  await chat(guestPage).getByRole('listitem').filter({ hasText: /CollabHost.*A message from the host/ }).waitFor({ timeout: realtimeTimeout })
  await collaboration(guestPage).getByLabel('Message to meeting').fill('A response from the guest')
  await button(guestPage, 'Send message').click()
  await chat(hostPage).getByRole('listitem').filter({ hasText: /CollabGuest.*A response from the guest/ }).waitFor({ timeout: realtimeTimeout })

  await Promise.all([hostPage, guestPage].map(page => button(page, 'Join audio and video').click()))
  await Promise.all([tile(hostPage, guest.name).waitFor(), tile(guestPage, host.name).waitFor()])
  const microphone = button(hostPage, 'Microphone')
  const camera = button(hostPage, 'Camera')
  assert.equal(await microphone.getAttribute('aria-pressed'), 'false')
  assert.equal(await camera.getAttribute('aria-pressed'), 'false')
  await camera.click()
  await hostPage.waitForSelector('button[data-lk-source="camera"][aria-pressed="true"]')
  await guestPage.waitForFunction(name => {
    const participant = document.querySelector('[data-lk-participant-name="' + name + '"]')
    return (participant?.closest('.lk-participant-tile')?.querySelector('video')?.videoWidth ?? 0) > 0
  }, host.name)
  await microphone.click()
  await hostPage.waitForSelector('button[data-lk-source="microphone"][aria-pressed="true"]')
  await guestPage.waitForFunction(() => [...document.querySelectorAll('.meeting-media audio')].some(audio =>
    audio.srcObject?.getAudioTracks().length && audio.currentTime > 0))
  await tile(guestPage, host.name).locator('[data-lk-muted=true]').waitFor({ state: 'detached' })

  await button(guestPage, 'Camera').click()
  const guestVideo = tile(hostPage, guest.name).locator('video')
  await guestVideo.waitFor()
  await guestVideo.evaluate(video => video.play())
  const settingsStart = videoSettings.length
  setHostQuality(ConnectionQuality.POOR)
  await networkStatus(hostPage).getByText('Network: Poor · Reduced video quality').waitFor()
  await networkStatus(hostPage).getByText('Network: Poor · Audio-only').waitFor({ timeout: 7000 })
  await stage(hostPage).getByText('Video paused to keep audio clear').waitFor()
  await guestVideo.waitFor({ state: 'detached' })
  await hostPage.waitForFunction(() => window.pausedVideoSenders.size > 0)
  const lowVideo = videoSettings.slice(settingsStart).find(setting => setting.quality === VideoQuality.LOW && !setting.width && !setting.disabled)
  assert.ok(lowVideo, 'LiveKit should receive a low video quality request')
  const [guestVideoSid] = lowVideo.trackSids
  assert.ok(subscriptions.some(subscription => subscription.trackSids.includes(guestVideoSid) && !subscription.subscribe))
  const audio = stage(guestPage).locator('audio').first()
  const audioTime = await audio.evaluate(element => element.currentTime)
  await guestPage.waitForFunction(time => document.querySelector('.meeting-media audio')?.currentTime > time + 0.25, audioTime)
  assert.equal(await camera.getAttribute('aria-pressed'), 'true')
  assert.equal(await microphone.getAttribute('aria-pressed'), 'true')
  setHostQuality(ConnectionQuality.GOOD)
  await networkStatus(hostPage).getByText('Network: Good · Audio-only').waitFor()
  setHostQuality(ConnectionQuality.EXCELLENT)
  await networkStatus(hostPage).getByText('Network: Excellent', { exact: true }).waitFor({ timeout: 11000 })
  await hostPage.waitForFunction(() => window.pausedVideoSenders.size === 0)
  await guestVideo.waitFor()
  await guestVideo.evaluate(video => video.play())
  assert.ok(subscriptions.some(subscription => subscription.trackSids.includes(guestVideoSid) && subscription.subscribe))
  await button(guestPage, 'Camera').click()

  await microphone.click()
  await tile(guestPage, host.name).locator('[data-lk-muted=true]').waitFor()
  await camera.click()
  await hostPage.waitForSelector('button[data-lk-source="camera"][aria-pressed="false"]')
  await tile(guestPage, host.name).and(guestPage.locator('[data-lk-video-muted="true"]')).waitFor()

  await Promise.all([hostPage, guestPage].map(page => button(page, 'Participants').click()))
  await button(hostPage, 'Spotlight ' + guest.name).click()
  await attendee(guestPage, guest.name).getByText('Spotlight', { exact: true }).waitFor({ timeout: realtimeTimeout })
  await Promise.all([focused(hostPage, guest).waitFor(), focused(guestPage, guest).waitFor()])
  await button(guestPage, 'Pin ' + host.name).click()
  await focused(guestPage, host).waitFor()
  assert.equal(await focused(hostPage, guest).count(), 1)
  await button(guestPage, 'Unpin ' + host.name).click()
  await focused(guestPage, guest).waitFor()

  await guestPage.getByRole('button', { name: 'Leave', exact: true }).filter({ visible: true })
    .and(guestPage.locator('.release-panel > .release-row button')).click()
  await collaboration(guestPage).waitFor({ state: 'hidden' })
  await attendee(hostPage, guest.name).waitFor({ state: 'hidden', timeout: realtimeTimeout })
  await focused(hostPage, guest).waitFor({ state: 'hidden' })
  assert.deepEqual(data(await guest.client.from('st_v6_meeting_chat').select('id').eq('meeting_id', meeting)), [])
} catch (error) {
  if (diagnostics.length) console.error(diagnostics.slice(-10))
  throw error
} finally {
  await browser.close()
}

console.log('Passed two-browser roster, chat, camera and microphone, quality adaptation, audio-only recovery, pin, spotlight, and access cleanup.')
