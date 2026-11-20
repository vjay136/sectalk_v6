// Run against the isolated loopback app, Supabase, and LiveKit with Chromium fake media.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { ConnectionQuality, SignalRequest, SignalResponse, VideoQuality } from '@livekit/protocol'
import { watchCallQos } from './helpers/call-qos.mjs'

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
const testRecovery = process.env.SECTALK_TEST_RECONNECT === '1'
const meeting = testRecovery ? data(await host.client.rpc('st_v3_schedule', {
  p_id: randomUUID(), p_workspace: workspace, p_title: title, p_agenda: '',
  p_start: new Date(Date.now() + 120_000).toISOString(), p_end: new Date(Date.now() + 900_000).toISOString(),
})) : data(await host.client.rpc('st_v6_start_instant_meeting', {
  p_id: randomUUID(), p_workspace: workspace, p_title: title, p_minutes: 15,
}))
if (testRecovery) data(await host.client.rpc('st_v3_meeting_state', { p_meeting: meeting, p_state: 'live' }))
const link = new URL(app.href)
link.searchParams.set('meeting', meeting)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const testBlur = process.env.SECTALK_TEST_BACKGROUND_BLUR === '1'
const testSharing = process.env.SECTALK_TEST_SCREEN_SHARE === '1'
const testQuality = process.env.SECTALK_TEST_QOS === '1'
const testAnalytics = process.env.SECTALK_TEST_ANL_02 === '1'
const samples = new WeakMap()
const browser = await chromium.launch({
  executablePath: process.env.SECTALK_TEST_BROWSER,
  args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream',
    ...(testBlur ? ['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] : [])],
})

const diagnostics = []
let setHostQuality
let hostSocket
let signalConnections = 0
let signalResumes = 0
const hostJoins = []
let resumedHostSid
const videoSettings = []
const subscriptions = []
async function open(person) {
  const page = await browser.newPage({ locale: 'en-US', permissions: ['microphone', 'camera'] })
  if (testQuality) samples.set(page, watchCallQos(page, 'meeting'))
  page.on('console', event => {
    if (event.type() === 'error') diagnostics.push(person.name + ' ' + event.text())
  })
  // The short cross-browser assertions below require push updates with the 5-second poll delayed.
  await page.addInitScript(() => {
    const every = window.setInterval.bind(window)
    window.setInterval = (handler, delay, ...args) => every(handler, delay === 5000 ? 30000 : delay, ...args)
  })
  if (testSharing) await page.addInitScript(() => {
    navigator.mediaDevices.getDisplayMedia = async options => {
      if (window.denyScreenCapture) throw new DOMException('Denied', 'NotAllowedError')
      const canvas = document.createElement('canvas')
      canvas.width = 320
      canvas.height = 180
      const context = canvas.getContext('2d')
      let frame = 0
      const timer = setInterval(() => {
        context.fillStyle = frame++ % 2 ? 'navy' : 'teal'
        context.fillRect(0, 0, 320, 180)
      }, 80)
      const stream = canvas.captureStream(12)
      const [video] = stream.getVideoTracks()
      window.stopScreenCapture = () => {
        clearInterval(timer)
        video.stop()
        video.dispatchEvent(new Event('ended'))
      }
      if (options.audio) {
        const audio = new AudioContext()
        const oscillator = audio.createOscillator()
        const destination = audio.createMediaStreamDestination()
        oscillator.connect(destination)
        oscillator.start()
        stream.addTrack(destination.stream.getAudioTracks()[0])
      }
      return stream
    }
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
      if (testRecovery) {
        signalConnections++
        hostSocket = client
      }
      let hostSid = resumedHostSid
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
        if (testRecovery && response.message.case === 'reconnect') signalResumes++
        if (response.message.case === 'join') {
          hostSid = response.message.value.participant?.sid
          resumedHostSid = hostSid
          if (testRecovery && hostSid) hostJoins.push(hostSid)
        }
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
  assert.equal(await guestPage.getByRole('region', { name: 'Meeting setup' }).count(), 0)
  const guestSession = data(await guest.client.auth.getSession()).session
  const deniedProbe = await guestPage.request.post(new URL('/api/meetings/token', app).href, {
    data: { meetingId: meeting, networkCheck: true },
    headers: { Authorization: 'Bearer ' + guestSession.access_token },
  })
  assert.equal(deniedProbe.status(), 403)
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

  const setup = guestPage.getByRole('region', { name: 'Meeting setup' })
  await setup.getByRole('combobox', { name: /^Microphone\b/ }).selectOption({ index: 1 })
  await setup.getByRole('combobox', { name: /^Camera\b/ }).selectOption({ index: 1 })
  await button(guestPage, 'Test microphone').click()
  await setup.getByRole('meter').waitFor()
  await button(guestPage, 'Stop microphone test').click()
  await setup.getByRole('meter').waitFor({ state: 'detached' })
  await button(guestPage, 'Test camera').click()
  await guestPage.waitForFunction(() => document.querySelector('video[aria-label="Camera preview"]')?.videoWidth > 0)
  const localCamera = await setup.getByLabel('Camera preview').evaluateHandle(video => video.srcObject.getVideoTracks()[0])
  const blurButton = button(guestPage, 'Blur camera background')
  assert.equal(await blurButton.getAttribute('aria-pressed'), 'false')
  if (testBlur) {
    await blurButton.click()
    await setup.getByRole('button', { name: 'Blur camera background', pressed: true }).waitFor()
    await guestPage.waitForFunction(raw => {
      const video = document.querySelector('video[aria-label="Camera preview"]')
      const output = video?.srcObject?.getVideoTracks()[0]
      return output && output !== raw && video.videoWidth > 0
    }, localCamera)
    await blurButton.click()
    await setup.getByRole('button', { name: 'Blur camera background', pressed: false }).waitFor()
  } else {
    await guestPage.evaluate(() => {
      const getContext = HTMLCanvasElement.prototype.getContext
      HTMLCanvasElement.prototype.getContext = function (type, ...args) {
        return type === 'webgl2' ? null : getContext.call(this, type, ...args)
      }
    })
    await blurButton.click()
    await setup.getByText('Background blur is unavailable in this browser.', { exact: true }).waitFor()
    assert.equal(await blurButton.getAttribute('aria-pressed'), 'false')
    assert.equal(await localCamera.evaluate(track => track.readyState), 'live')
  }
  await button(guestPage, 'Stop camera test').click()
  await setup.getByLabel('Camera preview').waitFor({ state: 'detached' })
  await guestPage.waitForFunction(track => track.readyState === 'ended', localCamera)
  await localCamera.dispose()
  const probeResponse = guestPage.waitForResponse(response =>
    response.url().endsWith('/api/meetings/token') && response.request().method() === 'POST')
  await button(guestPage, 'Check network').click()
  await setup.getByText('Connected to the meeting server.', { exact: true }).waitFor()
  const { token: probeToken } = await (await probeResponse).json()
  const { video: probeGrant } = JSON.parse(Buffer.from(probeToken.split('.')[1], 'base64url'))
  assert.ok(probeGrant.room.startsWith('sectalk-network-check-'))
  assert.equal(probeGrant.hidden, true)
  assert.equal(probeGrant.canPublish, false)
  assert.equal(probeGrant.canSubscribe, false)
  assert.equal(await stage(guestPage).count(), 0)
  assert.equal(await stage(hostPage).count(), 0)

  if (testBlur) {
    await button(guestPage, 'Test camera').click()
    await blurButton.click()
    await setup.getByRole('button', { name: 'Blur camera background', pressed: true }).waitFor()
  }
  await Promise.all([hostPage, guestPage].map(page => button(page, 'Join audio and video').click()))
  await Promise.all([tile(hostPage, guest.name).waitFor(), tile(guestPage, host.name).waitFor()])
  if (testQuality) for (const page of [hostPage, guestPage]) {
    assert.match(await samples.get(page)('setup'), /^(fast|moderate|slow)$/)
    if (testAnalytics) {
      assert.equal(await samples.get(page)('join', 'started', false), 'started')
      assert.equal(await samples.get(page)('join', 'connected'), 'connected')
    }
  }
  if (testBlur) {
    await guestPage.waitForSelector('button[data-lk-source="camera"][aria-pressed="true"]')
    await tile(hostPage, guest.name).locator('video').waitFor()
    await hostPage.waitForFunction(name => {
      const participant = document.querySelector('[data-lk-participant-name="' + name + '"]')
      return (participant?.closest('.lk-participant-tile')?.querySelector('video')?.videoWidth ?? 0) > 0
    }, guest.name)
    await button(guestPage, 'Camera').click()
    await guestPage.waitForSelector('button[data-lk-source="camera"][aria-pressed="false"]')
  }
  if (testSharing) {
    const shareEndpoint = new URL('/api/meetings/screen-share', app).href
    const tokenHeaders = { Authorization: 'Bearer ' + guestSession.access_token }
    const shareRequest = (action, leaseId) => guestPage.request.post(shareEndpoint, {
      headers: tokenHeaders, data: { meetingId: meeting, action, leaseId },
    })
    const hostSession = data(await host.client.auth.getSession()).session
    const hostShareRequest = (action, leaseId) => hostPage.request.post(shareEndpoint, {
      headers: { Authorization: 'Bearer ' + hostSession.access_token }, data: { meetingId: meeting, action, leaseId },
    })
    const hostAttempt = randomUUID()
    const guestAttempt = randomUUID()
    const [hostClaim, guestClaim] = await Promise.all([hostShareRequest('claim', hostAttempt), shareRequest('claim', guestAttempt)])
    assert.deepEqual([hostClaim.status(), guestClaim.status()].sort(), [200, 409])
    const cleared = hostClaim.ok() ? await hostShareRequest('release', hostAttempt) : await shareRequest('release', guestAttempt)
    assert.equal(cleared.status(), 200)

    await hostPage.evaluate(() => { window.denyScreenCapture = true })
    await button(hostPage, 'Share screen').click()
    await stage(hostPage).getByText('Screen sharing was cancelled or blocked.', { exact: true }).waitFor()
    await hostPage.evaluate(() => { window.denyScreenCapture = false })
    await stage(hostPage).getByLabel('Share audio when available').check()
    await button(hostPage, 'Share screen').click()
    await button(hostPage, 'Stop sharing screen').waitFor()
    await guestPage.waitForFunction(() => [...document.querySelectorAll('.meeting-media video')].some(video => video.videoWidth > 0))
    await guestPage.waitForFunction(() => [...document.querySelectorAll('.meeting-media audio')].some(audio => audio.srcObject?.getAudioTracks().length))
    await stage(guestPage).getByText('Someone is already presenting.', { exact: true }).waitFor()
    assert.equal(await button(guestPage, 'Share screen').isEnabled(), false)
    assert.equal((await shareRequest('claim', randomUUID())).status(), 409)
    await hostPage.evaluate(() => window.stopScreenCapture())
    await stage(hostPage).getByText('Screen sharing ended.', { exact: true }).waitFor()
    await hostPage.waitForFunction(() => [...document.querySelectorAll('.meeting-media button')].some(button =>
      button.textContent.includes('Share screen') && !button.disabled))

    const starting = guestPage.waitForRequest(request => request.url() === shareEndpoint && request.postDataJSON()?.action === 'claim')
    await button(guestPage, 'Share screen').click()
    const guestLease = (await starting).postDataJSON().leaseId
    await button(guestPage, 'Stop sharing screen').waitFor()
    assert.equal((await shareRequest('release', guestLease)).status(), 200)
    await stage(guestPage).getByText(/Screen sharing (permission was lost|ended)\./).waitFor()
    await stage(hostPage).getByText('Someone is already presenting.', { exact: true }).waitFor({ state: 'detached' })
  }
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
  if (testRecovery) {
    const signalCount = signalConnections
    const resumeCount = signalResumes
    const joinedSessions = hostJoins.length
    const playing = tile(guestPage, host.name).locator('video')
    const before = await playing.evaluate(video => video.currentTime)
    await hostSocket.close({ code: 1011, reason: 'loopback signaling recovery test' })
    const deadline = Date.now() + 20_000
    while ((signalConnections <= signalCount || signalResumes <= resumeCount) && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    assert.ok(signalConnections > signalCount)
    assert.ok(signalResumes > resumeCount, 'LiveKit should acknowledge resumed signaling')
    assert.equal(hostJoins.length, joinedSessions, 'A resumed signal session should keep the same LiveKit participant')
    await guestPage.waitForFunction(({ person, time }) => {
      const participant = document.querySelector('[data-lk-participant-name="' + person + '"]')
      return (participant?.closest('.lk-participant-tile')?.querySelector('video')?.currentTime ?? 0) > time + 0.1
    }, { person: host.name, time: before })
    assert.equal(await stage(guestPage).locator('[data-lk-participant-name="' + host.name + '"]').count(), 1)
    if (testQuality) assert.equal(await samples.get(hostPage)('recovery'), 'recovered')
  }
  await microphone.click()
  await hostPage.waitForSelector('button[data-lk-source="microphone"][aria-pressed="true"]')
  if (testQuality) for (const page of [hostPage, guestPage]) {
    assert.match(await samples.get(page)('relay'), /^(relayed|non_relayed)$/)
  }
  if (testQuality && testAnalytics) assert.match(await samples.get(guestPage)('mos'), /^(below_2|2_to_3|3_to_4|4_or_more)$/)
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

console.log('Passed pre-join device tests, network probe, ' + (testBlur ? 'live background blur' : 'background blur fallback') +
  (testSharing ? ', screen video and audio, one-presenter enforcement, and capture and permission loss' : '') +
  ', two-browser roster, chat, camera and microphone, quality adaptation, audio-only recovery, pin, spotlight, and access cleanup.')
if (testQuality) console.log('Passed LiveKit setup and selected ICE route sample privacy and delivery.')
if (testRecovery) console.log('Passed scheduled meeting signaling resume with the same participant and live video.')
