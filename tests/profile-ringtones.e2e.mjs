import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const database = new URL(process.env.SECTALK_STORAGE_TEST_URL)
for (const url of [app, database]) assert.equal(url.hostname, '127.0.0.1')
const auth = { persistSession: false, autoRefreshToken: false }
const admin = createClient(database.href, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, { auth })
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER,
  args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] })
const created = []
const password = randomUUID() + '!Rt9'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(role) {
  const handle = 'ring_' + role + '_' + randomUUID().slice(0, 8)
  const email = handle + '@example.invalid'
  const name = 'Ringtone QA ' + role
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  created.push(user.id)
  const client = createClient(database.href, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, { auth })
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { handle, email, name, client }
}

function wave(seconds) {
  const rate = 8000
  const bytes = Buffer.alloc(44 + seconds * rate * 2)
  bytes.write('RIFF'); bytes.writeUInt32LE(bytes.length - 8, 4); bytes.write('WAVEfmt ', 8)
  bytes.writeUInt32LE(16, 16); bytes.writeUInt16LE(1, 20); bytes.writeUInt16LE(1, 22)
  bytes.writeUInt32LE(rate, 24); bytes.writeUInt32LE(rate * 2, 28); bytes.writeUInt16LE(2, 32)
  bytes.writeUInt16LE(16, 34); bytes.write('data', 36); bytes.writeUInt32LE(bytes.length - 44, 40)
  for (let i = 0; i < seconds * rate; i++) bytes.writeInt16LE(Math.round(5000 * Math.sin(i / rate * 2 * Math.PI * 440)), 44 + i * 2)
  return bytes
}

const navigation = page => page.getByRole('navigation', { name: 'SecTalk features' })
async function open(person, mobile) {
  const context = await browser.newContext({ permissions: ['microphone'], viewport: mobile ? { width: 390, height: 844 } : undefined })
  const page = await context.newPage()
  await page.addInitScript(() => {
    window.fixtureRingtones = []
    const start = AudioBufferSourceNode.prototype.start
    const stop = AudioBufferSourceNode.prototype.stop
    AudioBufferSourceNode.prototype.start = function (...args) {
      if (this.buffer) window.fixtureRingtones.push({ loop: this.loop, seconds: this.buffer.duration, source: this, stopped: false })
      return start.apply(this, args)
    }
    AudioBufferSourceNode.prototype.stop = function (...args) {
      const found = window.fixtureRingtones.find(entry => entry.source === this)
      if (found) found.stopped = true
      return stop.apply(this, args)
    }
  })
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address',{ exact: true }).fill(person.email)
  await page.getByLabel('Password',{ exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  const accept = page.getByRole('button', { name: 'Accept and continue', exact: true })
  await navigation(page).or(accept).first().waitFor()
  if (await accept.isVisible()) {
    await page.getByRole('checkbox', { name: 'I accept the SecTalk Community Rules.' }).check()
    await accept.click()
  }
  await navigation(page).waitFor()
  return page
}

async function ringtones(page) {
  await navigation(page).getByRole('button', { name: 'More', exact: true }).click()
  await navigation(page).getByRole('button', { name: 'Profile', exact: true }).click()
  await page.getByRole('button', { name: 'Ringtones', exact: true }).click()
  return page.getByRole('region', { name: 'Call ringtone' })
}

try {
  const [caller, receiver] = await Promise.all([account('caller'), account('receiver')])
  const chat = data(await caller.client.rpc('st_request', { p_handle: receiver.handle }))
  data(await receiver.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  const [from, to] = await Promise.all([open(caller, false), open(receiver, true)])
  const panel = await ringtones(to)
  const select = panel.getByLabel('Incoming call ringtone')
  assert.equal(await select.locator('option').count(), 4)
  await select.selectOption('pulse')
  await panel.getByText('Ringtone saved on this device.').waitFor()
  await panel.getByRole('button', { name: 'Preview ringtone' }).click()
  await to.waitForFunction(() => window.fixtureRingtones.some(entry => entry.seconds === 3 && !entry.loop))
  await panel.getByRole('button', { name: 'Stop preview' }).click()
  await panel.getByLabel('Use an audio file').setInputFiles({ name: 'over-limit.wav', mimeType: 'audio/wav', buffer: wave(21) })
  await panel.getByRole('alert').getByText('Choose an audio clip between 1 and 20 seconds.').waitFor()
  assert.equal(await select.inputValue(), 'pulse')
  await panel.getByLabel('Use an audio file').setInputFiles({ name: 'custom.wav', mimeType: 'audio/wav', buffer: wave(2) })
  await panel.getByText('Custom ringtone saved on this device.').waitFor()
  assert.equal(await select.inputValue(), 'local')
  await to.reload()
  const restored = await ringtones(to)
  await restored.getByText('custom.wav · 2 seconds').waitFor()
  await restored.getByRole('button', { name: 'Preview ringtone' }).click()
  await to.waitForFunction(() => window.fixtureRingtones.some(entry => entry.seconds === 2 && !entry.loop))
  await restored.getByRole('button', { name: 'Stop preview' }).click()
  await from.locator('.chat-item').filter({ hasText: receiver.name }).click()
  await from.getByRole('button', { name: 'Start audio call', exact: true }).click()
  const incoming = to.getByRole('region', { name: 'Audio call', exact: true })
  await incoming.getByText('Audio · Incoming call', { exact: true }).waitFor()
  await to.waitForFunction(() => window.fixtureRingtones.some(entry => entry.seconds === 2 && entry.loop && !entry.stopped))
  await incoming.getByRole('button', { name: 'Decline', exact: true }).click()
  await to.waitForFunction(() => window.fixtureRingtones.some(entry => entry.seconds === 2 && entry.loop && entry.stopped))
  await restored.getByRole('button', { name: 'Remove custom clip', exact: true }).click()
  await restored.getByText('Ringtone saved on this device.').waitFor()
  assert.equal(await restored.getByLabel('Incoming call ringtone').inputValue(), 'classic')
  console.log('Verified preset selection, preview, duration rejection, custom storage after reload, incoming Web Audio playback, stopping on decline, and removing the local clip.')
} finally {
  await browser.close()
  for (const id of created) await admin.auth.admin.deleteUser(id)
}
