import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { once } from 'node:events'
import test from 'node:test'
import {
  notificationMailConfiguration, notificationProviderFailure, sendNotificationEmail,
} from '../apps/web/lib/notification-email-server.ts'

test('controlled loopback SMTP distinguishes retryable and terminal provider responses', async () => {
  const replies = [450, 550]
  const server = createServer(socket => {
    socket.setEncoding('utf8')
    socket.write('220 loopback ESMTP\r\n')
    let pending = ''
    socket.on('data', chunk => {
      pending += chunk
      const lines = pending.split('\r\n')
      pending = lines.pop()
      for (const line of lines) {
        if (/^(EHLO|HELO|MAIL FROM:|RSET)/i.test(line)) socket.write('250 loopback\r\n')
        else if (/^RCPT TO:<recipient@example\.invalid>$/i.test(line)) {
          socket.write(String(replies.shift()) + ' controlled recipient failure\r\n')
        } else if (/^QUIT$/i.test(line)) socket.end('221 closing\r\n')
        else socket.write('550 unexpected SMTP command\r\n')
      }
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const overrides = {
    SECTALK_APP_URL: 'http://127.0.0.1:3484',
    SECTALK_NOTIFICATION_SMTP_HOST: '127.0.0.1',
    SECTALK_NOTIFICATION_SMTP_PORT: String(server.address().port),
    SECTALK_NOTIFICATION_SMTP_FROM: 'testing@example.invalid',
    SECTALK_NOTIFICATION_DRAIN_SECRET: 'a-local-test-value-with-at-least-32-characters',
  }
  const unset = ['VERCEL', 'SECTALK_NOTIFICATION_SMTP_USER', 'SECTALK_NOTIFICATION_SMTP_PASSWORD']
  const previous = Object.fromEntries([...Object.keys(overrides), ...unset].map(key => [key, process.env[key]]))
  Object.assign(process.env, overrides)
  for (const key of unset) delete process.env[key]
  try {
    const config = notificationMailConfiguration()
    assert.ok(config)
    const job = {
      recipient: 'fixture', lease: 'fixture', email: 'recipient@example.invalid', cadence: 'daily',
      delivery_id: 'f0000000-0000-4000-8000-000000000001', unsubscribe_key: 'fixture', mentions: 1, tasks: 0, calls: 0,
    }
    await assert.rejects(() => sendNotificationEmail(config, job), error => {
      assert.equal(error.responseCode, 450)
      assert.equal(notificationProviderFailure(error), 'retry')
      return true
    })
    await assert.rejects(() => sendNotificationEmail(config, job), error => {
      assert.equal(error.responseCode, 550)
      assert.equal(notificationProviderFailure(error), 'rejected')
      return true
    })
    assert.deepEqual(replies, [])
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
    await new Promise(resolve => server.close(resolve))
  }
})
