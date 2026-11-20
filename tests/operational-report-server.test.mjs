import assert from 'node:assert/strict'
import test from 'node:test'
import { reportCsv } from '../apps/web/lib/operational-report-server.ts'
import { notificationMailConfiguration, notificationSMTPConfiguration } from '../apps/web/lib/notification-email-server.ts'

test('report CSV accepts aggregate fields and rejects spreadsheet formulas', () => {
  const row = {operation: 'file_upload', requests: 15, client_errors: 1, server_errors: 0,
    throttled: 0, unavailable: 0, peak_in_flight: 2, p50_band: 3, p95_band: 5}
  const report = {cadence: 'daily', rows: [row], period_end: '2026-11-20T12:00:00Z'}
  assert.match(reportCsv(report), /^Operation,Requests,Client errors.*\r\nfile_upload,15,1,0,0,0,2,3,5\r\n$/)
  assert.throws(() => reportCsv({...report, rows: [{...row, operation: '=malicious()'}]}), /Invalid operation label/)
  assert.throws(() => reportCsv({...report, rows: [{...row, requests: -1}]}), /Invalid aggregate value/)
})

test('operational reports can reuse SMTP without the notification drain secret', () => {
  const values = {
    VERCEL: undefined, SECTALK_NOTIFICATION_DRAIN_SECRET: undefined,
    SECTALK_NOTIFICATION_SMTP_USER: undefined, SECTALK_NOTIFICATION_SMTP_PASSWORD: undefined,
    SECTALK_APP_URL: 'http://127.0.0.1:3484', SECTALK_NOTIFICATION_SMTP_HOST: '127.0.0.1',
    SECTALK_NOTIFICATION_SMTP_PORT: '55426', SECTALK_NOTIFICATION_SMTP_FROM: 'ops@example.invalid',
  }
  const old = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]))
  try {
    for (const [key, value] of Object.entries(values)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
    assert.ok(notificationSMTPConfiguration()?.transport)
    assert.equal(notificationMailConfiguration(), null)
  } finally {
    for (const [key, value] of Object.entries(old)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
})
