import assert from 'node:assert/strict'
import test from 'node:test'
import { defangSafetyLinks, messageSafetyAction } from '../apps/web/lib/message-safety-action.mjs'

test('managed message thresholds distinguish hints, warnings, and local previews', () => {
  const hint = messageSafetyAction('A gift card is ready for your birthday.')
  assert.equal(hint.level, 'hint')
  assert.equal(hint.hold, false)
  assert.equal(hint.priority, false)
  const warning = messageSafetyAction('Please send your account password.')
  assert.equal(warning.level, 'warning')
  assert.equal(warning.priority, false)
  const blurred = messageSafetyAction('Please send your intimate pictures.')
  assert.equal(blurred.blur, true)
  assert.equal(blurred.hold, false)
  const held = messageSafetyAction('I will hurt you.')
  assert.equal(held.hold, true)
  assert.equal(held.priority, true)
})

test('defanging changes suspicious link text while preserving ordinary HTTPS', () => {
  assert.equal(defangSafetyLinks('http://example.invalid/hi and https://example.org/hello'),
    'hxxp[:]//example[.]invalid/hi and https://example.org/hello')
  assert.equal(defangSafetyLinks('https://bit.ly/demo'), 'hxxps[:]//bit[.]ly/demo')
})
