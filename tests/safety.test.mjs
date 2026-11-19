import assert from 'node:assert/strict'
import test from 'node:test'
import { riskIndicators } from '../apps/web/lib/safety.mjs'

test('ordinary conversations get no warning', () => {
  assert.deepEqual(riskIndicators('See you at 5. https://example.com/about'), [])
})

test('prompts for credentials and unusual payment methods are flagged', () => {
  assert.equal(riskIndicators('Send me your verification code and buy gift cards.').length, 2)
})

test('suspicious links get one warning without being visited', () => {
  assert.equal(riskIndicators('http://example.com https://bit.ly/test https://192.0.2.1').length, 1)
  assert.equal(riskIndicators('https://example.org@other.example/path').length, 1)
  assert.deepEqual(riskIndicators('https://%'), [])
})
