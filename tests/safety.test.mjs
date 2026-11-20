import assert from 'node:assert/strict'
import test from 'node:test'
import { evaluateMessageRisk, messageRiskVersion, riskIndicators, threatSeverity, threatTaxonomy } from '../apps/web/lib/safety.mjs'

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

test('messages can show separate warnings for spam, harassment and intimate requests', () => {
  assert.match(riskIndicators('Claim your prize, click https://example.org')[0], /spam/i)
  assert.match(riskIndicators("I'm going to hurt you")[0], /harassment/i)
  assert.match(riskIndicators('Send me explicit photos')[0], /intimate/i)
  assert.deepEqual(riskIndicators('The campus club hosts a sexual health discussion today.'), [])
})

test('scores are versioned and include bounded, categorized evidence', () => {
  const report=evaluateMessageRisk('Send me your one-time code and buy gift cards.')
  assert.equal(report.modelVersion, messageRiskVersion)
  assert.equal(report.score, 72)
  assert.equal(report.confidence, 0.82)
  assert.equal(report.severity, 'medium')
  assert.deepEqual(report.reasons.map(indicator => indicator.category), ['credential_harvesting', 'payment_fraud'])
  assert.ok(report.reasons.every(indicator => threatTaxonomy[indicator.category] && indicator.reason))
  assert.deepEqual(evaluateMessageRisk('See you online.'), {
    score:0, confidence:0, severity:'info', modelVersion:messageRiskVersion, reasons:[],
  })
})

test('severity boundaries are explicit and weak signals do not become high-risk', () => {
  assert.deepEqual([0,29,30,59,60,79,80,89,90,100].map(threatSeverity),
    ['info','info','low','low','medium','medium','high','high','critical','critical'])
  const weak=evaluateMessageRisk('Claim your prize with gift cards at http://short.example')
  assert.equal(weak.score, 54)
  assert.ok(weak.confidence < 0.6)
  const strong=evaluateMessageRisk('I’m going to hurt you. Share your verification code at http://test.example')
  assert.equal(strong.score, 89)
  assert.equal(strong.severity, 'high')
})
