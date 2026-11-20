import assert from 'node:assert/strict'
import test from 'node:test'
import { classifyScamMessage, scamClassifierVersion } from '../apps/web/lib/message-scam.mjs'
import { evaluateMessageRisk, threatTaxonomy } from '../apps/web/lib/safety.mjs'

const fixtures = [
  ['phishing','Your account has been locked. Click https://login.example.invalid to restore access.'],
  ['credential_harvesting','Reply with your one-time code so I can confirm your account.'],
  ['romance_scam','My darling, I am stranded after a medical emergency. Please send me money.'],
  ['investment_scam','Join this investment with guaranteed returns. Make your deposit today.'],
  ['job_scam','You have a remote job offer. Please pay the onboarding deposit.'],
  ['delivery_scam','Your package had a failed delivery. Confirm your address at https://parcel.example.invalid.'],
  ['tech_support_scam','I work for technical support. Please grant me remote access immediately.'],
  ['prize_scam','You have won a prize. Pay the registration fee to accept it.'],
  ['impersonation',"I'm the CEO. Urgently wire the funds today and keep this confidential."],
]

test('classifies each supported scam or phishing pattern with bounded, fixed evidence', () => {
  for(const [category,message] of fixtures) {
    const matches=classifyScamMessage(message)
    assert.deepEqual(matches.map(match=>match.category),[category],message)
    const [match]=matches
    assert.ok(threatTaxonomy[category])
    assert.equal(match.modelVersion,scamClassifierVersion)
    assert.ok(match.confidence>=0.6 && match.confidence<1)
    assert.ok(match.reasons.every(reason=>typeof reason==='string' && !reason.includes('.invalid')))
  }
})

test('requires corroborating context for generic topics and links', () => {
  for(const message of [
    'Never share your verification code.',
    'Please read the instructions for changing your password.',
    'You have a job offer. Your contract arrives tomorrow.',
    'We missed the package delivery yesterday.',
    'Your package had a failed delivery. Confirm the address at https://%.',
    'Your shipment was delivered. See the receipt https://example.org.',
    'My darling, your flight home arrives at six.',
    'The investment seminar is open. Please register.',
    'The technical support number is in the employee handbook.',
    'My friend won a prize.',
    'I am your manager. Could you join the team meeting?',
    'See you at 5. https://example.org.',
  ]) assert.deepEqual(classifyScamMessage(message),[],message)
})

test('normalizes bounded text and retains independent findings without changing legacy scoring', () => {
  const message='Your account is locked. Open https://login.example.invalid and enter your verification code.'
  assert.deepEqual(classifyScamMessage(message).map(match=>match.category),['credential_harvesting','phishing'])
  assert.equal(classifyScamMessage('Ｓｈａｒｅ your verifi'+'\u200bcation code.')[0].category,'credential_harvesting')
  assert.deepEqual(classifyScamMessage('x'.repeat(16000)+message),[])
  assert.deepEqual(evaluateMessageRisk(fixtures[4][1]).reasons,[])
})
