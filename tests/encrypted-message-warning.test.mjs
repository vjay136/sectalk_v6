import assert from 'node:assert/strict'
import test from 'node:test'
import { encryptedMessageWarning } from '../apps/web/lib/encrypted-message-warning.ts'

test('warning heuristics flag credential solicitation across basic Unicode obfuscation', () => {
  assert.match(encryptedMessageWarning('Please se\u200bnd me the ｍｙ ｏｎｅ－ｔｉｍｅ code.'), /security code/)
  assert.match(encryptedMessageWarning('Enter your password in this form.'), /password/)
  assert.equal(encryptedMessageWarning('Keep your verification code private.'), null)
})

test('payment warning requires both pressure and a payment signal', () => {
  assert.match(encryptedMessageWarning('You must act now and pay in crypto.'), /send money/)
  assert.equal(encryptedMessageWarning('The birthday gift cards are ready.'), null)
  assert.equal(encryptedMessageWarning('Urgent team meeting this afternoon.'), null)
})
