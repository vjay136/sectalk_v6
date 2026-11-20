import assert from 'node:assert/strict'
import { test } from 'node:test'
import { confirmationRedirect } from '../apps/web/lib/auth-confirmation-origin.mjs'

test('a hosted email link uses the configured HTTPS SecTalk origin', () => {
  const request = 'http://localhost:3000/api/auth/sign-up'
  assert.equal(confirmationRedirect('https://team.sectalk.example/', request, true), 'https://team.sectalk.example/auth/confirm')
  for (const invalid of [undefined, 'http://localhost:3000', 'https://127.0.0.1', 'https://dev.localhost',
    'https://name:secret@team.sectalk.example', 'https://team.sectalk.example/a', 'https://team.sectalk.example/?redirect=elsewhere']) {
    assert.equal(confirmationRedirect(invalid, request, true), null)
  }
})

test('a local fixture can use its own loopback origin', () => {
  const request = 'http://127.0.0.1:3535/api/auth/sign-up'
  assert.equal(confirmationRedirect(undefined, request, false), 'http://127.0.0.1:3535/auth/confirm')
  assert.equal(confirmationRedirect('http://127.0.0.1:3535', request, false), 'http://127.0.0.1:3535/auth/confirm')
  assert.equal(confirmationRedirect('http://127.0.0.1:3535', 'http://localhost:3535/api/auth/sign-up', false),
    'http://127.0.0.1:3535/auth/confirm')
  assert.equal(confirmationRedirect('http://127.0.0.1:3484', request, false), null)
  assert.equal(confirmationRedirect(undefined, 'https://untrusted.example/api/auth/sign-up', false), null)
})
