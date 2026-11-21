import assert from 'node:assert/strict'
import { test } from 'node:test'
import { parsePublicLegalRelease } from '../apps/web/lib/public-legal-release.ts'

const now = new Date('2025-02-01T00:00:00Z')
const document = () => ({
  status: 'approved', version: 'v1', approvedOn: '2024-12-31', effectiveOn: '2025-01-01',
  sections: [{ title: 'Synthetic section', text: '<em>Literal non-markup text</em>' }],
})
const fixture = () => ({
  operator: {name: 'Synthetic operator', supportEmail: 'help@example.invalid', privacyEmail: 'privacy@example.invalid'},
  terms: document(), privacy: document(),
})
const evaluate = input => parsePublicLegalRelease(JSON.stringify(input), now)

test('only complete locally approved and effective operator documents are ready', () => {
  const ready = evaluate(fixture())
  assert.equal(ready.operator.name, 'Synthetic operator')
  assert.equal(ready.operator.supportContact, 'mailto:help@example.invalid')
  assert.equal(ready.operator.privacyContact, 'mailto:privacy@example.invalid')
  assert.equal(ready.terms.effectiveOn, '2025-01-01')
  assert.equal(ready.privacy.sections[0].text, '<em>Literal non-markup text</em>')
  assert.equal(parsePublicLegalRelease(undefined, now), null)
  assert.equal(parsePublicLegalRelease('{', now), null)
  assert.equal(evaluate({ ...fixture(), privacy: undefined }), null)
  for (const fields of [
    { status: 'draft' }, { version: '' }, { sections: [] }, { effectiveOn: '2025-03-01' },
    { effectiveOn: '2025-02-30' }, { approvedOn: '2025-01-02' }, { sections: [{ title: 'Title', text: '' }] },
  ]) assert.equal(evaluate({ ...fixture(), terms: { ...document(), ...fields } }), null)
})

test('invalid contact values and oversized configuration stay unavailable', () => {
  for (const supportEmail of ['javascript:alert(1)', 'support@example.invalid?subject=test', 'support@example.invalid\r\nC: hidden']) {
    const input = fixture()
    input.operator.supportEmail = supportEmail
    assert.equal(evaluate(input), null)
  }
  assert.equal(evaluate({ ...fixture(), extra: 'x'.repeat(32001) }), null)
})

test('explicit HTTPS contact forms work separately or alongside the other email contact', () => {
  const input = fixture()
  delete input.operator.privacyEmail
  input.operator.privacyUrl = 'https://privacy.example.invalid/requests'
  assert.deepEqual(evaluate(input).operator, {
    name: 'Synthetic operator', supportContact: 'mailto:help@example.invalid',
    privacyContact: 'https://privacy.example.invalid/requests',
  })
  delete input.operator.supportEmail
  input.operator.supportUrl = 'https://support.example.invalid'
  assert.equal(evaluate(input).operator.supportContact, 'https://support.example.invalid/')
  input.privacy.status = 'draft'
  assert.equal(evaluate(input), null)
})

test('ambiguous or unsafe contact links keep legal publication unavailable', () => {
  const input = fixture()
  input.operator.privacyUrl = 'https://privacy.example.invalid/requests'
  assert.equal(evaluate(input), null)
  delete input.operator.privacyEmail
  for (const url of ['/privacy', '//example.invalid', 'http://example.invalid', 'https:///example.invalid',
    'https://example.invalid/path?source=form', 'https://example.invalid/path#account', 'https://joe@example.invalid',
    'https://example.invalid\\path', 'https://127.0.0.1/request', 'https://localhost/path', 'https://example.invalid/path\n']) {
    input.operator.privacyUrl = url
    assert.equal(evaluate(input), null, url)
  }
  const origin = 'https://sectalk.example.invalid'
  for (const path of ['/security/report', '/security/report/', '/security/%72eport']) {
    input.operator.privacyUrl = origin + path
    assert.equal(parsePublicLegalRelease(JSON.stringify(input), now, origin), null)
  }
  input.operator.privacyUrl = origin + '/support/privacy'
  assert.equal(parsePublicLegalRelease(JSON.stringify(input), now, origin).operator.privacyContact, input.operator.privacyUrl)
})
