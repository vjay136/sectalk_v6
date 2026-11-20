import assert from 'node:assert/strict'
import { test } from 'node:test'
import { parseSecurityDisclosure } from '../apps/web/lib/security-disclosure.ts'

const now = Date.parse('2026-11-20T00:00:00Z')
const config = {
  origin: 'https://deployment.example.com',
  contact: 'https://github.com/vjay136/sectalk_ver2/security/advisories/new',
  expires: '2027-03-01T00:00:00Z',
}

test('disclosure links use the configured deployment and private destination', () => {
  assert.deepEqual(parseSecurityDisclosure(config, now), {
    contact: config.contact,
    expires: config.expires,
    canonical: 'https://deployment.example.com/.well-known/security.txt',
    policy: 'https://deployment.example.com/security',
  })
  const contact = 'mailto:security+reports@example.com'
  assert.equal(parseSecurityDisclosure({ ...config, contact }, now)?.contact, contact)
})

test('missing, unsafe, or stale contact configuration fails closed', () => {
  for (const [key, values] of Object.entries({
    origin: [undefined, 'http://deployment.example.com', 'https://deployment.example.com/path', 'https://user@deployment.example.com'],
    contact: [undefined, 'javascript:alert(1)', 'http://github.com/', 'https://owner:secret@github.com/', 'https://github.com/?token=secret', 'mailto:security@example.com\n', 'https://github.com/\nPolicy: https://other.example.com'],
    expires: [undefined, 'not a date', '2026-11-20T00:00:00Z', '2027-11-20T00:00:00Z', '2027-02-30T00:00:00Z'],
  })) {
    for (const value of values) assert.equal(parseSecurityDisclosure({ ...config, [key]: value }, now), null)
  }
})
