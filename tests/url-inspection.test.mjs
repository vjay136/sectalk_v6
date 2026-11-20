import assert from 'node:assert/strict'
import test from 'node:test'
import { generateKeyPairSync, sign } from 'node:crypto'
import { inspectionDomainSignals, normalizeInspectionUrl } from '../apps/web/lib/url-inspection-policy.mjs'
import { urlReputation, verifiedUrlReputation } from '../apps/web/lib/url-reputation-feed.mjs'
import { chooseInspectionAddress, inspectUserUrl } from '../apps/web/lib/url-inspection-worker.mjs'

test('normalizes syntax, strips URL secrets, and recognizes a confusable brand in an unrelated domain', () => {
  const sample = normalizeInspectionUrl(' https://p\u0430ypal.example.invalid/test?fixture=opaque#redacted ')
  assert.ok(sample?.stripped)
  assert.equal(sample.url.pathname, '/test')
  assert.deepEqual(inspectionDomainSignals(sample.url).possibleBrands, ['PayPal'])
  assert.equal(inspectionDomainSignals(sample.url).internationalized, true)
  assert.deepEqual(inspectionDomainSignals(new URL('https://www.paypal.com/')).possibleBrands, [])
  assert.equal(normalizeInspectionUrl('https://example.invalid:9443/'), null)
  assert.equal(normalizeInspectionUrl('https://fixture@example.invalid/'), null)
  assert.equal(normalizeInspectionUrl('file:///fixture'), null)
})

test('verified reputation and recent registration require the pinned signature and a current manifest', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const pem = publicKey.export({ format: 'pem', type: 'spki' })
  const now = Date.parse('2026-11-20T12:00:00Z')
  const payload = JSON.stringify({ source: 'Synthetic registry fixture',
    issued: '2026-11-20T00:00:00Z', expires: '2026-11-22T00:00:00Z',
    domains: [{ domain: 'example.invalid', reputation: 'risk-listed', registered: '2026-11-19' }] })
  const signature = sign(null, Buffer.from(payload), privateKey).toString('base64url')
  const verified = verifiedUrlReputation(JSON.stringify({ payload, signature }), pem, now)
  assert.deepEqual(urlReputation('sub.example.invalid', verified, now), {
    status: 'risk-listed', source: 'Synthetic registry fixture', domain: 'example.invalid', registered: '2026-11-19', recent: true,
  })
  assert.deepEqual(urlReputation('else.invalid', verified, now), { status: 'unlisted', source: 'Synthetic registry fixture' })
  assert.equal(verifiedUrlReputation(JSON.stringify({ payload: payload.replace('risk-listed', 'observed'), signature }), pem, now), null)
  assert.deepEqual(urlReputation('example.invalid', verified, Date.parse('2026-11-22')), { status: 'unavailable' })
})

test('follows approved HTTPS redirect metadata only, stripping queries and stopping at the policy boundary', async () => {
  const seen = []
  const approve = new Set(['approved.example.invalid'])
  const transport = {
    resolve: async () => 'fixture-address',
    head: async url => {
      seen.push(url.href)
      return url.pathname === '/one' ? { status: 302, location: '/two?private=omitted' } :
        { status: 302, location: 'https://unapproved.example.invalid/private' }
    },
  }
  const result = await inspectUserUrl('https://approved.example.invalid/one', approve, null, transport)
  assert.equal(result.outcome, 'blocked')
  assert.deepEqual(seen, ['https://approved.example.invalid/one', 'https://approved.example.invalid/two'])
  assert.equal(result.hops.length, 2)
  assert.deepEqual(result.domains[0].reputation, { status: 'unavailable' })
})

test('limits a redirect chain and stops before HEAD when resolution is unavailable', async () => {
  const approve = new Set(['approved.example.invalid'])
  const result = await inspectUserUrl('https://approved.example.invalid/0', approve, null, {
    resolve: async () => 'fixture-address',
    head: async url => ({ status: 302, location: '/' + (Number(url.pathname.slice(1)) + 1) }),
  })
  assert.equal(result.hops.length, 4)
  assert.equal(result.outcome, 'redirect-limit')
  const blocked = await inspectUserUrl('https://approved.example.invalid/', approve, null, {
    resolve: async () => null, head: async () => assert.fail('An unapproved destination was dialed'),
  })
  assert.equal(blocked.outcome, 'blocked')
  assert.deepEqual(blocked.hops, [])
})

test('a DNS answer set must be public before choosing any connection address', () => {
  assert.equal(chooseInspectionAddress([]), null)
  assert.equal(chooseInspectionAddress([{ address:'127.0.0.1', family:4 }]), null)
  assert.equal(chooseInspectionAddress([{ address:'8.8.8.8', family:4 },{ address:'::1', family:6 }]), null)
  assert.equal(chooseInspectionAddress([{ address:'2606:4700:4700::1111', family:6 },{ address:'8.8.8.8', family:4 }]), '8.8.8.8')
})
