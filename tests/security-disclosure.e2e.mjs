// Exercise the production HTTP routes on an isolated loopback server.
import assert from 'node:assert/strict'

const app = new URL(process.env.SECTALK_DISCLOSURE_TEST_APP)
assert.equal(app.hostname, '127.0.0.1')
const contact = process.env.SECTALK_DISCLOSURE_TEST_CONTACT
const origin = process.env.SECTALK_DISCLOSURE_TEST_ORIGIN
const disclosureResponse = await fetch(new URL('/.well-known/security.txt', app), { redirect: 'error' })
const pageResponse = await fetch(new URL('/security', app), { redirect: 'error' })
assert.equal(pageResponse.status, 200)
assert.match(disclosureResponse.headers.get('content-type'), /^text\/plain; charset=utf-8$/i)
assert.equal(disclosureResponse.headers.get('cache-control'), 'no-store')
const body = await disclosureResponse.text()
const page = await pageResponse.text()
assert.match(page, /<h1[^>]*>Report a security vulnerability<\/h1>/)

if (contact) {
  assert.equal(disclosureResponse.status, 200)
  assert.ok(body.endsWith('\n'))
  const fields = Object.fromEntries(body.trimEnd().split('\n').map(line => {
    const separator = line.indexOf(': ')
    assert.ok(separator > 0)
    return [line.slice(0, separator), line.slice(separator + 2)]
  }))
  assert.equal(fields.Contact, contact)
  assert.ok(Date.parse(fields.Expires) > Date.now())
  assert.equal(fields.Canonical, new URL('/.well-known/security.txt', origin).href)
  assert.equal(fields.Policy, new URL('/security', origin).href)
  assert.equal(fields['Preferred-Languages'], 'en')
  assert.ok(page.includes('href="' + contact + '"'))
} else {
  assert.equal(disclosureResponse.status, 503)
  assert.ok(!body.includes('Contact:'))
  assert.ok(page.includes('The private reporting channel is unavailable'))
  assert.ok(!page.includes('Submit a private report'))
}

console.log('Passed security.txt and disclosure page HTTP checks.')
