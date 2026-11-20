import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

const origin = new URL(process.env.SECTALK_MALWARE_SCANNER_URL)
assert.equal(origin.hostname, '127.0.0.1')
const secret = process.env.SECTALK_MALWARE_SCANNER_SECRET
assert.ok(secret?.length >= 32)
const scan = (bytes, key = secret) => fetch(new URL('/scan', origin), {
  method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/octet-stream' }, body: bytes,
})
const safe = Buffer.from('A benign attachment file')
const marker = Buffer.from('SecTalk benign isolated scanner marker v6')
assert.equal((await scan(safe, 'incorrect-secret')).status, 404)
assert.equal((await scan(Buffer.alloc(4 * 1024 * 1024 + 1))).status, 413)
for (const [bytes, verdict] of [[safe, 'clean'], [marker, 'malware']]) {
  const response = await scan(bytes)
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { verdict, sha256: createHash('sha256').update(bytes).digest('hex') })
}
for (const response of await Promise.all([scan(safe), scan(safe), scan(safe)])) {
  assert.equal(response.status, 200)
}
console.log('ClamAV worker passed authentication, input bounds, exact SHA-256, and two benign synthetic fixture verdicts.')
