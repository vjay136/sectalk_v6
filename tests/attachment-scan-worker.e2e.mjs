import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { officePackage, pdfWithCompressedLink } from './attachment-document-fixtures.mjs'

const origin = new URL(process.env.SECTALK_MALWARE_SCANNER_URL)
assert.equal(origin.hostname, '127.0.0.1')
const secret = process.env.SECTALK_MALWARE_SCANNER_SECRET
assert.ok(secret?.length >= 32)
const scan = (bytes, key = secret, format) => fetch(new URL('/scan', origin), {
  method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/octet-stream',
    ...(format ? { 'X-SecTalk-Document-Format': format } : {}) }, body: bytes,
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
if (process.argv.includes('--documents')) {
  const compressedPdf = pdfWithCompressedLink()
  assert.equal(compressedPdf.includes('/URI'), false)
  for (const [format, bytes, inspection] of [
    ['docx', officePackage(), { status: 'inspected', reason: null }],
    ['docm', officePackage({ macro: true }), { status: 'inspected', reason: 'document_macro_marker' }],
    ['xlsx', officePackage({ family: 'excel' }), { status: 'inspected', reason: null }],
    ['xlsm', officePackage({ family: 'excel', macro: true }), { status: 'inspected', reason: 'document_macro_marker' }],
    ['pptx', officePackage({ family: 'powerpoint' }), { status: 'inspected', reason: null }],
    ['pptm', officePackage({ family: 'powerpoint', macro: true }), { status: 'inspected', reason: 'document_macro_marker' }],
    ['docx', officePackage({ external: true }), { status: 'inspected', reason: 'embedded_link_marker' }],
    ['docx', officePackage({ extra: { 'word/embeddings/container.bin': 'Benign placeholder' } }), { status: 'inspected', reason: 'embedded_document_marker' }],
    ['docx', officePackage({ extra: { '../unexpected.xml': '<unused/>' } }), { status: 'unsupported' }],
    ['docx', officePackage({ extra: {
      'word/document.xml': '<document xmlns="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><!--' +
        'a'.repeat(260 * 1024) + '--></document>',
    } }), { status: 'unsupported' }],
    ['docx', officePackage({ badMain: true }), { status: 'unsupported' }],
    ['xlsx', officePackage(), { status: 'unsupported' }],
    ['pdf', compressedPdf, { status: 'inspected', reason: 'embedded_link_marker' }],
    ['pdf', pdfWithCompressedLink({ scriptMarker: true }), { status: 'inspected', reason: 'script_marker' }],
  ]) {
    const response = await scan(bytes, secret, format)
    assert.equal(response.status, 200, format)
    assert.deepEqual(await response.json(), {
      verdict: 'clean', sha256: createHash('sha256').update(bytes).digest('hex'),
      inspection: { format, ...inspection },
    })
  }
  const largeParts = Object.fromEntries(Array.from({ length: 5 }, (_, index) =>
    ['word/custom/' + index + '.txt', 'a'.repeat(3 * 1024 * 1024)]))
  const oversizedArchive = await scan(officePackage({ extra: largeParts }), secret, 'docx')
  if (oversizedArchive.status === 200) {
    assert.deepEqual((await oversizedArchive.json()).inspection, { format: 'docx', status: 'unsupported' })
  } else {
    assert.equal(oversizedArchive.status, 503)
  }
  console.log('Structured worker checks passed with benign Office packages and a compressed PDF link object.')
}
