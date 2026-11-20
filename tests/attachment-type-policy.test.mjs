import assert from 'node:assert/strict'
import { zipSync, strToU8 } from 'fflate'
import { allowedFileType } from '../apps/web/lib/file-type-policy.ts'
import { officePackage, pdfWithCompressedLink } from './attachment-document-fixtures.mjs'

const text = Buffer.from('A harmless plain-text note.')
const pdf = pdfWithCompressedLink()
const zip = Buffer.from(zipSync({ 'note.txt': strToU8('A harmless archived note.') }))
const docx = officePackage()
const generic = 'application/octet-stream'

assert.equal(allowedFileType('note.txt', 'text/plain; charset=utf-8', text), true)
assert.equal(allowedFileType('note.txt', 'image/png', text), false)
assert.equal(allowedFileType('note.png', 'image/png', text), false)
assert.equal(allowedFileType('note.pdf', generic, text), false)
assert.equal(allowedFileType('note.pdf', 'application/pdf', pdf), true)
assert.equal(allowedFileType('note.txt', generic, pdf), false)
assert.equal(allowedFileType('note.docx', generic, text), false)
assert.equal(allowedFileType('note.docx', 'text/plain', docx), false)
assert.equal(allowedFileType('note.docx', generic, docx), true)
assert.equal(allowedFileType('note.zip', 'application/zip', zip), false)
assert.equal(allowedFileType('note.7z', generic, zip), false)
assert.equal(allowedFileType('note.rar', generic, zip), false)
assert.equal(allowedFileType('note.pdf', 'application/pdf', zip), false)
assert.equal(allowedFileType('note.txt', generic, zip), false)
console.log('Attachment MIME and byte mismatch checks and unsupported archive policy passed.')
