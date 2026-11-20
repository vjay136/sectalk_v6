import assert from 'node:assert/strict'
import { inspectAttachment } from '../apps/web/lib/attachment-inspection.ts'

const inspect = (name, sample) => inspectAttachment(name, Buffer.from(sample))
assert.equal(inspect('guide.txt', 'A reference to https://docs.example.invalid/help.'), null)
assert.equal(inspect('notes.txt', 'Discussion of vbaProject.bin as a packaging convention'), 'document_macro_marker')
assert.equal(inspect('notes.txt', 'Documentation discussing the <script> element'), 'script_marker')
assert.equal(inspect('notes.txt', 'https://docs.example.invalid@other.example.invalid/help'), 'suspicious_link_format')
assert.equal(inspect('notes.txt', 'https://xn--bcher-kva.example.invalid/help'), 'suspicious_link_format')
assert.equal(inspect('notes.txt', 'https://docs.example.invalid/path?q=mailto:name@example.invalid'), null)
assert.equal(inspect('sample.pdf', '%PDF-1.4\n/Type /Page\n%%EOF'), null)
assert.equal(inspect('sample.pdf', '%PDF-1.4\n/Java#53cript\n%%EOF'), 'script_marker')
assert.equal(inspect('sample.pdf', '%PDF-1.4\n/EmbeddedFile\n%%EOF'), 'embedded_document_marker')
assert.equal(inspect('sample.pdf', '%PDF-1.4\n/URI\n%%EOF'), 'embedded_link_marker')
assert.equal(inspect('sample.pdf', '%PDF-1.4\n/URIs\n%%EOF'), null)
assert.equal(inspect('sample.png', 'contains /URI and vbaProject.bin markers'), null)
assert.equal(inspect('large.txt', ' '.repeat(4 * 1024 * 1024) + '<script>'), null)
console.log('Bounded local attachment inspection tests passed.')
