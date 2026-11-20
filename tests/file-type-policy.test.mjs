import assert from 'node:assert/strict'
import { test } from 'node:test'
import { allowedFileType, sniffFileType } from '../apps/web/lib/file-type-policy.ts'

test('file type policy cross-checks extension, declared MIME, and stored bytes',()=>{
  const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a9MsAAAAASUVORK5CYII=','base64')
  assert.equal(sniffFileType(png),'image/png')
  assert.equal(allowedFileType('picture.PNG','image/png',png),true)
  assert.equal(allowedFileType('picture.PNG','',png),true)
  assert.equal(allowedFileType('picture.jpg','image/jpeg',png),false)
  assert.equal(allowedFileType('picture.PNG','image/jpeg',png),false)
  assert.equal(allowedFileType('picture.PNG','image/png',png.subarray(0,16)),false)
  assert.equal(allowedFileType('picture.svg','image/svg+xml',Buffer.from('<svg/>')),false)
  assert.equal(allowedFileType('notes.txt','text/plain',Buffer.from('Meeting notes\n')),true)
  assert.equal(allowedFileType('notes.txt','text/plain',Buffer.from([0,255,10])),false)
  assert.equal(allowedFileType('summary.pdf','application/pdf',Buffer.from('%PDF-1.7\n%%EOF')),true)
})
