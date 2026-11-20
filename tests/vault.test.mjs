import assert from 'node:assert/strict'
import test from 'node:test'
import { lockFile, unlockFile } from '../apps/web/lib/vault.ts'

test('vault encrypts its filename and payload, and rejects a wrong passphrase or altered file', async () => {
  const password = 'a long sample passphrase'
  const payload = 'A private vault test document.'
  const file = new File([payload], 'private-note.txt')
  const encrypted = await lockFile(file, password)
  const bytes = new Uint8Array(await encrypted.arrayBuffer())
  const envelopeText = new TextDecoder().decode(bytes)
  assert.equal(envelopeText.includes(file.name), false)
  assert.equal(envelopeText.includes(payload), false)

  const restored = await unlockFile(encrypted, password)
  assert.equal(restored.name, file.name)
  assert.equal(await restored.file.text(), payload)
  await assert.rejects(unlockFile(encrypted, 'some other password'))

  bytes[bytes.length - 1] ^= 1
  await assert.rejects(unlockFile(new Blob([bytes]), password))
})
