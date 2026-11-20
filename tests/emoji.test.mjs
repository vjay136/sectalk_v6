import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { customEmoji, nativeEmoji } from '../apps/web/lib/emoji-catalog.ts'

test('picker includes native emoji and at least ten thousand distinct SecTalk combinations', () => {
  assert.ok(nativeEmoji.some(entry => entry.value === '😀'))
  assert.ok(nativeEmoji.length >= 1800)
  assert.ok(customEmoji.length >= 10000)
  assert.equal(new Set(customEmoji.map(entry => entry.value)).size, customEmoji.length)
  assert.ok(customEmoji.every(entry => /^\[\[st:.+\|.+\]\]$/u.test(entry.value)))
})

test('occupation catalog contains distinct, searchable codes and titles', async () => {
  const input = JSON.parse(await readFile(new URL('../apps/web/lib/occupations.json', import.meta.url),'utf8'))
  assert.equal(input.length,1016)
  assert.equal(new Set(input.map(entry=>entry.id)).size,input.length)
  assert.ok(input.every(entry=>/^work-\d{2}-\d{4}\.\d{2}$/.test(entry.id)&&entry.name.trim()))
})
