import assert from 'node:assert/strict'
import test from 'node:test'
import { parseRichText, safeRichLink } from '../apps/web/lib/rich-message.mjs'

test('rich messages use text tokens, with literal markup, images, invalid links and preserved emoji', () => {
  const value = 'Hi **bold** *em* `code` ![alt](https://web.example.org/icon.png) [script](javascript:alert) <img> [[st:😀|🎉]]'
  const parts = parseRichText(value)
  assert.deepEqual(parts.filter(part => part.kind !== 'text'), [
    { kind: 'strong', text: 'bold' }, { kind: 'em', text: 'em' }, { kind: 'code', text: 'code' },
  ])
  for (const literal of ['![alt](https://web.example.org/icon.png)', '[script](javascript:alert)', '<img>', '[[st:😀|🎉]]']) {
    assert.ok(parts.some(part => part.kind === 'text' && part.text.includes(literal)))
  }
})

test('only absolute HTTPS domain destinations become links and inspection drops query and fragment', () => {
  const [link, punctuation] = parseRichText('https://approved.example.org/docs?private=42#example.')
  assert.deepEqual(link.url, { href: 'https://approved.example.org/docs?private=42#example',
    host: 'approved.example.org', inspect: 'https://approved.example.org/docs' })
  assert.equal(punctuation.text, '.')
  for (const rejected of ['javascript:alert', 'data:text/html,test', 'http://example.org', 'https://who@example.org',
    '//example.org', 'https://127.0.0.1', 'https://[::1]', 'https://box.internal', 'https://example.org:81',
    'https://example.org\\test', 'https://example.org/\u202espoof']) assert.equal(safeRichLink(rejected), null, rejected)
})
