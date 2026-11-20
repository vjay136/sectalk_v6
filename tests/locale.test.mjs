import assert from 'node:assert/strict'
import { test } from 'node:test'
import { formatMessage, locales, resolveLocale } from '../apps/web/lib/locale.ts'

test('accepts supported locale cookies and defaults to English for unknown values', () => {
  assert.equal(locales[resolveLocale('ar')].direction, 'rtl')
  assert.equal(locales[resolveLocale('en')].direction, 'ltr')
  for (const unsupported of [undefined, '', 'ar-SA', 'en-US', 'constructor', '__proto__']) {
    assert.equal(resolveLocale(unsupported), 'en')
  }
})

test('formats English and all Arabic ICU plural categories', () => {
  const shortcutCount = (locale, count) => formatMessage(locale, 'keyboardShortcutCount', { count })
  assert.deepEqual([0, 1, 2].map(count => shortcutCount('en', count)), [
    'No shortcuts', '1 shortcut', '2 shortcuts',
  ])
  assert.deepEqual([0, 1, 2, 6, 11, 100].map(count => shortcutCount('ar', count)), [
    'لا توجد اختصارات', 'اختصار واحد', 'اختصاران', '٦ اختصارات', '١١ اختصارًا', '١٠٠ اختصار',
  ])
})
