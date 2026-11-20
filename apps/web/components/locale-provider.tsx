'use client'

import { createContext, useContext, useState, type ReactNode } from 'react'
import { formatMessage, locales, resolveLocale, type Locale, type Message } from '../lib/locale'

const LocaleContext = createContext<{
  locale: Locale
  changeLocale: (next: Locale) => void
  t: (...message: Message) => string
} | null>(null)

export function LocaleProvider({ initialLocale, children }: { initialLocale: Locale; children: ReactNode }) {
  const [locale, setLocale] = useState(initialLocale)

  function changeLocale(next: Locale) {
    const root = document.documentElement
    root.lang = next
    root.dir = locales[next].direction
    setLocale(next)
  }

  return <LocaleContext.Provider value={{ locale, changeLocale, t: (...message) => formatMessage(locale, ...message) }}>
    {children}
  </LocaleContext.Provider>
}

export function useLocale() {
  const context = useContext(LocaleContext)
  if (!context) throw new Error('useLocale must be used within LocaleProvider')
  return context
}

export function LanguageSelect() {
  const { locale, changeLocale, t } = useLocale()
  const [saving, setSaving] = useState(false)
  const [failed, setFailed] = useState(false)

  async function saveLanguage(next: Locale) {
    setSaving(true)
    setFailed(false)
    try {
      const response = await fetch('/api/preferences/language', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ locale: next }),
      })
      if (!response.ok) throw new Error('The language preference was not saved.')
      changeLocale(next)
    } catch {
      setFailed(true)
    } finally {
      setSaving(false)
    }
  }

  return <label className="language-select">
    {t('language')}
    <select value={locale} aria-busy={saving} disabled={saving} onChange={event => void saveLanguage(resolveLocale(event.target.value))}>
      {(Object.keys(locales) as Locale[]).map(value =>
        <option key={value} value={value} lang={value} dir={locales[value].direction}>{locales[value].name}</option>
      )}
    </select>
    {failed && <span role="alert">{locale === 'ar' ? 'تعذّر حفظ اللغة. حاول مجددًا.' : 'Could not save the language. Try again.'}</span>}
  </label>
}
