'use client'

import { createContext, useContext, useState, type ReactNode } from 'react'
import { formatMessage, localeCookie, locales, resolveLocale, type Locale, type Message } from '../lib/locale'

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
    const secure = location.protocol === 'https:' ? '; Secure' : ''
    document.cookie = `${localeCookie}=${next}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`
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
  return <label className="language-select">
    {t('language')}
    <select value={locale} onChange={event => changeLocale(resolveLocale(event.target.value))}>
      {(Object.keys(locales) as Locale[]).map(value =>
        <option key={value} value={value} lang={value} dir={locales[value].direction}>{locales[value].name}</option>
      )}
    </select>
  </label>
}
