import type { Metadata } from 'next'
import { cookies } from 'next/headers'
import { LocaleProvider } from '../components/locale-provider'
import { OfflineRegistration } from '../components/offline-registration'
import { locales, resolveLocale } from '../lib/locale'
import { loopbackLocaleCookie, securedLocaleCookie } from '../lib/browser-request-policy'
import './styles.css'

export const metadata: Metadata = {
  title: 'SecTalk by Eagle Security',
  description: 'Private conversations with built-in tools to stop harassment and report scams.',
}

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const preferences = await cookies()
  const local = process.env.SECTALK_APP_URL?.startsWith('http://127.0.0.1:') || process.env.NODE_ENV !== 'production'
  const locale = resolveLocale(preferences.get(securedLocaleCookie)?.value ?? (local ? preferences.get(loopbackLocaleCookie)?.value : undefined))
  return <html lang={locale} dir={locales[locale].direction}><body>
    <LocaleProvider initialLocale={locale}>{children}</LocaleProvider>
    <OfflineRegistration/>
  </body></html>
}
