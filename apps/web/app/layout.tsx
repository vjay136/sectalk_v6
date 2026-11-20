import type { Metadata } from 'next'
import { cookies } from 'next/headers'
import { LocaleProvider } from '../components/locale-provider'
import { OfflineRegistration } from '../components/offline-registration'
import { localeCookie, locales, resolveLocale } from '../lib/locale'
import './styles.css'

export const metadata: Metadata = {
  title: 'SecTalk by Eagle Security',
  description: 'Private conversations with built-in tools to stop harassment and report scams.',
}

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const locale = resolveLocale((await cookies()).get(localeCookie)?.value)
  return <html lang={locale} dir={locales[locale].direction}><body>
    <LocaleProvider initialLocale={locale}>{children}</LocaleProvider>
    <OfflineRegistration/>
  </body></html>
}
