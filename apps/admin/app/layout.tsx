import type { Metadata } from 'next'
import '../../web/app/styles.css'
import './operator.css'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = {
  title: 'SecTalk Operator Console',
  description: 'SecTalk queue operations by Eagle Security.',
  robots: { index: false, follow: false },
}

export default function Layout({children}: {children: React.ReactNode}) {
  return <html lang="en"><body>{children}</body></html>
}
