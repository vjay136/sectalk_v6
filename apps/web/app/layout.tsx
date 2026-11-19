import type { Metadata } from 'next'
import './styles.css'

export const metadata: Metadata = {
  title: 'SecTalk by Eagle Security',
  description: 'Private conversations with built-in tools to stop harassment and report scams.',
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>
}
