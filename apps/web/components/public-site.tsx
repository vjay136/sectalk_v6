import type { ReactNode } from 'react'
import Image from 'next/image'
import Link from 'next/link'
import styles from './public-site.module.css'

const links = [
  ['/about', 'Overview'], ['/pricing', 'Pricing'], ['/trust', 'Security'], ['/docs', 'Docs'], ['/status', 'Status'], ['/legal', 'Legal'],
] as const
const legalLinks = [
  ['/legal/terms', 'Terms'], ['/legal/privacy', 'Privacy'], ['/legal/dpa', 'DPA template'],
] as const

export function PublicSite({ children }: { children: ReactNode }) {
  return <div className={styles.shell}>
    <header className={styles.header}>
      <Link href="/about" className={styles.brand}>
        <Image src="/sectalk-logo.webp" width={44} height={44} alt=""/>
        <span>SecTalk{' '}<small>Eagle Security</small></span>
      </Link>
      <nav aria-label="Public pages" className={styles.links}>
        {links.map(([href, name]) => <Link key={href} href={href}>{name}</Link>)}
      </nav>
      <Link href="/#account" className="secondary">Sign in</Link>
    </header>
    <main className={styles.content} id="main-content">{children}</main>
    <footer className={styles.footer}>
      <span>SecTalk by Eagle Security</span>
      <nav aria-label="Legal and support">
        {legalLinks.map(([href, name]) => <Link key={href} href={href}>{name}</Link>)}
        <Link href="/security">Report a vulnerability</Link>
      </nav>
    </footer>
  </div>
}
