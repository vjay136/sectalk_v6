import type { Metadata } from 'next'
import Image from 'next/image'
import Link from 'next/link'
import { FileCheck2, MessagesSquare, ShieldCheck } from 'lucide-react'
import { PublicSite } from '../../components/public-site'
import styles from '../../components/public-site.module.css'

export const metadata: Metadata = { title: 'Messaging and safety tools | SecTalk' }

export default function OverviewPage() {
  return <PublicSite>
    <section className={styles.hero}>
      <div>
        <h1>Conversations with stronger safety controls.</h1>
        <p>Chat and call in real time, organize your work in shared spaces, and report harmful messages with a clear review history.</p>
        <div className="action-row">
          <Link className="primary" href="/?mode=signup#account">Create an account</Link>
          <Link className="secondary" href="/pricing">Compare plans</Link>
        </div>
      </div>
      <Image src="/sectalk-logo.webp" alt="SecTalk Eagle Security shield" width={400} height={400} priority/>
    </section>
    <section className={styles.cards} aria-label="SecTalk features">
      <article><MessagesSquare aria-hidden/><h2>Chat, voice and video</h2><p>Reach accepted contacts with messages or calls. Use room threads, private attachments, reactions and workspace tasks to keep conversations organized.</p></article>
      <article><ShieldCheck aria-hidden/><h2>Report and track concerns</h2><p>Block unwanted contact, flag abuse or suspected fraud, and follow review updates in your Safety center.</p></article>
      <article><FileCheck2 aria-hidden/><h2>Manage workspace access</h2><p>Control member roles, keep files scoped to authorized people, and review governance and security activity with an authenticator.</p></article>
    </section>
  </PublicSite>
}
