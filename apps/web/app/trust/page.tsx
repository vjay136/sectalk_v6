import type { Metadata } from 'next'
import Link from 'next/link'
import { PublicSite } from '../../components/public-site'
import styles from '../../components/public-site.module.css'

export const metadata: Metadata = { title: 'Security and trust | SecTalk' }

export default function TrustPage() {
  return <PublicSite>
    <article className={styles.reading}>
      <header className={styles.heading}><h1>Security and trust</h1><p>Understand how SecTalk controls access and handles safety reports.</p></header>
      <h2>Account and workspace access</h2>
      <p>Accounts use verified email and can add an authenticator. Sensitive workspace and staff actions require a verified authenticator and an eligible role. Room, file and meeting access follow current membership and settings.</p>
      <h2>Conversation privacy</h2>
      <p>Private access controls restrict who can see content. Managed conversations may be processed by SecTalk to provide search, reporting and moderation. Check a conversation or call’s own protection indicators before sharing sensitive information.</p>
      <h2>Safety response</h2>
      <p>Block a contact to stop new direct communication. Use the Report action to submit a concern with the context you choose to share. The Safety center shows your case status.</p>
      <h2>Vulnerability reporting and service health</h2>
      <p>Use the private disclosure process for a suspected weakness in SecTalk itself. Check the status page for the current web app and database readiness.</p>
      <div className="action-row"><Link className="primary" href="/security">Report a vulnerability</Link><Link className="secondary" href="/status">View service status</Link></div>
    </article>
  </PublicSite>
}
