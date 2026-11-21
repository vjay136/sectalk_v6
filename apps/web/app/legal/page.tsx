import type { Metadata } from 'next'
import Link from 'next/link'
import { connection } from 'next/server'
import { PublicSite } from '../../components/public-site'
import styles from '../../components/public-site.module.css'
import { publicLegalRelease } from '../../lib/public-legal-release'

export const metadata: Metadata = { title: 'Legal | SecTalk', robots: { index: false } }

export default async function LegalIndex() {
  await connection()
  const release = publicLegalRelease()
  return <PublicSite>
    <article className={styles.reading}>
      <header className={styles.heading}>
        <h1>Legal</h1>
        <p>{release ? 'Read the effective service terms and privacy notice.' : 'The service terms and privacy notice are available as drafts. The effective documents will be published after operator approval.'}</p>
      </header>
      {release && <section aria-labelledby="legal-operator">
        <h2 id="legal-operator">Service operator</h2>
        <p>{release.operator.name}</p>
        <ul>
          <li><a href={release.operator.supportContact}>Service contact</a></li>
          <li><a href={release.operator.privacyContact}>Privacy contact</a></li>
        </ul>
      </section>}
      <section aria-labelledby="legal-documents">
        <h2 id="legal-documents">Documents</h2>
        <ul>
          <li><Link href="/legal/terms">Terms of service</Link> · {release ? 'Effective ' + release.terms.effectiveOn : 'Draft'}</li>
          <li><Link href="/legal/privacy">Privacy notice</Link> · {release ? 'Effective ' + release.privacy.effectiveOn : 'Draft'}</li>
          <li><Link href="/legal/dpa">Data processing addendum template</Link> · Unsigned template</li>
        </ul>
      </section>
    </article>
  </PublicSite>
}
