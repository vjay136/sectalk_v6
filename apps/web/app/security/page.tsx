import type { Metadata } from 'next'
import Link from 'next/link'
import { connection } from 'next/server'
import { getSecurityDisclosure } from '../../lib/security-disclosure'

export const metadata: Metadata = { title: 'Report a security vulnerability | SecTalk' }

export default async function SecurityPage() {
  await connection()
  const disclosure = getSecurityDisclosure()

  return <main className="center-page">
    <section className="panel release-panel" aria-labelledby="disclosure-title">
      <h1 id="disclosure-title">Report a security vulnerability</h1>
      <p>Use coordinated disclosure to report weaknesses in SecTalk’s web app, APIs, or access controls. For harmful messages or behavior, use the Report option in the conversation.</p>
      {disclosure
        ? <a className="primary" href={disclosure.contact}>Submit a private report</a>
        : <p role="status">The private reporting channel is unavailable. Keep vulnerability details private until the contact is available.</p>}
      <h2>What to include</h2>
      <p>Share the affected feature and version, the security impact, and a clear description using only test accounts and synthetic data. Remove passwords, tokens, private messages, and personal information.</p>
      <h2>How disclosure works</h2>
      <p>Keep the report private while maintainers assess it and coordinate any fix or public advisory. Use environments and accounts you have explicit permission to test.</p>
      <div className="action-row">
        {disclosure && <a className="secondary" href="/.well-known/security.txt">security.txt</a>}
        <Link className="secondary" href="/">Back to SecTalk</Link>
      </div>
    </section>
  </main>
}
