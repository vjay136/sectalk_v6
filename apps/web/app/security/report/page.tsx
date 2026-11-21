import Link from 'next/link'
import {notFound} from 'next/navigation'
import {connection} from 'next/server'
import {vulnerabilityIntakeContact} from '../../../lib/security-disclosure'
import {DisclosureForm} from '../../../components/disclosure-form'

export const metadata={title:'Submit a private vulnerability report | SecTalk',robots:{index:false,follow:false}}

export default async function VulnerabilityReport() {
  await connection()
  if (!vulnerabilityIntakeContact()) notFound()
  return <main className="center-page"><section className="panel release-panel">
    <h1>Submit a private vulnerability report</h1>
    <p>Describe the affected feature and impact using synthetic data. Remove login codes, tokens, or other people’s information.</p>
    <DisclosureForm/>
    <Link href="/security">Disclosure policy</Link>
  </section></main>
}
