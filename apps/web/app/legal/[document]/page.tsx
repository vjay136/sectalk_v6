import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { connection } from 'next/server'
import { PublicSite } from '../../../components/public-site'
import styles from '../../../components/public-site.module.css'
import { publicLegalRelease } from '../../../lib/public-legal-release'

const documents = {
  terms: {
    title: 'Terms of service',
    summary: 'Draft terms for SecTalk by Eagle Security. These terms are available for review and have no effective date.',
    sections: [
      ['Accounts and workspaces', 'Use an email address you control and keep your password and verification codes private. Workspace administrators can manage membership, permissions, and access to workspace resources. Review workspace rules and the conversation’s encryption mode before sharing confidential material.'],
      ['Acceptable use', 'Do not use SecTalk to harass, threaten, stalk, impersonate, defraud, share sexual material without consent, exploit a minor, or distribute unlawful content. Share material you have permission to use. Use the conversation controls to stop unwanted contact or report abuse.'],
      ['Reports, restrictions and appeals', 'Safety reviewers may examine submitted evidence and use warnings or access restrictions. Open Safety to review the status and outcome of a report you submitted. Use the available appeal action if you believe a restriction was applied in error.'],
      ['Subscriptions and renewal', 'Review the price, currency and billing interval shown before you authorize a purchase. Open Billing to review your plan, invoices and renewal settings. Enterprise orders follow the applicable signed agreement. Confirm the applicable cancellation and refund rules before subscribing.'],
      ['Leaving the service', 'Use Profile to request a copy of eligible account data or start account deletion. Workspace retention, pending obligations and applicable preservation requirements can affect availability and deletion.'],
    ],
  },
  privacy: {
    title: 'Privacy notice',
    summary: 'Draft privacy notice for SecTalk by Eagle Security. It describes the app’s data handling and has no effective date.',
    sections: [
      ['Account, device and workspace data', 'SecTalk uses account and profile details, approved-device identifiers, session and security events, and workspace membership to verify accounts, manage access and deliver the features you use. People can discover you using the profile details and visibility controls you choose.'],
      ['Messages, files and calls', 'Standard and managed workspace content is available to authorized service functions under the relevant permissions. Protected direct and group messages use browser-held keys. The service keeps routing metadata, such as participants, approved-device identifiers, delivery order and times. Call services process signaling and media for the selected call mode. Recording, captions and summaries depend on the enabled controls and permissions.'],
      ['Safety and service providers', 'Authorized reviewers can open evidence submitted through Safety. Enrollment, email delivery, file storage, communications, and subscription providers process data required for the enabled services. A payment provider may collect payment details at checkout. SecTalk retains the transaction and billing records needed to operate the subscription.'],
      ['Account data and preferences', 'Open Profile and select Privacy and data to download eligible personal records or request account deletion. Profile settings also control sharing, discovery and notifications. The app shows the state of a deletion request and any applicable dependency before processing it.'],
      ['Retention and operator details', 'Retention depends on the data type, workspace policy and applicable preservation requirements. The published notice will specify the operator and contact, processing purposes and applicable legal bases, provider and transfer details, and applicable rights and complaint channels.'],
    ],
  },
  dpa: {
    title: 'Data processing addendum template',
    summary: 'Negotiation template for managed workspaces. Complete the schedule fields and sign the applicable agreement before using it as a contract.',
    sections: [
      ['Parties and scope', 'Schedule A identifies the customer controller, service provider, points of contact, the agreement term, processing purposes, instructions and authorized transfer locations. Include account holders and workspace members as applicable and describe account information, workspace content, audit events and support records.'],
      ['Instructions and safeguards', 'The processor follows documented instructions, limits access to authorized people under confidentiality commitments, and implements the measures listed in Schedule B. Include access management, logging, encryption, incident response, recovery, and retention controls appropriate to the selected deployment.'],
      ['Subprocessors and transfers', 'Schedule C lists authorized subprocessors, services and processing regions. Set out the parties’ notice, objection and written flow-down process. Document any applicable transfer mechanism and supplementary safeguards separately.'],
      ['Incidents, rights and deletion', 'Agree on the notification channel and timing for incidents, assistance with data rights and impact assessments, and provision of compliance evidence. Define return or deletion at termination and any lawful exceptions using the retention schedule.'],
      ['Audit and execution', 'Record audit procedures, the agreement order of precedence, schedule dates and each party’s signatory. Each deployment needs completed schedules reflecting the contracted services.'],
    ],
  },
} as const

function findDocument(key: string) {
  return Object.hasOwn(documents, key) ? documents[key as keyof typeof documents] : null
}

export async function generateMetadata({ params }: { params: Promise<{ document: string }> }): Promise<Metadata> {
  const document = findDocument((await params).document)
  return { title: document ? document.title + ' | SecTalk' : 'Legal | SecTalk', robots: { index: false } }
}

export default async function LegalPage({ params }: { params: Promise<{ document: string }> }) {
  const { document: key } = await params
  const document = findDocument(key)
  if (!document) notFound()
  await connection()
  const release = key === 'dpa' ? null : publicLegalRelease()
  const approved = key === 'terms' ? release?.terms : key === 'privacy' ? release?.privacy : undefined
  return <PublicSite>
    <article className={styles.reading}>
      <Link href="/legal">All legal documents</Link>
      <header className={styles.heading}>
        <h1>{document.title}</h1>
        {approved ? <p>Effective <time dateTime={approved.effectiveOn}>{approved.effectiveOn}</time> · Version {approved.version}</p> : <>
          <p><strong>{key === 'dpa' ? 'Unsigned template' : 'Draft'}</strong></p>
          <p>{document.summary}</p>
          {key !== 'dpa' && <p>The effective document will be published after operator approval.</p>}
        </>}
      </header>
      {approved && release ? <>
        <section aria-label="Service operator">
          <h2>Service operator</h2>
          <p>{release.operator.name}</p>
          {key === 'privacy' ? <a href={release.operator.privacyContact}>Privacy contact</a> :
            <a href={release.operator.supportContact}>Service contact</a>}
        </section>
        {approved.sections.map(({ title, text }, index) =>
          <section key={index}><h2>{title}</h2><p style={{whiteSpace:'pre-line'}}>{text}</p></section>)}
      </> : document.sections.map(([title, text]) => <section key={title}><h2>{title}</h2><p>{text}</p></section>)}
      {key === 'privacy' && <p><Link href="/#account">Sign in to manage your account data</Link></p>}
      {key === 'dpa' && <p><a href="https://eur-lex.europa.eu/eli/dec_impl/2021/915/oj">European Commission controller–processor clauses</a></p>}
    </article>
  </PublicSite>
}
