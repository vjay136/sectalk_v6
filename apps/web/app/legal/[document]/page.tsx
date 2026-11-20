import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { PublicSite } from '../../../components/public-site'
import styles from '../../../components/public-site.module.css'

const documents = {
  terms: {
    title: 'Terms of service',
    summary: 'SecTalk v6 draft. The service operator will finalize these terms before public release.',
    sections: [
      ['Accounts and access', 'Keep your account credentials private and use a valid email address. Workspace administrators can manage access and enforce workspace policies for their members.'],
      ['Acceptable use', 'Do not use SecTalk to harass, threaten, impersonate, defraud or distribute unlawful content. Use the Safety center and conversation controls to report abuse and stop unwanted contact.'],
      ['Content and moderation', 'Share only content you have permission to use. SecTalk may review reports and restrict accounts to protect users. Workspace retention settings and applicable preservation obligations may affect content availability.'],
      ['Subscriptions', 'The applicable price, currency and billing interval are shown before purchase. Manage renewals through Billing or the applicable enterprise agreement. Refund and cancellation terms depend on the finalized subscription terms and applicable law.'],
    ],
  },
  privacy: {
    title: 'Privacy notice',
    summary: 'SecTalk v6 draft. This notice describes the app’s data use. The operator will publish its finalized notice and contact details before public release.',
    sections: [
      ['Information you provide', 'SecTalk stores account, profile and membership information and processes the messages, uploads, reports and other content you choose to submit. Call services process signaling and media as needed for the selected call mode.'],
      ['Why the service uses it', 'Data supports account verification, communication, access control, workspace operations, safety investigations, and subscriptions when a billing provider is configured. Optional recordings, captions or summaries use the applicable feature controls and permissions.'],
      ['Who has access', 'Other participants and workspace roles receive access according to the selected visibility and permissions. Authorized staff can review submitted evidence. Infrastructure, email, media and billing providers process information needed to provide their enabled services.'],
      ['Retention and choices', 'Retention depends on data type, workspace policy and active preservation requirements. Account and notification settings control available choices. The final notice will specify the operator, legal bases where applicable, retention procedures, contact details and how to exercise applicable rights.'],
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

export function generateStaticParams() {
  return Object.keys(documents).map(document => ({ document }))
}

export async function generateMetadata({ params }: { params: Promise<{ document: string }> }): Promise<Metadata> {
  const document = findDocument((await params).document)
  return { title: document ? document.title + ' | SecTalk' : 'Legal | SecTalk', robots: { index: false } }
}

export default async function LegalPage({ params }: { params: Promise<{ document: string }> }) {
  const { document: key } = await params
  const document = findDocument(key)
  if (!document) notFound()
  return <PublicSite>
    <article className={styles.reading}>
      <header className={styles.heading}><h1>{document.title}</h1><p>{document.summary}</p></header>
      {document.sections.map(([title, text]) => <section key={title}><h2>{title}</h2><p>{text}</p></section>)}
      {key === 'dpa' && <p><a href="https://eur-lex.europa.eu/eli/dec_impl/2021/915/oj">European Commission controller–processor clauses</a></p>}
    </article>
  </PublicSite>
}
