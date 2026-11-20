import type { Metadata } from 'next'
import Link from 'next/link'
import { PublicSite } from '../../components/public-site'
import styles from '../../components/public-site.module.css'

export const metadata: Metadata = { title: 'Help and product guides | SecTalk' }

const guides = [
  ['account', 'Create or recover an account', 'Create a password when signing up. Open the email confirmation link, finish verification on the SecTalk page, and sign in. If you forget your password, request a code from the sign-in screen and enter it before choosing a new password.'],
  ['chat', 'Find contacts and start a conversation', 'Open Contacts and send a connection request. After it is accepted, use Inbox to send a message, attach a supported file, reply, or open the message menu for available actions. The audio and video controls are in the conversation header.'],
  ['safety', 'Block a contact or report a message', 'Open the conversation or message menu and choose Block or Report. When reporting, select a reason and review what will be included. Track status from Safety → My reports.'],
  ['workspace', 'Work in rooms and shared files', 'Choose your workspace and select a room or the Files tab. Use the room view for threads and pins. Administrators use Workspaces → Governance for controls available to their role.'],
  ['billing', 'Compare and manage plans', 'Open Billing to compare the available currencies and intervals. Select My subscription for the current terms or to open the billing portal when a provider account is linked.'],
] as const

export default function DocsPage() {
  return <PublicSite>
    <article className={styles.reading}>
      <header className={styles.heading}><h1>SecTalk guides</h1><p>Find the controls you need for accounts, conversations and workspaces.</p></header>
      <nav aria-label="On this page"><ul>{guides.map(([id, title]) => <li key={id}><a href={'#' + id}>{title}</a></li>)}</ul></nav>
      {guides.map(([id, title, text]) => <section id={id} key={id}><h2>{title}</h2><p>{text}</p></section>)}
      <div className="action-row"><Link href="/#account" className="primary">Open SecTalk</Link><Link href="/status" className="secondary">Check service status</Link></div>
    </article>
  </PublicSite>
}
