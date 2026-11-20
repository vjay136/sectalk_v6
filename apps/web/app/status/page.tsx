import Link from 'next/link'
import { connection } from 'next/server'
import { checkConfiguredDatabase } from '../../lib/readiness'

export default async function StatusPage() {
  await connection()
  const ready = await checkConfiguredDatabase()
  const checked = new Date()
  return <main className="center-page">
    <section className="panel release-panel" aria-labelledby="service-status">
      <h1 id="service-status">SecTalk service status</h1>
      <dl>
        <div className="release-row"><dt>Web app</dt><dd>Reachable</dd></div>
        <div className="release-row"><dt>Database readiness</dt><dd>{ready ? 'Ready' : 'Unavailable'}</dd></div>
      </dl>
      <p>Checked at <time dateTime={checked.toISOString()}>{checked.toISOString()}</time></p>
      <Link className="secondary" href="/">Back to SecTalk</Link>
    </section>
  </main>
}
