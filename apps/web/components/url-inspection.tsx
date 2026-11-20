'use client'

import { useState, type FormEvent } from 'react'
import { db } from '../lib/data'

type Reputation = { status: 'unavailable' | 'unlisted' | 'observed' | 'risk-listed'; source?: string; domain?: string;
  registered?: string | null; recent?: boolean }
type Result = { normalized: string; stripped: boolean; outcome: 'checked' | 'blocked' | 'unavailable' | 'redirect-limit';
  hops: Array<{ url: string; status: number }>; domains: Array<{
    hostname: string; internationalized: boolean; possibleBrands: string[]; unencrypted: boolean; reputation: Reputation
  }> }

const outcomeText = {
  checked: 'The worker checked response headers. This check cannot determine whether a site is safe.',
  blocked: 'The network check stopped at a destination outside the approved HTTPS scope.',
  unavailable: 'Network inspection is unavailable for this URL.',
  'redirect-limit': 'The redirect chain reached the inspection limit.',
}
const reputationText = {
  unavailable: 'Verified reputation and registration data are unavailable.',
  unlisted: 'This domain is absent from the configured reputation feed.',
  observed: 'This domain is present in the configured reputation feed.',
  'risk-listed': 'The configured feed lists this domain for security review.',
}

export function UrlInspection() {
  const [value, setValue] = useState('')
  const [result, setResult] = useState<Result>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setResult(undefined)
    setError('')
    try {
      const { data } = await db!.auth.getSession()
      const response = await fetch('/api/safety/url-inspection', {
        method: 'POST', headers: { Authorization: 'Bearer ' + data.session?.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value }),
      })
      const dataSet = await response.json()
      if (!response.ok) { setError(dataSet.error || 'URL inspection is unavailable.'); return }
      setResult(dataSet as Result)
    } catch {
      setError('URL inspection is unavailable.')
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="URL inspection">
    <h2>URL inspection</h2>
    <form className="release-form" onSubmit={event => void inspect(event)}>
      <label>Web address<input type="url" required maxLength={1500} value={value} disabled={busy} autoComplete="off" spellCheck={false}
        onChange={event => { setValue(event.target.value); setResult(undefined); setError('') }} placeholder="https://example.org/path" /></label>
      <p>The worker checks approved HTTPS destinations after you submit. Queries and fragments are removed.</p>
      <button className="primary" type="submit" disabled={busy}>Inspect URL</button>
    </form>
    {busy && <p role="status">Inspecting URL…</p>}
    {error && <p role="alert">{error}</p>}
    {result && <div aria-label="URL inspection results">
      <p role="status">{outcomeText[result.outcome]}</p>
      <p>Normalized address <code style={{ overflowWrap: 'anywhere' }}>{result.normalized}</code></p>
      {result.stripped && <p>The query or fragment was omitted.</p>}
      {result.hops.length > 0 && <><h3>Response chain</h3><ol>{result.hops.map(hop =>
        <li key={hop.url}><code style={{ overflowWrap: 'anywhere' }}>{hop.url}</code> · HTTP {hop.status}</li>)}</ol></>}
      {result.domains.map(domain => <article className="release-board-item" key={domain.hostname}>
        <h3><bdi>{domain.hostname}</bdi></h3>
        {domain.internationalized && <p>The hostname contains an internationalized label shown in Punycode.</p>}
        {domain.unencrypted && <p>The address uses unencrypted HTTP.</p>}
        {domain.possibleBrands.length > 0 && <p>The hostname resembles {domain.possibleBrands.join(', ')} branding.</p>}
        <p>{reputationText[domain.reputation.status]}</p>
        {domain.reputation.source && <p>Verified source {domain.reputation.source}</p>}
        {domain.reputation.registered && <p>{domain.reputation.recent ? 'Recently registered' : 'Registration date'}{' '}
          <time dateTime={domain.reputation.registered}>{domain.reputation.registered}</time>
          {domain.reputation.domain ? ' · ' + domain.reputation.domain : ''}</p>}
      </article>)}
    </div>}
  </section>
}
