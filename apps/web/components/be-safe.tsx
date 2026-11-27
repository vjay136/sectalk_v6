'use client'

import { useState, type FormEvent } from 'react'
import { Search, ShieldAlert } from 'lucide-react'
import { db } from '../lib/data'
import { SectionTabs } from './section-tabs'

type Mode = 'message' | 'link' | 'account'
type Lookup = { categories: string[]; restricted: boolean; links: { address: string; restricted: boolean }[] }

const categories: Record<string, string> = {
  spam: 'Spam', unwanted: 'Unwanted content', fake: 'False or misleading content', abuse: 'Abuse or harassment',
  fraud: 'Fraud or scam', gambling: 'Gambling solicitation', insecure_link: 'Unsafe link', other: 'Reviewed safety warning',
}

function extractLinks(value: string) {
  const links = new Set<string>()
  for (const match of value.matchAll(/https?:\/\/[^\s<>"']+/gi)) {
    const raw = match[0].replace(/[.,!?;:]+$/, '')
    const url = raw.length <= 1500 && !raw.includes('\\') ? URL.parse(raw) : null
    if (!url || url.username || url.password || url.port) continue
    url.search = ''
    url.hash = ''
    links.add(url.href)
  }
  return [...links]
}

export function BeSafe() {
  const [mode, setMode] = useState<Mode>('message')
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<Lookup>()

  function reset() { setError(''); setResult(undefined) }

  async function check(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const input = value.trim()
    if (!input || busy) return
    reset()
    const handle = mode === 'account' ? input.replace(/^@/, '').toLowerCase() : null
    if (handle !== null && !/^[a-z0-9_]{3,24}$/.test(handle)) {
      setError('Enter one exact SecTalk username.'); return
    }
    const links = mode === 'account' ? [] : extractLinks(input)
    if (links.length > 8 || (mode === 'link' && !links.length)) {
      setError('Enter one to eight web addresses starting with https:// or http://.'); return
    }
    setBusy(true)
    try {
      const fingerprint = mode === 'message' ? Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',
        new TextEncoder().encode(input))), byte => byte.toString(16).padStart(2, '0')).join('') : null
      const { data, error: failure } = await db!.rpc('st_be_safe_lookup', {
        p_fingerprint: fingerprint, p_links: links, p_handle: handle,
      }).abortSignal(AbortSignal.timeout(8000))
      if (failure || !data) {
        setError(failure?.code === 'PT429' || failure?.message === 'Too many requests'
          ? 'You’ve reached the check limit. Try again in a minute.' : 'SecTalk couldn’t check its records. Try again.')
        return
      }
      if (mode === 'link' && !data.links.length) {
        setError('Enter a web address with a valid domain.'); return
      }
      setResult(data)
    } catch { setError('SecTalk couldn’t check its records. Try again.') }
    finally { setBusy(false) }
  }

  const hasWarning = result && (result.restricted || result.categories.length > 0 || result.links.some(link => link.restricted))

  return <section className="release-section" aria-label="Be Safe lookup">
    <h2>Be Safe</h2>
    <p>Check SecTalk’s reviewed safety records before you reply, open a link, or forward a message.</p>
    <SectionTabs label="What to check" value={mode} onChange={next => {
      if (!busy) { setMode(next); setValue(''); reset() }
    }} options={[["message", "Message"], ["link", "Links"], ["account", "Username"]]} />
    <form className="release-form" onSubmit={check}>
      <label>{mode === 'account' ? 'SecTalk username' : mode === 'link' ? 'Web addresses' : 'Exact message text'}
        {mode === 'account' ? <input placeholder="@username" required maxLength={25} value={value} disabled={busy}
          autoCapitalize="none" autoComplete="off" spellCheck={false} onChange={event => { setValue(event.target.value); reset() }} />
          : <textarea rows={mode === 'link' ? 3 : 5} maxLength={8000} required value={value} disabled={busy}
            autoComplete="off" spellCheck={false} onChange={event => { setValue(event.target.value); reset() }} />}
      </label>
      <p className="muted">{mode === 'account' ? 'Checks active restrictions for contacts and profiles that opted into discovery.'
        : mode === 'link' ? 'Checks up to eight links without visiting them. Query strings and fragments are omitted.'
        : 'Paste a complete message for an exact match. SecTalk checks its fingerprint and up to eight embedded links.'}</p>
      <button type="submit" className="primary" disabled={busy || !value.trim()}><Search size={16} /> {busy ? 'Checking…' : 'Check safety records'}</button>
    </form>
    {error && <p role="alert">{error}</p>}
    {result && <div className="release-board-item" aria-live="polite">
      <h3>{hasWarning ? <><ShieldAlert size={18} /> SecTalk warning found</> : 'No matching warning'}</h3>
      {result.categories.length > 0 && <ul>{result.categories.map(category => <li key={category}>{categories[category] ?? categories.other}</li>)}</ul>}
      {result.restricted && <p>SecTalk has an active safety restriction on this account.</p>}
      {result.links.length > 0 && <ul>{result.links.map(link => <li key={link.address}>
        <code style={{ overflowWrap: 'anywhere' }}>{link.address}</code> · {link.restricted ? 'Restricted' : 'No matching warning'}
      </li>)}</ul>}
      <p className="muted">An unmatched result leaves safety unverified. You can report suspicious content from its conversation.</p>
    </div>}
  </section>
}
