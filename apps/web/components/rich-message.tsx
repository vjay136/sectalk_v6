'use client'

import { db } from '../lib/data'
import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { parseRichText, safeRichLink } from '../lib/rich-message.mjs'
import { isSuspiciousSafetyLink } from '../lib/safety.mjs'
import { EmojiText } from './emoji-text'

const preferenceEvent = 'sectalk:link-preview'
const preferenceKey = (account: string) => 'sectalk:link-preview:' + account
const preferenceListeners = new Set<() => void>()
function updatePreference() {
  preferenceListeners.forEach(notify => notify())
}
function subscribe(notify: () => void) {
  if (!preferenceListeners.size) {
    window.addEventListener('storage', updatePreference)
    window.addEventListener(preferenceEvent, updatePreference)
  }
  preferenceListeners.add(notify)
  return () => {
    preferenceListeners.delete(notify)
    if (!preferenceListeners.size) {
      window.removeEventListener('storage', updatePreference)
      window.removeEventListener(preferenceEvent, updatePreference)
    }
  }
}
function usePreviewPreference(account?: string) {
  return useSyncExternalStore(subscribe, () => {
    try { return !!account && localStorage.getItem(preferenceKey(account)) === 'enabled' }
    catch { return false }
  }, () => false)
}
export function MessageFormatting({ account, mode }: { account: string; mode: 'managed' | 'encrypted' }) {
  const enabled = usePreviewPreference(account)
  return <details className="rich-message-formatting">
    <summary>Message formatting and link previews</summary>
    <p>Use **bold**, *italic*, or {'`code`'}. Use [label](https://example.org) for a labeled link.</p>
    <label><input type="checkbox" checked={enabled} onChange={event => {
      try {
        if (event.target.checked) localStorage.setItem(preferenceKey(account), 'enabled')
        else localStorage.removeItem(preferenceKey(account))
        window.dispatchEvent(new Event(preferenceEvent))
      } catch { /* Preferences stay disabled if browser storage is unavailable. */ }
    }}/> Enable link previews on this device</label>
    <p>{mode === 'encrypted' ? 'Encrypted previews show the destination domain computed on this device.' :
      'You can request a preview for an approved HTTPS destination. Only the address without query or fragment is sent for checking.'}</p>
  </details>
}

type Link = NonNullable<ReturnType<typeof safeRichLink>>
type Preview = { host: string; status: number } | 'unavailable'

function ManagedLinkPreview({ account, link }: { account: string; link: Link }) {
  const [busy, setBusy] = useState(false)
  const [preview, setPreview] = useState<Preview>()
  const pending = useRef<AbortController>(undefined)
  useEffect(() => () => pending.current?.abort(), [])
  async function show() {
    if (pending.current) return
    const request = new AbortController()
    pending.current = request
    setBusy(true)
    try {
      const { data: { session } } = await db!.auth.getSession()
      if (session?.user.id !== account || request.signal.aborted) throw new Error('Session unavailable')
      const response = await fetch('/api/safety/url-inspection', {
        method: 'POST', signal: request.signal, headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: link.inspect }),
      })
      if (!response.ok) throw new Error('Preview unavailable')
      const result = await response.json()
      const final = Array.isArray(result.hops) ? result.hops.at(-1) : null
      const destination = safeRichLink(final?.url)
      if (result.outcome !== 'checked' || !destination || !Number.isInteger(final.status) || final.status < 100 || final.status > 599) {
        throw new Error('Preview unavailable')
      }
      setPreview({ host: destination.host, status: final.status })
    } catch {
      if (!request.signal.aborted) setPreview('unavailable')
    } finally {
      if (pending.current === request) pending.current = undefined
      if (!request.signal.aborted) setBusy(false)
    }
  }
  return <span className="rich-message-preview">
    <button type="button" className="text-button" onClick={() => void show()} disabled={busy}>
      {busy ? 'Checking link preview…' : 'Check link preview'}
    </button>
    {preview && <span role="status">{preview === 'unavailable' ? 'Link preview unavailable.' :
      <>Destination <bdi>{preview.host}</bdi> · HTTP {preview.status}. Site safety is unverified.</>}</span>}
  </span>
}

export function RichMessage({ value, account, mode, allowLinks = true }: {
  value: string; account?: string; mode?: 'managed' | 'encrypted'; allowLinks?: boolean
}) {
  const enabled = usePreviewPreference(account)
  const parts = parseRichText(value)
  const safe = (link: Link) => allowLinks && !isSuspiciousSafetyLink(link.href)
  const first = parts.find(part => part.url && safe(part.url))?.url
  return <span className="rich-message">{parts.map((part, index) => {
    switch (part.kind) {
      case 'code': return <code key={index}>{part.text}</code>
      case 'strong': return <strong key={index}><EmojiText value={part.text}/></strong>
      case 'em': return <em key={index}><EmojiText value={part.text}/></em>
      case 'link': {
        const address = part.url
        if (address && safe(address) && mode === 'encrypted') return <button key={index} type="button" className="text-button rich-message-link"
          onClick={() => window.open(address.href, '_blank', 'noopener,noreferrer')}><bdi>{part.text}</bdi>
          {part.text !== address.href && <small> (<bdi>{address.host}</bdi>)</small>}</button>
        return address && safe(address) ?
        <a key={index} href={part.url.href} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">
          <bdi>{part.text}</bdi>{part.text !== part.url.href && <small> (<bdi>{part.url.host}</bdi>)</small>}
        </a> : <span key={index}>{part.text}{part.url && <> (<bdi>{part.url.host}</bdi>)</>}</span>
      }
      default: return <EmojiText key={index} value={part.text}/>
    }
  })}
    {enabled && first && (mode === 'encrypted' ? <small className="rich-message-preview">Link domain <bdi>{first.host}</bdi></small> :
      mode === 'managed' && account ? <ManagedLinkPreview key={account + first.inspect} account={account} link={first}/> : null)}
  </span>
}
