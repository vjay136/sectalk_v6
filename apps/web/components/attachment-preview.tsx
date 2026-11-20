'use client'

import { useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'

type Preview = { kind: 'image'; url: string } | { kind: 'text'; text: string; truncated: boolean }

export function AttachmentPreview({ file, filename }: { file: string; filename: string }) {
  const [preview, setPreview] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef<AbortController | null>(null)
  useEffect(() => () => pending.current?.abort(), [])
  const image = preview?.kind === 'image' ? preview.url : null
  useEffect(() => () => { if (image) URL.revokeObjectURL(image) }, [image])

  async function show() {
    if (busy) return
    const request = new AbortController()
    pending.current = request
    setBusy(true)
    setError('')
    try {
      const { data } = await db!.auth.getSession()
      if (!data.session) { setError('Sign in to preview the attachment.'); return }
      const response = await fetch('/api/files/preview?file=' + encodeURIComponent(file), {
        headers: { Authorization: 'Bearer ' + data.session.access_token }, signal: request.signal,
      })
      if (!response.ok) {
        const payload = await response.json().catch(() => null)
        setError(payload?.error || 'The attachment preview is unavailable.')
      } else if (response.headers.get('content-type') === 'image/png') {
        const blob = await response.blob()
        if (!request.signal.aborted) setPreview({ kind: 'image', url: URL.createObjectURL(blob) })
      } else {
        const value = await response.json()
        if (!request.signal.aborted && value.kind === 'text' && typeof value.text === 'string') setPreview(value as Preview)
      }
    } catch {
      if (!request.signal.aborted) setError('The attachment preview is unavailable.')
    } finally {
      if (!request.signal.aborted) setBusy(false)
    }
  }

  return <section aria-label="Attachment preview">
    {!preview && <button className="secondary" type="button" disabled={busy} onClick={() => void show()}>
      {busy ? 'Loading preview…' : 'Load preview'}
    </button>}
    {error && <p className="error" role="alert">{error}</p>}
    {preview?.kind === 'image' && <img src={preview.url} alt={'Preview of ' + filename}
      style={{ display: 'block', maxWidth: '100%', maxHeight: '18rem', objectFit: 'contain' }}/>}
    {preview?.kind === 'image' && /\.pdf$/i.test(filename) && <p className="muted">First page</p>}
    {preview?.kind === 'text' && <>
      <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: '16rem', overflow: 'auto' }}>{preview.text}</pre>
      {preview.truncated && <p className="muted">Showing the first part of this text file.</p>}
    </>}
  </section>
}
