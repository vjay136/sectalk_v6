'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { downloadName, formatChatFileBytes, saveDownload } from '../../lib/chat-files'

type Details = { filename: string; size_bytes: number; view_only: boolean }

export default function SharedFilePage() {
  const [password, setPassword] = useState('')
  const [file, setFile] = useState<Details | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [preview, setPreview] = useState('')
  useEffect(() => () => { if (preview) URL.revokeObjectURL(preview) }, [preview])

  async function requestAccess(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const response = await fetch('/api/files/share', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: location.hash.slice(1), password, action: file ? file.view_only ? 'preview' : 'download' : 'view' }),
      })
      if (!response.ok) {
        const payload = await response.json().catch(() => null)
        setError(payload?.error || 'The shared attachment is unavailable.')
        setFile(null)
        return
      }
      if (file?.view_only) {
        if (response.headers.get('content-type') !== 'image/png') throw new Error('Unexpected preview type')
        setPreview(URL.createObjectURL(await response.blob()))
        setPassword('')
      } else if (file) {
        saveDownload(await response.blob(), downloadName(file.filename))
        setFile(null)
        setPassword('')
      } else setFile(await response.json() as Details)
    } catch {
      setError('The shared attachment is unavailable.')
    } finally {
      setBusy(false)
    }
  }

  return <main className="content-page">
    <header className="content-title"><h1>Shared attachment</h1></header>
    <section className="panel release-panel">
      <form onSubmit={requestAccess}>
        <label>Share password<input type="password" autoComplete="off" minLength={10} maxLength={64}
          required value={password} onChange={event => { setPassword(event.target.value); setFile(null); setPreview('') }}/></label>
        {file && <p><strong>{file.filename}</strong> · {formatChatFileBytes(file.size_bytes)}</p>}
        {!preview && <button className="primary" disabled={busy}>{file ? file.view_only ? 'Preview attachment' : 'Download attachment' : 'Open shared attachment'}</button>}
      </form>
      {preview && <img src={preview} alt={'Preview of ' + file?.filename} style={{ display: 'block', maxWidth: '100%' }}/>}
      {error && <p className="error" role="alert">{error}</p>}
    </section>
  </main>
}
