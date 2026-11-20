'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'

type Share = { id: string; expires_at: string; max_downloads: number; downloads: number; revoked_at: string | null;
  view_only: boolean; watermark: boolean }
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function AttachmentShareLinks({ file, onChanged, allowPreview }: { file: string; onChanged: () => void; allowPreview: boolean }) {
  const [links, setLinks] = useState<Share[]>([])
  const [created, setCreated] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [viewOnly, setViewOnly] = useState(false)

  const load = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v6_list_file_shares', { p_file: file })
    if (error) setError('Could not load share links.')
    else setLinks(data as Share[])
  }, [file])
  useEffect(() => { void load() }, [load])

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const fields = new FormData(form)
    const password = String(fields.get('password'))
    const length = new TextEncoder().encode(password).length
    setError('')
    if (length < 10 || length > 64) {
      setError('Use a password between 10 and 64 bytes.')
      return
    }
    setBusy(true)
    setCopied(false)
    try {
      const { data, error } = await db!.rpc('st_v6_create_file_share', {
        p_file: file, p_password: password, p_seconds: Number(fields.get('duration')),
        p_downloads: Number(fields.get('downloads')),
        p_view_only: viewOnly, p_watermark: viewOnly && fields.has('watermark'),
      })
      if (error) setError(error.code === 'PT409' ? 'Revoke an active link before creating another.' : 'Could not create the share link.')
      else {
        form.reset()
        setViewOnly(false)
        setCreated(location.origin + '/shared-file#' + data)
        await load()
        onChanged()
      }
    } finally {
      setBusy(false)
    }
  }

  async function revoke(id: string) {
    setBusy(true)
    setError('')
    try {
      const { error } = await db!.rpc('st_v6_revoke_file_share', { p_file: file, p_link: id })
      if (error) setError('Could not revoke the share link.')
      else {
        setCreated('')
        await load()
        onChanged()
      }
    } finally {
      setBusy(false)
    }
  }

  return <details>
    <summary>Share links</summary>
    <form onSubmit={create}>
      <label>Share password<input name="password" type="password" minLength={10} maxLength={64} autoComplete="new-password" required/></label>
      <label>Expires after<select name="duration" defaultValue="86400">
        <option value="900">15 minutes</option><option value="3600">1 hour</option>
        <option value="86400">1 day</option><option value="604800">7 days</option>
      </select></label>
      {allowPreview && <label>Link access<select value={viewOnly ? 'preview' : 'download'} onChange={event=>setViewOnly(event.target.value==='preview')}>
        <option value="download">Allow downloading</option><option value="preview">View only</option>
      </select></label>}
      {viewOnly && <label className="task-check"><input name="watermark" type="checkbox" defaultChecked/> Watermark previews</label>}
      <label>{viewOnly ? 'Maximum previews' : 'Maximum downloads'}<input name="downloads" type="number" min={1} max={100} defaultValue={5} required/></label>
      <button className="secondary" disabled={busy}>Create share link</button>
    </form>
    {created && <div>
      <label>New share link<input value={created} readOnly onFocus={event => event.target.select()}/></label>
      <button className="secondary" type="button" onClick={async () => {
        try { await navigator.clipboard.writeText(created); setCopied(true) }
        catch { setError('Select the displayed link to copy it manually.') }
      }}>Copy link</button>
      {copied && <p role="status">Share link copied.</p>}
      <p className="muted">Copy the link now and give the password separately to the intended recipient.</p>
    </div>}
    {links.length > 0 && <ul className="audit">{links.map(link => {
      const active = !link.revoked_at && Date.parse(link.expires_at) > Date.now() && link.downloads < link.max_downloads
      return <li key={link.id}>
        <span>{link.revoked_at ? 'Revoked' : active ? 'Active' : 'Expired or used up'} · {link.downloads}/{link.max_downloads}
          {' '}{link.view_only ? 'previews' : 'downloads'}{link.watermark ? ' · Watermarked' : ''}</span>
        <small>Expires <time dateTime={link.expires_at}>{dateFormat.format(new Date(link.expires_at))}</time></small>
        {active && <button className="secondary" type="button" disabled={busy} onClick={() => void revoke(link.id)}>Revoke link</button>}
      </li>
    })}</ul>}
    {error && <p role="alert" className="error">{error}</p>}
  </details>
}
