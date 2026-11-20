'use client'

import {useEffect, useState, type FormEvent} from 'react'
import {db} from '../../lib/data'

type Scope = {id: string; name: string}
type Batch = {id: string; period: string; deliveries: Record<string, string>}
type Listing = {batches: Batch[]; channels: string[]}
const channelNames: Record<string, string> = {webhook: 'Webhook', syslog: 'Syslog (CEF)', s3: 'S3 batch'}

async function requestSiem(path: string, options?: RequestInit) {
  const session = await db?.auth.getSession()
  const token = session?.data.session?.access_token
  if (!token) throw new Error('Sign in to export SIEM digests.')
  const response = await fetch('/api/siem' + path, {...options, headers: {
    Authorization: 'Bearer ' + token, ...(options?.body ? {'Content-Type': 'application/json'} : {}),
  }})
  if (response.status === 403) throw new Error('Fresh authenticator verification and enterprise workspace ownership are required.')
  if (response.status === 400) throw new Error('Choose a completed UTC hour within the past seven days.')
  if (!response.ok) throw new Error('The SIEM export is currently unavailable.')
  return response
}

export default function SiemExports() {
  const [scopes, setScopes] = useState<Scope[]>([])
  const [workspace, setWorkspace] = useState('')
  const [period, setPeriod] = useState(() => new Date(Math.floor(Date.now() / 3600000) * 3600000 - 3600000).toISOString().slice(0, 16))
  const [listing, setListing] = useState<Listing | null>(null)
  const [status, setStatus] = useState('')
  const [pending, setPending] = useState(false)
  const [revision, setRevision] = useState(0)
  const [channel, setChannel] = useState('download')

  useEffect(() => {
    if (!db) return
    const controller = new AbortController()
    void db.rpc('st_v7_permission_catalog', {p_workspace: null, p_room: null}).abortSignal(controller.signal).then(result => {
      if (controller.signal.aborted) return
      if (result.error) setStatus('Sign in to load your workspaces.')
      else setScopes(result.data.workspaces)
    })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!workspace) return
    const controller = new AbortController()
    void requestSiem('?workspace=' + workspace, {signal: controller.signal})
      .then(response => response.json()).then(data => {
        if (!controller.signal.aborted) setListing(data)
      }).catch((error: Error) => {
        if (!controller.signal.aborted) setStatus(error.message)
      })
    return () => controller.abort()
  }, [workspace, revision])

  async function download(batch: string) {
    const response = await requestSiem('?workspace=' + workspace + '&batch=' + batch)
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a')
    link.href = url
    link.download = 'sectalk-siem-' + batch + '.json'
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setPending(true)
    setStatus('')
    try {
      const response = await requestSiem('', {method: 'POST', body: JSON.stringify({workspace, period: period + ':00.000Z', channel})})
      const {id} = await response.json()
      if (channel === 'download') await download(id)
      setStatus(channel === 'download' ? 'Signed digest downloaded.' : 'Digest queued for delivery.')
      setRevision(value => value + 1)
    } catch (error) {
      setStatus((error as Error).message)
    } finally {
      setPending(false)
    }
  }

  return <main className="panel">
    <a href="/">Back to SecTalk</a>
    <h1>SIEM exports</h1>
    <p>Export hourly counts of workspace security audit events as signed JSON.</p>
    <label>Workspace
      <select value={workspace} disabled={pending} onChange={event => {
        setWorkspace(event.target.value)
        setListing(null)
        setChannel('download')
        setStatus('')
      }}>
        <option value="">Choose a workspace</option>
        {scopes.map(scope => <option key={scope.id} value={scope.id}>{scope.name}</option>)}
      </select>
    </label>
    {listing && <>
      <form onSubmit={submit}>
        <label>Hour starting (UTC)
          <input type="datetime-local" required step={3600} value={period} onChange={event => setPeriod(event.target.value)}/>
        </label>
        <label>Export destination
          <select value={channel} onChange={event => setChannel(event.target.value)}>
            <option value="download">Signed JSON download</option>
            {listing.channels.map(value => <option key={value} value={value}>{channelNames[value]}</option>)}
          </select>
        </label>
        <button disabled={pending}>{channel === 'download' ? 'Download signed digest' : 'Queue digest'}</button>
      </form>
      <h2>Recent digests</h2>
      <button type="button" onClick={() => setRevision(value => value + 1)}>Refresh deliveries</button>
      {listing.batches.length === 0 && <p>No digests yet.</p>}
      <ul>{listing.batches.map(batch => <li key={batch.id}>
        <time dateTime={batch.period}>{new Date(batch.period).toISOString()}</time>
        {Object.entries(batch.deliveries).map(([key, state]) => <span key={key}>{' · ' + channelNames[key] + ' ' + state}</span>)}
        <button type="button" onClick={() => void download(batch.id).catch(error => setStatus(error.message))}>Download digest</button>
      </li>)}</ul>
    </>}
    {status && <p role="status">{status}</p>}
  </main>
}
