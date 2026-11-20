'use client'

import { useEffect, useRef, useState } from 'react'
import { db, formatError } from '../lib/data'
import { saveDownload } from '../lib/chat-files'

type View = { owner: boolean; host: boolean; attendee: boolean; policy: boolean; recording: {
  id: string; status: string; mode: 'audio'|'single-camera'; eligible: boolean; accepted: boolean; count: number; approved: number
} | null }

function statusLabel(status: string, title: string) {
  const labels: Record<string, string> = {
    starting:'Starting '+title.toLowerCase()+'…', recording:title+' is in progress.', stopping:'Finalizing the recording…',
    ready:'The '+title.toLowerCase()+' is ready.', discard:'Recording stopped. Discarding the output…', failed:'The recording was discarded.',
  }
  return labels[status]
}

async function request(meeting: string, action: string, id?: string, signal?: AbortSignal) {
  const { data } = await db!.auth.getSession()
  const response = await fetch('/api/meetings/recordings', {
    method:'POST', headers:{ 'Content-Type':'application/json', Authorization:'Bearer '+data.session?.access_token },
    body:JSON.stringify({ meeting, action, id }), signal,
  })
  const result = await response.json()
  if (!response.ok) throw new Error(result.error)
  return result as View
}

export function MeetingRecording({ meeting, workspace, ended }: { meeting: string; workspace: string; ended: boolean }) {
  const [configured,setConfigured] = useState(false)
  const [state,setState] = useState<View|null>(null)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const version=useRef(0)

  useEffect(() => {
    const controller = new AbortController()
    let timer: number | undefined
    async function refresh() {
      const attempt = ++version.current
      try {
        const latest = await request(meeting,'view',undefined,controller.signal)
        if (!controller.signal.aborted && attempt === version.current) setState(latest)
      } catch {}
    }
    void fetch('/api/meetings/recordings',{ signal: controller.signal }).then(response=>response.json()).then(value => {
      if (controller.signal.aborted || !value.configured) return
      setConfigured(true)
      void refresh()
      timer = window.setInterval(() => void refresh(), 5000)
    }).catch(() => {})
    return () => { controller.abort(); window.clearInterval(timer) }
  },[meeting])

  async function act(action: string) {
    if (busy) return
    setBusy(true);setError('')
    ++version.current
    try {
      const latest = await request(meeting,action,state?.recording?.id)
      ++version.current
      setState(latest)
    } catch(failure) {
      setError(formatError(failure,'The recording action failed.'))
    } finally { setBusy(false) }
  }

  async function changePolicy() {
    if (busy || !state) return
    setBusy(true);setError('')
    ++version.current
    try {
      const result = await db!.rpc('st_v6_set_recording_policy',{ p_workspace:workspace,p_enabled:!state.policy })
      if (result.error) throw result.error
      const latest = await request(meeting,'view')
      ++version.current
      setState(latest)
    } catch(failure) {
      setError(formatError(failure,'The recording policy could not be updated.'))
    } finally { setBusy(false) }
  }

  async function download() {
    if (busy || !state?.recording) return
    setBusy(true);setError('')
    try {
      const { data } = await db!.auth.getSession()
      const query = new URLSearchParams({ meeting, recording:state.recording.id })
      const response = await fetch('/api/meetings/recordings?'+query,{headers:{ Authorization:'Bearer '+data.session?.access_token }})
      if (!response.ok) throw new Error('Recording unavailable.')
      saveDownload(await response.blob(),state.recording.mode==='single-camera' ? 'meeting.mp4' : 'meeting.ogg')
    } catch(failure) {
      setError(formatError(failure,'The recording could not be downloaded.'))
    } finally { setBusy(false) }
  }

  if (!configured || !state || (!state.owner && !state.attendee && !state.recording)) return null
  if (ended && !state.recording) return null
  const rec=state.recording
  const title = rec?.mode==='single-camera' ? 'Single-camera recording' : 'Audio recording'
  const label = title.toLowerCase()
  return <section className="release-section" aria-label="Meeting recording">
    <h3>Meeting recording</h3>
    {error && <p role="alert" className="error">{error}</p>}
    {state.owner && !ended && <button type="button" className="secondary" disabled={busy} onClick={() => void changePolicy()}>
      {state.policy ? 'Disable workspace recording' : 'Allow workspace recording'}
    </button>}
    {!state.policy && !rec && <p>Recording is disabled for this workspace.</p>}
    {state.policy && state.host && state.attendee && (!rec || rec.status==='failed' || rec.status==='collecting') && <>
      <div className="release-row">
        <button type="button" className="secondary" disabled={busy || rec?.status==='collecting'} onClick={() => void act('request')}>Request audio recording</button>
        <button type="button" className="secondary" disabled={busy || rec?.status==='collecting'} onClick={() => void act('request-video')}>Request recording with my camera</button>
      </div>
    </>}
    {rec?.status==='collecting' && <>
      <p role="status">{title} requested. All connected participants must agree before recording starts. {rec.approved} of {rec.count} have agreed.</p>
      {rec.mode==='single-camera' && <p>This records the requester’s current camera and the microphones published when they requested consent. Other cameras and shared screens are excluded.</p>}
      <div className="release-row">
        {rec.eligible && !rec.accepted && <button type="button" className="primary" disabled={busy} onClick={() => void act('accept')}>Agree to {label}</button>}
        {rec.eligible && <button type="button" className="secondary" disabled={busy} onClick={() => void act('withdraw')}>{rec.accepted?'Withdraw recording consent':'Decline '+label}</button>}
        {state.host && <button type="button" className="primary" disabled={busy || rec.approved!==rec.count} onClick={() => void act('start')}>Start {label}</button>}
      </div>
    </>}
    {rec && rec.status!=='collecting' && <p role="status">{statusLabel(rec.status,title)}</p>}
    {rec && ['starting','recording','stopping'].includes(rec.status) && rec.eligible &&
      <button type="button" className="secondary" disabled={busy} onClick={() => void act('withdraw')}>Withdraw recording consent</button>}
    {state.host && rec?.status==='recording' && <button type="button" className="danger" disabled={busy} onClick={() => void act('stop')}>Stop {label}</button>}
    {rec?.status==='ready' && rec.accepted && <button type="button" className="secondary" disabled={busy} onClick={() => void download()}>Download {label}</button>}
  </section>
}
