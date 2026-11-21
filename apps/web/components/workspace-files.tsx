'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { downloadName, extensions, formatChatFileBytes, saveDownload, supportedFile } from '../lib/chat-files'
import { workspaceFileRequest, WorkspaceFileRequestError } from '../lib/workspace-files-client'
import { WorkspaceFileDetails } from './workspace-file-details'
import { WorkspaceFileHistory } from './workspace-file-history'
import { FileEgressExplanation } from './workspace-file-egress'

type Entry = { id: string; filename: string; size_bytes: number; can_remove: boolean }

export function WorkspaceFiles({ workspace, owner }: { workspace: string; owner: boolean }) {
  return <FileLibrary scope={workspace} owner={owner}/>
}

export function RoomFiles({ room }: { room: string }) {
  return <FileLibrary scope={room} room owner={false}/>
}

function FileLibrary({ scope, owner, room = false }: { scope: string; owner: boolean; room?: boolean }) {
  const [files, setFiles] = useState<Entry[] | null>(null)
  const [canUpload, setCanUpload] = useState(!room)
  const [selection, setSelection] = useState<{ file: File; id: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [loadError, setLoadError] = useState('')
  const [ssoRequired, setSsoRequired] = useState(false)
  const [feedback, setFeedback] = useState('')
  const [details, setDetails] = useState<string | null>(null)
  const loadVersion = useRef(0)

  const load = useCallback(async (signal?: AbortSignal) => {
    const request = ++loadVersion.current
    try {
      const data = await (await workspaceFileRequest(scope, 'GET', { room, signal })).json()
      if (!signal?.aborted && request===loadVersion.current) {
        setFiles(room ? data.files as Entry[] : data as Entry[])
        setCanUpload(!room || data.can_upload === true)
        setSsoRequired(false)
        setLoadError('')
      }
    } catch (failure) {
      if (!signal?.aborted && request===loadVersion.current) {
        const blocked = failure instanceof WorkspaceFileRequestError && failure.code==='workspace_sso_required'
        setFiles(null)
        setCanUpload(false)
        setSsoRequired(blocked)
        setLoadError(blocked ? failure.message : room ? 'Could not load room files.' : 'Could not load workspace files.')
        if(blocked)setDetails(null)
      }
    }
  }, [room, scope])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    const timer = window.setInterval(() => void load(controller.signal), room ? 5000 : 8000)
    return () => {
      controller.abort()
      ++loadVersion.current
      window.clearInterval(timer)
    }
  }, [load, room])

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !selection || !canUpload) return
    if (!supportedFile(selection.file)) {
      setError('Choose a supported file up to 4 MiB.')
      return
    }
    const form = event.currentTarget
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      const result = await (await workspaceFileRequest(scope, 'POST', { ...selection, room })).json()
      setFeedback(room ? 'Room file uploaded.' :
        result.duplicate ? 'Uploaded. An identical file already exists in this workspace.' : 'Workspace file uploaded.')
      setSelection(null)
      form.reset()
      await load()
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not upload this workspace file.')
    } finally {
      setBusy(false)
    }
  }

  async function useFile(entry: Entry, remove: boolean) {
    if (busy || (remove && !window.confirm(room ? 'Remove this file from the room?' : 'Remove this file from the workspace?'))) return
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      const result = await workspaceFileRequest(scope, remove ? 'DELETE' : 'GET', { id: entry.id, room })
      if (remove) {
        if (details === entry.id) setDetails(null)
        setFeedback(room ? 'Room file removed.' : 'Workspace file removed.')
        await load()
      } else saveDownload(await result.blob(), downloadName(entry.filename))
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not access this workspace file.')
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label={room ? 'Room files' : 'Workspace files'}>
    <h2>{room ? 'Room files' : 'Workspace files'}</h2>
    <p>{room ? 'Files are available to members of this room.' : 'Files are available to active members of this workspace.'}</p>
    {canUpload && <form className="release-form" onSubmit={upload}>
      <label>{room ? 'Choose room file' : 'Choose workspace file'}<input type="file" accept={extensions} disabled={busy} required onChange={event => {
        const file = event.target.files?.[0]
        setSelection(file ? { file, id: crypto.randomUUID() } : null)
        setError('')
      }}/></label>
      <button className="primary" disabled={busy || !selection}>{room ? 'Upload room file' : 'Upload workspace file'}</button>
    </form>}
    <button className="secondary" type="button" disabled={busy} onClick={() => {setError(''); void load()}}>Refresh files</button>
    {feedback && <p role="status">{feedback}</p>}
    {error && <p className="error" role="alert">{error}</p>}
    {loadError && <p role={ssoRequired?'status':'alert'} className={ssoRequired?undefined:'error'}>{loadError}</p>}
    {files === null && !error && !loadError && <p role="status">{room ? 'Loading room files…' : 'Loading workspace files…'}</p>}
    {files?.length === 0 && <p>{room ? 'No room files yet.' : 'No workspace files yet.'}</p>}
    {files?.map(entry => <article className="release-board-item" key={entry.id}>
      <h3>{entry.filename}</h3>
      <p>{formatChatFileBytes(entry.size_bytes)}</p>
      {!room && <button type="button" className="secondary" disabled={busy} onClick={() => setDetails(entry.id)}>View file details</button>}
      <button type="button" className="secondary" disabled={busy} onClick={() => void useFile(entry, false)}>Download file</button>
      {room && <FileEgressExplanation scope={scope} file={entry.id} room/>}
      {entry.can_remove && <button type="button" className="secondary" disabled={busy} onClick={() => void useFile(entry, true)}>Remove file</button>}
    </article>)}
    {!room && !ssoRequired && details && <WorkspaceFileDetails key={details} workspace={scope} file={details} close={() => setDetails(null)}/>}
    {!room && !ssoRequired && <WorkspaceFileHistory workspace={scope} owner={owner}/>}
  </section>
}
