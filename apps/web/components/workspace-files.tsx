'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { downloadName, extensions, formatChatFileBytes, saveDownload, supportedFile } from '../lib/chat-files'
import { workspaceFileRequest } from '../lib/workspace-files-client'
import { WorkspaceFileDetails } from './workspace-file-details'
import { WorkspaceFileHistory } from './workspace-file-history'

type Entry = { id: string; filename: string; size_bytes: number; can_remove: boolean }

export function WorkspaceFiles({ workspace, owner }: { workspace: string; owner: boolean }) {
  const [files, setFiles] = useState<Entry[] | null>(null)
  const [selection, setSelection] = useState<{ file: File; id: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [feedback, setFeedback] = useState('')
  const [details, setDetails] = useState<string | null>(null)

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const rows = await (await workspaceFileRequest(workspace, 'GET', { signal })).json() as Entry[]
      if (!signal?.aborted) setFiles(rows)
    } catch {
      if (!signal?.aborted) {
        setFiles(null)
        setError('Could not load workspace files.')
      }
    }
  }, [workspace])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    return () => controller.abort()
  }, [load])

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !selection) return
    if (!supportedFile(selection.file)) {
      setError('Choose a supported file up to 4 MiB.')
      return
    }
    const form = event.currentTarget
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      const result = await (await workspaceFileRequest(workspace, 'POST', selection)).json()
      setFeedback(result.duplicate ? 'Uploaded. An identical file already exists in this workspace.' : 'Workspace file uploaded.')
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
    if (busy || (remove && !window.confirm('Remove this file from the workspace?'))) return
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      const result = await workspaceFileRequest(workspace, remove ? 'DELETE' : 'GET', { id: entry.id })
      if (remove) {
        if (details === entry.id) setDetails(null)
        setFeedback('Workspace file removed.')
        await load()
      } else saveDownload(await result.blob(), downloadName(entry.filename))
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not access this workspace file.')
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="Workspace files">
    <h2>Workspace files</h2>
    <p>Files are available to active members of this workspace.</p>
    <form className="release-form" onSubmit={upload}>
      <label>Choose workspace file<input type="file" accept={extensions} disabled={busy} required onChange={event => {
        const file = event.target.files?.[0]
        setSelection(file ? { file, id: crypto.randomUUID() } : null)
        setError('')
      }}/></label>
      <button className="primary" disabled={busy || !selection}>Upload workspace file</button>
    </form>
    <button className="secondary" type="button" disabled={busy} onClick={() => {setError(''); void load()}}>Refresh files</button>
    {feedback && <p role="status">{feedback}</p>}
    {error && <p className="error" role="alert">{error}</p>}
    {files === null && !error && <p role="status">Loading workspace files…</p>}
    {files?.length === 0 && <p>No workspace files yet.</p>}
    {files?.map(entry => <article className="release-board-item" key={entry.id}>
      <h3>{entry.filename}</h3>
      <p>{formatChatFileBytes(entry.size_bytes)}</p>
      <button type="button" className="secondary" disabled={busy} onClick={() => setDetails(entry.id)}>View file details</button>
      <button type="button" className="secondary" disabled={busy} onClick={() => void useFile(entry, false)}>Download file</button>
      {entry.can_remove && <button type="button" className="secondary" disabled={busy} onClick={() => void useFile(entry, true)}>Remove file</button>}
    </article>)}
    {details && <WorkspaceFileDetails key={details} workspace={workspace} file={details} close={() => setDetails(null)}/>}
    <WorkspaceFileHistory workspace={workspace} owner={owner}/>
  </section>
}
