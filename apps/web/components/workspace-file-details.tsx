'use client'

import { useEffect, useState } from 'react'
import { downloadName, formatChatFileBytes, saveDownload } from '../lib/chat-files'
import { workspaceFileRequest } from '../lib/workspace-files-client'
import { FileEgressExplanation } from './workspace-file-egress'

type Details = { filename: string; size_bytes: number }

export function WorkspaceFileDetails({ workspace, file, close }: { workspace: string; file: string; close?: () => void }) {
  const [details, setDetails] = useState<Details | null>(null)
  const [error, setError] = useState('')
  const [link, setLink] = useState('')
  const [copied, setCopied] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    void workspaceFileRequest(workspace, 'POST', { id: file, action: 'view', signal: controller.signal })
      .then(response => response.json()).then((metadata: Details) => {
        if (!controller.signal.aborted) setDetails(metadata)
      }).catch(failure => {
        if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : 'Workspace file is unavailable.')
      })
    return () => controller.abort()
  }, [workspace, file])

  async function useFile(share: boolean) {
    if (busy || !details) return
    setBusy(true)
    setError('')
    setCopied(false)
    setLink('')
    try {
      if (share) {
        const response = await workspaceFileRequest(workspace, 'POST', { id: file, action: 'share' })
        const { path } = await response.json()
        if (path !== '/workspace-file/' + workspace.toLowerCase() + '/' + file.toLowerCase()) throw new Error('Workspace link is unavailable.')
        const url = location.origin + path
        setLink(url)
        try { await navigator.clipboard.writeText(url); setCopied(true) } catch {
          // The generated link remains available for manual copying.
        }
      } else {
        const response = await workspaceFileRequest(workspace, 'GET', { id: file })
        saveDownload(await response.blob(), downloadName(details.filename))
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Workspace file is unavailable.')
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-board-item" aria-label="Workspace file details">
    <h3>{details?.filename ?? 'Workspace file details'}</h3>
    {close && <button className="secondary" type="button" onClick={close}>Close details</button>}
    {!details && !error && <p role="status">Loading file details…</p>}
    {error && <p className="error" role="alert">{error}</p>}
    {details && <>
      <p>{formatChatFileBytes(details.size_bytes)}</p>
      <button className="secondary" type="button" disabled={busy} onClick={() => void useFile(false)}>Download workspace file</button>
      <button className="secondary" type="button" disabled={busy} onClick={() => void useFile(true)}>Copy workspace link</button>
      <FileEgressExplanation scope={workspace} file={file}/>
      {link && <><label>Workspace file link<input value={link} readOnly onFocus={event => event.currentTarget.select()}/></label>
        <p role="status">{copied ? 'Workspace link copied.' : 'Select the link to copy it.'} Active workspace membership is required.</p></>}
    </>}
  </section>
}
