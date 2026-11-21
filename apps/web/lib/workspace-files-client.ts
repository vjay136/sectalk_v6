import { db } from './data'

export class WorkspaceFileRequestError extends Error {
  constructor(message: string, readonly code?: string) {
    super(message)
  }
}

export async function workspaceFileRequest(workspace: string, method: string, options: {
  id?: string; file?: File; action?: 'view' | 'share'; signal?: AbortSignal; room?: boolean; rollbackReview?: string;
  rollbackProof?: string; rollbackRestore?: string
} = {}) {
  const { data } = await db!.auth.getSession()
  if (!data.session) throw new Error('Sign in to access workspace files.')
  const query = new URLSearchParams(options.room ? { room: workspace } : { workspace })
  if (options.id) query.set('file', options.id)
  if (options.action) query.set('action', options.action)
  if (options.rollbackReview) query.set('residency-rollback', options.rollbackReview)
  if (options.rollbackRestore) query.set('residency-rollback-restore', options.rollbackRestore)
  const headers = new Headers({ Authorization: 'Bearer ' + data.session.access_token })
  if (options.rollbackProof) {
    query.set('residency-rollback-stage', '1')
    headers.set('X-SecTalk-Rollback-File-Proof', options.rollbackProof)
  }
  if (options.file) {
    headers.set('X-SecTalk-File-Name', encodeURIComponent(options.file.name))
    headers.set('Content-Type', options.file.type || 'application/octet-stream')
  }
  const response = await fetch((options.room ? '/api/room-files?' : '/api/workspace-files?') + query,
    { method, headers, body: options.file, signal: options.signal })
  if (!response.ok) {
    const detail = await response.json().catch(() => null)
    throw new WorkspaceFileRequestError(detail?.error || 'The workspace file action could not be completed.', detail?.code)
  }
  return response
}
