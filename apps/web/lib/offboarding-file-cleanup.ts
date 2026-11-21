import { authenticateFileRequest, fileFailure, fileHeaders } from './authenticated-file-request'
import { readAttachmentUpload } from './attachment-upload-body'
import { validFileId } from './file-download-ticket'
import { digestWorkspaceBytes, roomFilePath, workspaceFilePath, workspaceFileBucket, workspaceFileMaximum } from './workspace-file-storage'

export async function handleFileRegistrationCleanup(request: Request, scope: 'room' | 'workspace') {
  const unavailable = () => fileFailure(409, 'The exact '+scope+' file cleanup is unavailable. Check current approval, access and Storage status.')
  const query = new URL(request.url).searchParams
  const workspace = query.get('workspace')
  const copy = query.get('copy')
  const file = query.get('file')
  const action = query.get('action')
  const confirmation = query.get('confirmation')
  if (!validFileId(workspace) || !validFileId(copy) || !validFileId(file) || confirmation !== workspace ||
    (action !== 'review' && action !== 'remove')) return fileFailure(400, 'Confirm the exact workspace and '+scope+' file.')
  const auth = await authenticateFileRequest(request, {type:'workspace', id:workspace})
  if (auth instanceof Response) return auth
  const begin = await auth.client.rpc(scope === 'room' ? 'st_v8_begin_room_file_cleanup' : 'st_v8_begin_workspace_file_cleanup', {
    p_workspace:workspace,p_copy:copy,p_action:action,p_confirmation:confirmation,
  })
  if (begin.error?.code === '42501') return fileFailure(403, 'Current independent offboarding access is required.')
  const ticket = begin.data
  if (begin.error || !validFileId(ticket?.ticket) || (scope === 'room' ? !validFileId(ticket?.room) : ticket?.room !== undefined) || ticket.file !== file ||
    !Number.isInteger(ticket.bytes) || ticket.bytes < 1 || ticket.bytes > workspaceFileMaximum) return unavailable()

  const finish = scope === 'room' ? 'st_v8_finish_room_file_cleanup' : 'st_v8_finish_workspace_file_cleanup'
  if (action === 'review') {
    const bytes = await readAttachmentUpload(request, ticket.bytes).catch(() => null)
    if (bytes === undefined) return fileFailure(413, 'The retained file is larger than the approved copy.')
    if (!bytes || bytes.length !== ticket.bytes) return fileFailure(422, 'The retained bytes do not match the approved copy.')
    const result = await auth.storage.rpc(finish, {
      p_ticket:ticket.ticket,p_sha256:digestWorkspaceBytes(bytes),p_bytes:bytes.length,
    })
    return result.error || result.data !== true ? unavailable() : Response.json({reviewed:true}, {headers:fileHeaders})
  }

  // The documented object information call distinguishes a missing key from
  // lost access, bad credentials and a missing bucket.
  const path = scope === 'room' ? roomFilePath(workspace, ticket.room, file) : workspaceFilePath(workspace, file)
  const info = await auth.storage.storage.from(workspaceFileBucket).info(path).catch(() => null)
  const error = info?.error
  if (!error || !('code' in error) || error.code !== 'NoSuchKey' ||
    (error.status !== 404 && !(error.status === 400 && error.statusCode === '404'))) return unavailable()
  const result = await auth.storage.rpc(finish, {
    p_ticket:ticket.ticket,p_observed_at:new Date().toISOString(),
  })
  return result.error || result.data !== true ? unavailable() : Response.json({registrationRemoved:true}, {headers:fileHeaders})
}
