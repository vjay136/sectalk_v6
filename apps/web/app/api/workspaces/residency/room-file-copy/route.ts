import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../../../lib/authenticated-file-request'
import { validFileId } from '../../../../../lib/file-download-ticket'
import { digestWorkspaceBytes, roomFilePath, workspaceFileBucket, workspaceFileMaximum } from '../../../../../lib/workspace-file-storage'

export const runtime = 'nodejs'
const unavailable = () => fileFailure(404, 'The reviewed room file copy is unavailable.')

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams
  const workspace = query.get('workspace')?.toLowerCase()
  const file = query.get('file')?.toLowerCase()
  const review = query.get('residency-rollback')?.toLowerCase()
  if (!validFileId(workspace) || !validFileId(file) || !validFileId(review)) {
    return fileFailure(400, 'Choose a valid workspace, file, and rollback review.')
  }
  const auth = await authenticateFileRequest(request, { type: 'workspace', id: workspace })
  if (auth instanceof Response) return auth

  const scope = { p_workspace: workspace, p_review: review, p_file: file }
  const snapshot = await auth.client.rpc('st_v8_residency_rollback_room_file_copy', scope)
  const room = snapshot.data?.room
  const size = snapshot.data?.bytes
  if (snapshot.error || !validFileId(room) || !Number.isInteger(size) || size < 1 || size > workspaceFileMaximum) {
    return unavailable()
  }
  const stored = await auth.storage.storage.from(workspaceFileBucket).download(roomFilePath(workspace, room, file))
  if (stored.error || !stored.data || stored.data.size !== size) return unavailable()

  const bytes = Buffer.from(await stored.data.arrayBuffer())
  const signed = await auth.client.rpc('st_v8_residency_rollback_room_file_copy', {
    ...scope, p_sha256: digestWorkspaceBytes(bytes),
  })
  if (signed.error || signed.data?.room !== room || signed.data?.stamp !== snapshot.data.stamp ||
    signed.data?.bytes !== bytes.length || !signed.data?.proof) return unavailable()

  return new Response(Uint8Array.from(bytes), { headers: {
    ...fileHeaders,
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': 'attachment',
    'X-SecTalk-Rollback-File-Proof': Buffer.from(JSON.stringify(signed.data.proof)).toString('base64url'),
  } })
}
