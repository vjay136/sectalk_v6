import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../lib/authenticated-file-request'
import { validFileId } from '../../../lib/file-download-ticket'
import { readAttachmentUpload, readUploadFilename } from '../../../lib/attachment-upload-body'
import { allowedFileType, attachmentDocumentFormat, officeFormatPattern } from '../../../lib/file-type-policy'
import { attachmentInspectionLabel, inspectAttachment } from '../../../lib/attachment-inspection'
import { scanAttachment } from '../../../lib/attachment-scan-server'
import { checkFileEgress } from '../../../lib/file-egress'
import { digestWorkspaceBytes, workspaceFileBucket, workspaceFileFingerprint, workspaceFileMaximum, workspaceFilePath } from '../../../lib/workspace-file-storage'

export const runtime = 'nodejs'
export const maxDuration = 40

const forbidden = () => fileFailure(404, 'Workspace file access is unavailable.')
async function handle(request: Request) {
  const query = new URL(request.url).searchParams
  const workspace = query.get('workspace')?.toLowerCase()
  const file = query.get('file')?.toLowerCase()
  const action = query.get('action')
  const filename = readUploadFilename(request)
  const mime = request.headers.get('content-type') || ''
  if (!validFileId(workspace) || (file !== undefined && !validFileId(file))) return fileFailure(400, 'Choose a valid workspace file.')
  const auth = await authenticateFileRequest(request,{type:'workspace',id:workspace})
  if (auth instanceof Response) return auth
  const command = (action: string, size: number | null = null, hash: string | null = null) =>
    auth.storage.rpc('st_v6_workspace_file_command', {
      p_workspace: workspace, p_actor: auth.actor, p_action: action, p_id: file ?? null,
      p_filename: filename ?? null, p_bytes: size, p_hash: hash,
    })
  const record = (event: 'view' | 'download' | 'share') => auth.storage.rpc('st_v6_record_workspace_file_access', {
    p_workspace: workspace, p_file: file, p_actor: auth.actor, p_event: event,
  })
  const bucket = auth.storage.storage.from(workspaceFileBucket)
  if (request.method === 'GET' && !file) {
    const result = await command('list')
    if (result.error) return fileFailure(503, 'Workspace files are unavailable.')
    return result.data ? Response.json(result.data, { headers: fileHeaders }) : forbidden()
  }
  if (!file) return fileFailure(400, 'Choose a valid workspace file.')
  const object = workspaceFilePath(workspace, file)
  if (request.method === 'POST' && action !== null) {
    if (action !== 'view' && action !== 'share') return fileFailure(400, 'Choose a valid workspace file action.')
    if (action === 'share') {
      const denied = await checkFileEgress(auth.client, 'workspace', workspace, file, 'share')
      if (denied) return denied
    }
    const result = await record(action)
    if (result.error) return fileFailure(503, 'Workspace file access could not be recorded.')
    if (!result.data) return forbidden()
    return Response.json(action === 'share' ? { path: '/workspace-file/' + object } : result.data, { headers: fileHeaders })
  }
  if (request.method === 'DELETE') {
    const result = await command('remove')
    if (result.error) return fileFailure(503, 'The workspace file could not be removed.')
    return result.data ? new Response(null, { status: 204, headers: fileHeaders }) : forbidden()
  }
  if (request.method === 'GET') {
    const denied = await checkFileEgress(auth.client, 'workspace', workspace, file, 'download')
    if (denied) return denied
    const metadata = await command('get')
    if (metadata.error) return fileFailure(503, 'Workspace files are unavailable.')
    if (!metadata.data) return forbidden()
    const downloaded = await bucket.download(object)
    if (downloaded.error || !downloaded.data || downloaded.data.size !== metadata.data.size_bytes ||
      downloaded.data.size > workspaceFileMaximum) return forbidden()
    const bytes = Buffer.from(await downloaded.data.arrayBuffer())
    const current = await command('get')
    if (current.error || !current.data || current.data.size_bytes !== bytes.length ||
      (current.data.fingerprint && current.data.fingerprint !== workspaceFileFingerprint(workspace, digestWorkspaceBytes(bytes)))) {
      return forbidden()
    }
    const changed = await checkFileEgress(auth.client, 'workspace', workspace, file, 'download')
    if (changed) return changed
    const logged = await record('download')
    if (logged.error) return fileFailure(503, 'Workspace file access could not be recorded.')
    if (!logged.data) return forbidden()
    return new Response(Uint8Array.from(bytes), { headers: { ...fileHeaders, 'Content-Type': 'application/octet-stream',
      'Content-Disposition': 'attachment' } })
  }
  if (!filename || [...filename].length > 140 || /[\/\\\p{Cc}]/u.test(filename) || mime.length > 100) {
    return fileFailure(400, 'Choose a supported workspace file.')
  }
  if (Number(request.headers.get('content-length')) > workspaceFileMaximum) return fileFailure(413, 'Choose a file up to 4 MiB.')
  const access = await command('access')
  if (access.error) return fileFailure(503, 'Workspace files are unavailable.')
  if (!access.data) return forbidden()
  const bytes = await readAttachmentUpload(request, workspaceFileMaximum).catch(() => null)
  if (bytes === undefined) return fileFailure(413, 'Choose a file up to 4 MiB.')
  if (!bytes?.length) return fileFailure(400, 'Choose a file that contains data.')
  if (!allowedFileType(filename, mime, bytes)) return fileFailure(415, 'The file contents do not match a supported attachment type.')
  const hash = digestWorkspaceBytes(bytes)
  const blocked = await auth.storage.rpc('st_v7_upload_digest_blocked', { p_hash: hash })
  if (blocked.error) return fileFailure(503, 'The platform file policy could not be checked.')
  if (blocked.data === true) return fileFailure(422, 'The workspace file was blocked by platform policy.')
  const scan = await scanAttachment(bytes, hash, attachmentDocumentFormat(filename))
  if (scan.verdict === 'malware') {
    await command('malware', null, hash)
    return fileFailure(422, 'The workspace file was blocked by security scanning.')
  }
  if (scan.unsupported) return fileFailure(415, 'The document structure is outside supported inspection limits.')
  if (scan.verdict !== 'clean' || (officeFormatPattern.test(filename) && !scan.validatedFormat)) {
    return fileFailure(503, 'Workspace file security scanning is unavailable.')
  }
  const reason = attachmentInspectionLabel(scan.reason ?? inspectAttachment(filename, bytes))
  if (reason) return fileFailure(422, 'Workspace file inspection flagged ' + reason.toLowerCase() + '.')
  const reservation = await command('reserve', bytes.length, hash)
  if (reservation.error?.code === 'PT413') return fileFailure(413, 'The workspace file storage limit was reached.')
  if (reservation.error?.code === 'PT409') return fileFailure(409, 'Choose a new workspace file identifier.')
  if (reservation.error?.code === 'PT422') return fileFailure(422, 'The workspace file was blocked by security scanning.')
  if (reservation.error) return fileFailure(503, 'Workspace file storage is unavailable.')
  if (!reservation.data) return forbidden()
  if (!reservation.data.uploaded) {
    await bucket.upload(object, bytes, { contentType: 'application/octet-stream', upsert: false, cacheControl: '0' })
  }
  const stored = await bucket.download(object)
  if (stored.error || !stored.data || stored.data.size !== bytes.length ||
    digestWorkspaceBytes(Buffer.from(await stored.data.arrayBuffer())) !== hash) {
    return fileFailure(409, 'The workspace file in Storage could not be verified.')
  }
  const publication = await command('publish', bytes.length, hash)
  if (publication.error?.code === 'PT422') return fileFailure(422, 'The workspace file was blocked by security scanning.')
  if (publication.error) return fileFailure(503, 'The workspace file could not be published.')
  return publication.data ? Response.json(publication.data, { headers: fileHeaders }) : forbidden()
}

export const GET = handle
export const POST = handle
export const DELETE = handle
