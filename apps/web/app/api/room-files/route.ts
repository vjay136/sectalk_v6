import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../lib/authenticated-file-request'
import { validFileId } from '../../../lib/file-download-ticket'
import { readAttachmentUpload, readUploadFilename } from '../../../lib/attachment-upload-body'
import { allowedFileType, attachmentDocumentFormat, officeFormatPattern } from '../../../lib/file-type-policy'
import { inspectAttachment } from '../../../lib/attachment-inspection'
import { scanAttachment } from '../../../lib/attachment-scan-server'
import { checkFileEgress } from '../../../lib/file-egress'
import { digestWorkspaceBytes, roomFilePath, workspaceFileBucket, workspaceFileMaximum } from '../../../lib/workspace-file-storage'

export const runtime = 'nodejs'
export const maxDuration = 40
const unavailable = () => fileFailure(404, 'Room file access is unavailable.')

async function handle(request: Request) {
  const query = new URL(request.url).searchParams
  const room = query.get('room')?.toLowerCase()
  const file = query.get('file')?.toLowerCase()
  if (!validFileId(room) || (file !== undefined && !validFileId(file))) return fileFailure(400, 'Choose a valid room file.')
  const auth = await authenticateFileRequest(request,{type:'room',id:room})
  if (auth instanceof Response) return auth
  const filename = readUploadFilename(request)
  const command = (action: string, size: number | null = null, hash: string | null = null) =>
    auth.storage.rpc('st_v6_room_file_command', {
      p_room: room, p_actor: auth.actor, p_action: action, p_id: file ?? null,
      p_name: filename, p_bytes: size, p_hash: hash,
    })
  if (request.method === 'GET' && !file) {
    const list = await command('list')
    if (list.error) return fileFailure(503, 'Room files are unavailable.')
    return list.data ? Response.json(list.data, { headers: fileHeaders }) : unavailable()
  }
  if (!file) return fileFailure(400, 'Choose a valid room file.')
  if (request.method === 'DELETE') {
    const result = await command('remove')
    if (result.error) return fileFailure(503, 'The room file could not be removed.')
    return result.data ? new Response(null, { status: 204, headers: fileHeaders }) : unavailable()
  }
  const bucket = auth.storage.storage.from(workspaceFileBucket)
  if (request.method === 'GET') {
    const denied = await checkFileEgress(auth.client, 'room', room, file, 'download')
    if (denied) return denied
    const access = await command('get')
    if (access.error || !access.data) return unavailable()
    const stored = await bucket.download(roomFilePath(access.data.workspace, room, file))
    if (stored.error || !stored.data || stored.data.size !== access.data.size_bytes || stored.data.size > workspaceFileMaximum) return unavailable()
    const bytes = Buffer.from(await stored.data.arrayBuffer())
    const current = await command('get')
    if (current.error || !current.data || current.data.workspace !== access.data.workspace ||
      current.data.size_bytes !== bytes.length || current.data.sha256 !== digestWorkspaceBytes(bytes)) return unavailable()
    const changed = await checkFileEgress(auth.client, 'room', room, file, 'download')
    if (changed) return changed
    return new Response(Uint8Array.from(bytes), { headers: { ...fileHeaders, 'Content-Type': 'application/octet-stream',
      'Content-Disposition': 'attachment' } })
  }
  const mime = request.headers.get('content-type') || ''
  if (!filename || [...filename].length > 140 || /[\/\\\p{Cc}]/u.test(filename) || mime.length > 100) {
    return fileFailure(400, 'Choose a supported room file.')
  }
  if (Number(request.headers.get('content-length')) > workspaceFileMaximum) return fileFailure(413, 'Choose a file up to 4 MiB.')
  const gate = await command('access')
  if (gate.error) return fileFailure(503, 'Room file authorization is unavailable.')
  if (!gate.data) return unavailable()
  const bytes = await readAttachmentUpload(request, workspaceFileMaximum).catch(() => null)
  if (bytes === undefined) return fileFailure(413, 'Choose a file up to 4 MiB.')
  if (!bytes?.length) return fileFailure(400, 'Choose a file that contains data.')
  if (!allowedFileType(filename, mime, bytes)) return fileFailure(415, 'The file contents do not match a supported attachment type.')
  const hash = digestWorkspaceBytes(bytes)
  const document = attachmentDocumentFormat(filename)
  const scan = await scanAttachment(bytes, hash, document)
  if (scan.verdict === 'malware' || scan.reason || inspectAttachment(filename, bytes)) {
    return fileFailure(422, 'The room file was blocked by security inspection.')
  }
  if (scan.unsupported) return fileFailure(415, 'The document structure is outside supported inspection limits.')
  if (scan.verdict !== 'clean' || (officeFormatPattern.test(filename) && !scan.validatedFormat)) {
    return fileFailure(503, 'Room file security scanning is unavailable.')
  }
  const reservation = await command('reserve', bytes.length, hash)
  if (reservation.error?.code === 'PT413') return fileFailure(413, 'The room file storage limit was reached.')
  if (reservation.error?.code === 'PT422') return fileFailure(422, 'The room file was blocked by security scanning.')
  if (reservation.error) return fileFailure(503, 'Room file storage is unavailable.')
  if (!reservation.data) return unavailable()
  const path = roomFilePath(reservation.data.workspace, room, file)
  if (!reservation.data.uploaded) await bucket.upload(path, bytes, { contentType: 'application/octet-stream', upsert: false, cacheControl: '0' })
  const stored = await bucket.download(path)
  if (stored.error || !stored.data || stored.data.size !== bytes.length ||
    digestWorkspaceBytes(Buffer.from(await stored.data.arrayBuffer())) !== hash) return fileFailure(409, 'The room file could not be verified.')
  const published = await command('publish', bytes.length, hash)
  if (published.error?.code === 'PT422') return fileFailure(422, 'The room file was blocked by security scanning.')
  if (published.error) return fileFailure(503, 'The room file could not be published.')
  return published.data ? Response.json(published.data, { headers: fileHeaders }) : unavailable()
}

export const GET = handle
export const POST = handle
export const DELETE = handle
