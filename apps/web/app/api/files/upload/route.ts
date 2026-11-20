import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'
import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'
import { validFileId } from '../../../../lib/file-download-ticket'
import { allowedFileType } from '../../../../lib/file-type-policy'

export const runtime = 'nodejs'
export const maxDuration = 60

const maximumUploadBytes = 4 * 1024 * 1024
const attachmentBucket = 'sectalk-chat-files'

async function readUpload(request: Request) {
  const reader = request.body?.getReader()
  if (!reader) return null
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return Buffer.concat(chunks, size)
      size += value.byteLength
      if (size > maximumUploadBytes) {
        void reader.cancel().catch(() => undefined)
        return undefined
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
}

async function handlePost(request: Request) {
  const file = new URL(request.url).searchParams.get('file')
  const mime = request.headers.get('content-type') || ''
  if (!validFileId(file) || mime.length > 100) return fileFailure(400, 'Invalid attachment request.')
  if (Number(request.headers.get('content-length')) > maximumUploadBytes) {
    return fileFailure(413, 'This file exceeds the 4 MiB upload limit.')
  }
  const auth = await authenticateFileRequest(request)
  if (auth instanceof Response) return auth
  const bytes = await readUpload(request).catch(() => null)
  if (bytes === undefined) return fileFailure(413, 'This file exceeds the 4 MiB upload limit.')
  if (!bytes?.length) return fileFailure(400, 'Attach a file that contains data.')

  const authorize = () => auth.storage.rpc('st_v6_authorize_file_upload', {
    p_file: file, p_actor: auth.actor, p_bytes: bytes.length,
  })
  const permission = await authorize()
  if (permission.error?.code === 'PT413') return fileFailure(413, permission.error.message)
  if (permission.error?.code === 'PT409') return fileFailure(409, permission.error.message)
  if (permission.error) return fileFailure(503, 'Attachment permissions could not be verified.')
  if (!permission.data) return fileFailure(404, 'Attachment unavailable.')
  if (!allowedFileType(permission.data.filename, mime, bytes)) {
    return fileFailure(415, 'The file contents do not match an allowed attachment type.')
  }
  if (!permission.data.uploaded) {
    const { error } = await auth.storage.storage.from(attachmentBucket).upload(file, bytes, {
      contentType: 'application/octet-stream', cacheControl: '0', upsert: false,
    })
    if (error) {
      // A concurrent retry can finish the same non-overwriting upload first.
      const retry = await authorize()
      if (!retry.data?.uploaded) return fileFailure(409, 'The attachment could not be uploaded.')
    }
  }
  return Response.json({ id: file }, { headers: fileHeaders })
}

export async function POST(request: Request) {
  return withOperationalMetrics('file_upload', () => handlePost(request))
}
