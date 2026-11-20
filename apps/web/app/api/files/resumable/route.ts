import { createHash } from 'node:crypto'
import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'
import { validFileId } from '../../../../lib/file-download-ticket'
import { allowedFileType } from '../../../../lib/file-type-policy'
import { readAttachmentUpload } from '../../../../lib/attachment-upload-body'
import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'

export const runtime = 'nodejs'
export const maxDuration = 60

const maximumChunkBytes = 256 * 1024
const maximumUploadBytes = 4 * 1024 * 1024
const checksum = /^[0-9a-f]{64}$/

function hash(bytes: Buffer) {
  return createHash('sha256').update(bytes).digest('hex')
}

async function handle(request: Request, append: boolean) {
  const query = new URL(request.url).searchParams
  const file = query.get('file')?.toLowerCase()
  const sha256 = request.headers.get('x-sectalk-upload-sha256')
  const mime = request.headers.get('x-sectalk-file-type') || ''
  const action = append ? 'chunk' : query.get('action')
  if (!validFileId(file) || !sha256 || !checksum.test(sha256) || mime.length > 100 ||
    (action !== 'status' && action !== 'chunk' && action !== 'assemble') || (!append && action === 'chunk')) {
    return fileFailure(400, 'Invalid attachment upload request.')
  }
  const auth = await authenticateFileRequest(request)
  if (auth instanceof Response) return auth
  const record = (operation: string, offset: number | null = null, chunk: Buffer | null = null, chunkHash: string | null = null) =>
    auth.storage.rpc('st_v6_resumable_attachment', {
      p_file: file, p_actor: auth.actor, p_action: operation, p_sha256: sha256,
      p_offset: offset, p_chunk: chunk?.toString('base64') ?? null, p_chunk_hash: chunkHash,
    })
  type Result = Awaited<ReturnType<typeof record>>
  function fail(result: Result) {
    const error = result.error
    if (!error) return fileFailure(404, 'Attachment upload unavailable.')
    const code = error.code
    if (code === 'PT409' || code === 'PT413' || code === 'PT422' || code === '22023') {
      return fileFailure(code === '22023' ? 400 : Number(code.slice(2)), error.message)
    }
    return fileFailure(503, 'Attachment upload could not be verified.')
  }
  if (append) {
    const offset = query.get('offset')
    const chunkHash = request.headers.get('x-sectalk-chunk-sha256')
    if (!offset || !/^(0|[1-9][0-9]{0,6})$/.test(offset) || Number(offset) >= maximumUploadBytes ||
      !chunkHash || !checksum.test(chunkHash)) return fileFailure(400, 'Invalid attachment chunk.')
    if (Number(request.headers.get('content-length')) > maximumChunkBytes) return fileFailure(413, 'The attachment chunk is too large.')
    const chunk = await readAttachmentUpload(request, maximumChunkBytes).catch(() => null)
    if (chunk === undefined) return fileFailure(413, 'The attachment chunk is too large.')
    if (!chunk?.length) return fileFailure(400, 'The attachment chunk is empty.')
    if (hash(chunk) !== chunkHash) return fileFailure(422, 'The attachment chunk failed checksum verification.')
    const result = await record(action, Number(offset), chunk, chunkHash)
    return result.error || !result.data ? fail(result) : Response.json(result.data, { headers: fileHeaders })
  }
  const result = await record(action)
  if (result.error || !result.data) return fail(result)
  const bucket = auth.storage.storage.from('sectalk-chat-files')
  async function verifiedStorage(size: number) {
    const actual = await bucket.download(file!)
    return !actual.error && actual.data?.size === size && size <= maximumUploadBytes &&
      hash(Buffer.from(await actual.data.arrayBuffer())) === sha256
  }
  if (result.data.verify_existing) {
    if (!await verifiedStorage(result.data.offset)) return fileFailure(409, 'The attachment in Storage could not be verified.')
    return Response.json({ offset: result.data.offset, uploaded: true }, { headers: fileHeaders })
  }
  if (action === 'status' || result.data.uploaded) return Response.json(result.data, { headers: fileHeaders })
  const bytes = Buffer.from(result.data.bytes, 'base64')
  if (!bytes.length || bytes.length > maximumUploadBytes || hash(bytes) !== sha256) {
    return fileFailure(422, 'The full attachment failed checksum verification.')
  }
  if (!allowedFileType(result.data.filename, mime, bytes)) {
    return fileFailure(415, 'The file contents do not match an allowed attachment type.')
  }
  await bucket.upload(file, bytes, { contentType: 'application/octet-stream', cacheControl: '0', upsert: false })
  // A retry may find the previous verified upload after its acknowledgement was interrupted.
  if (!await verifiedStorage(bytes.length)) {
    return fileFailure(409, 'The attachment in Storage could not be verified.')
  }
  const completed = await record('finish')
  return completed.error || !completed.data ? fail(completed) : Response.json(completed.data, { headers: fileHeaders })
}

export async function POST(request: Request) {
  return withOperationalMetrics('file_upload', () => handle(request, false))
}

export async function PUT(request: Request) {
  return withOperationalMetrics('file_upload', () => handle(request, true))
}
