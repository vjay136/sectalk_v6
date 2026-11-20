import { createClient } from '@supabase/supabase-js'
import { fileAuthOptions, fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'
import { maximumPdfPreviewBytes, renderSharedAttachmentPreview } from '../../../../lib/file-preview-server'

export const runtime = 'nodejs'
export const maxDuration = 30

async function readInput(request: Request) {
  const reader = request.body?.getReader()
  if (!reader) return null
  let size = 0
  const decoder = new TextDecoder()
  let body = ''
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return JSON.parse(body + decoder.decode())
      size += value.byteLength
      if (size > 1024) {
        void reader.cancel().catch(() => undefined)
        return null
      }
      body += decoder.decode(value, { stream: true })
    }
  } finally {
    reader.releaseLock()
  }
}

export async function POST(request: Request) {
  const input = await readInput(request).catch(() => null)
  if (typeof input?.token !== 'string' || !/^[a-f0-9]{64}$/.test(input.token) ||
      typeof input.password !== 'string' || Buffer.byteLength(input.password) < 10 || Buffer.byteLength(input.password) > 64 ||
      (input.action !== 'view' && input.action !== 'download' && input.action !== 'preview')) {
    return fileFailure(400, 'Enter a valid link and password.')
  }
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SECTALK_FILE_STORAGE_KEY
  if (!url || !key) return fileFailure(503, 'Shared attachments are unavailable.')
  const storage = createClient(url, key, fileAuthOptions)
  const access = (action: 'view' | 'peek' | 'download' | 'preview_peek' | 'preview') => storage.rpc('st_v6_access_file_share', {
    p_token: input.token, p_password: input.password, p_action: action,
  })
  const previewRequest = input.action === 'preview'
  const permission = await access(input.action === 'view' ? 'view' : previewRequest ? 'preview_peek' : 'peek')
  if (permission.error) return fileFailure(503, 'Shared attachments are unavailable.')
  if (!permission.data) return fileFailure(404, 'The link or password is unavailable.')
  const { file, filename, size_bytes, view_only, watermark } = permission.data
  if (input.action === 'view') return Response.json({ filename, size_bytes, view_only }, { headers: fileHeaders })
  if (previewRequest !== view_only) return fileFailure(404, 'The link or password is unavailable.')
  const sizeLimit = previewRequest && /\.pdf$/i.test(filename) ? maximumPdfPreviewBytes : 4 * 1024 * 1024
  if (size_bytes < 1 || size_bytes > sizeLimit) return fileFailure(413, 'The attachment is too large.')

  const { data, error } = await storage.storage.from('sectalk-chat-files').download(file)
  if (error || !data || data.size !== size_bytes) return fileFailure(404, 'The shared attachment is unavailable.')
  if (previewRequest) {
    const preview = await renderSharedAttachmentPreview(filename, Buffer.from(await data.arrayBuffer()), watermark === true)
    if (preview?.kind === 'offline' || preview?.kind === 'busy') return fileFailure(503, 'The attachment preview is unavailable.')
    if (preview?.kind !== 'image') return fileFailure(415, 'This attachment could not be safely previewed.')
    const redemption = await access('preview')
    if (redemption.error) return fileFailure(503, 'Shared attachments are unavailable.')
    if (!redemption.data || redemption.data.file !== file || redemption.data.view_only !== true)
      return fileFailure(404, 'The link or password is unavailable.')
    return new Response(preview.data.buffer as ArrayBuffer, { headers: { ...fileHeaders, 'Content-Type': 'image/png',
      'Content-Security-Policy': "default-src 'none'; sandbox" } })
  }
  const redemption = await access('download')
  if (redemption.error) return fileFailure(503, 'Shared attachments are unavailable.')
  if (!redemption.data || redemption.data.file !== file || redemption.data.view_only !== false)
    return fileFailure(404, 'The link or password is unavailable.')
  return new Response(data, { headers: { ...fileHeaders, 'Content-Type': 'application/octet-stream',
    'Content-Disposition': 'attachment' } })
}
