import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'
import { validFileId } from '../../../../lib/file-download-ticket'
import { maximumPdfPreviewBytes, renderFilePreview } from '../../../../lib/file-preview-server'

export const runtime = 'nodejs'

export async function GET(request: Request) {
  const file = new URL(request.url).searchParams.get('file')
  if (!validFileId(file)) return fileFailure(400, 'Choose a valid attachment.')
  const auth = await authenticateFileRequest(request)
  if (auth instanceof Response) return auth
  const access = () => auth.client.rpc('st_v6_view_file_details', { p_file: file }).maybeSingle<{
    filename: string
    size_bytes: number
  }>()
  const initial = await access()
  if (initial.error?.code === 'PT429') return fileFailure(429, 'Wait a minute before trying another preview.')
  if (initial.error) return fileFailure(503, 'Attachment permissions could not be verified.')
  if (!initial.data) return fileFailure(404, 'Attachment unavailable.')
  const { filename, size_bytes } = initial.data
  if (!/\.(png|jpe?g|webp|gif|txt|pdf)$/i.test(filename)) return fileFailure(415, 'Preview is unavailable for this file type.')
  const limit = /\.pdf$/i.test(filename) ? maximumPdfPreviewBytes : 4 * 1024 * 1024
  if (!(size_bytes > 0 && size_bytes <= limit)) return fileFailure(413, 'The attachment is too large to preview.')
  const { data, error } = await auth.storage.storage.from('sectalk-chat-files').download(file)
  if (error || !data || data.size !== size_bytes) return fileFailure(404, 'Attachment unavailable.')
  const preview = await renderFilePreview(filename, Buffer.from(await data.arrayBuffer()))
  if (!preview) return fileFailure(415, 'This attachment could not be safely previewed.')
  if (preview.kind === 'busy') return fileFailure(503, 'Preview is busy. Try again shortly.')
  if (preview.kind === 'offline') return fileFailure(503, 'PDF preview is unavailable here.')
  const current = await access()
  if (current.error?.code === 'PT429') return fileFailure(429, 'Wait a minute before trying another preview.')
  if (current.error) return fileFailure(503, 'Attachment permissions could not be verified.')
  if (!current.data) return fileFailure(404, 'Attachment unavailable.')
  if (preview.kind === 'text') return Response.json(preview, { headers: fileHeaders })
  return new Response(preview.data.buffer as ArrayBuffer, {
    headers: { ...fileHeaders, 'Content-Type': 'image/png', 'Content-Security-Policy': "default-src 'none'; sandbox" },
  })
}
