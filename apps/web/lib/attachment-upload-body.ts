export { readBoundedBody as readAttachmentUpload } from './request-body'
export function readUploadFilename(request: Request) {
  const value = request.headers.get('x-sectalk-file-name')
  if (!value || value.length > 1680) return null
  try { return decodeURIComponent(value).trim() } catch { return null }
}
