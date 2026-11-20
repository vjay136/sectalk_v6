export async function readAttachmentUpload(request: Request, maximumBytes: number) {
  const reader = request.body?.getReader()
  if (!reader) return null
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return Buffer.concat(chunks, size)
      size += value.byteLength
      if (size > maximumBytes) {
        void reader.cancel().catch(() => undefined)
        return undefined
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
}
export function readUploadFilename(request: Request) {
  const value = request.headers.get('x-sectalk-file-name')
  if (!value || value.length > 1680) return null
  try { return decodeURIComponent(value).trim() } catch { return null }
}
