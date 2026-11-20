export async function readBoundedBody(request: Pick<Request, 'headers' | 'body'>, maximumBytes: number) {
  const declared = request.headers.get('content-length')
  if (declared && /^\d+$/.test(declared) && Number(declared) > maximumBytes) return undefined
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

export async function readBoundedText(request: Pick<Request, 'headers' | 'body'>, maximumBytes: number) {
  const bytes = await readBoundedBody(request, maximumBytes)
  return bytes == null ? bytes : new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
}
