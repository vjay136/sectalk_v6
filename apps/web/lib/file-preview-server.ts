import sharp from 'sharp'
import { allowedFileType } from './file-type-policy'

const textPreviewBytes = 8192
const maximumInputPixels = 8_000_000
const maximumImageSide = 4096
export const maximumPdfPreviewBytes = 1024 * 1024
let runningDecodes = 0

export type FilePreview = { kind: 'text'; text: string; truncated: boolean }
  | { kind: 'image'; data: Uint8Array } | { kind: 'busy' } | { kind: 'offline' }

async function rasterPdf(bytes: Buffer): Promise<FilePreview | null> {
  const configured = process.env.SECTALK_PDF_PREVIEW_WORKER_URL
  const key = process.env.SECTALK_PDF_WORKER_SECRET
  if (!configured || !key || Buffer.byteLength(key) < 32) return { kind: 'offline' }
  if (bytes.length > maximumPdfPreviewBytes) return null
  try {
    const url = new URL(configured)
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    if (!(url.protocol === 'https:' || (url.protocol === 'http:' && loopback))
      || url.username || url.password || url.search || url.hash) return { kind: 'offline' }
    const response = await fetch(new URL('/render', url), {
      method: 'POST', redirect: 'error', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/pdf' },
      body: Uint8Array.from(bytes), signal: AbortSignal.timeout(8000), cache: 'no-store',
    })
    if (response.status === 422 || response.status === 413) return null
    if (!response.ok || response.headers.get('Content-Type') !== 'image/png') return { kind: 'offline' }
    const size = Number(response.headers.get('Content-Length'))
    const reader = response.body?.getReader()
    if (!reader || !Number.isInteger(size) || size <= 0 || size > maximumPdfPreviewBytes) return null
    const chunks: Uint8Array[] = []
    let received = 0
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        received += value.length
        if (received > size) {
          void reader.cancel().catch(() => undefined)
          return null
        }
        chunks.push(value)
      }
    } finally {
      reader.releaseLock()
    }
    if (received !== size) return null
    // Decode the worker response and emit a fresh PNG even though the worker already rasterized it.
    return renderFilePreview('raster.png', Buffer.concat(chunks, received))
  } catch {
    return { kind: 'offline' }
  }
}

export async function renderFilePreview(filename: string, bytes: Buffer): Promise<FilePreview | null> {
  if (!/\.(png|jpe?g|webp|gif|txt|pdf)$/i.test(filename) || !allowedFileType(filename, '', bytes)) return null
  if (/\.pdf$/i.test(filename)) return rasterPdf(bytes)
  if (/\.txt$/i.test(filename)) {
    const truncated = bytes.length > textPreviewBytes
    const text = new TextDecoder().decode(bytes.subarray(0, textPreviewBytes), { stream: truncated })
      .replace(/[\u202a-\u202e\u2066-\u2069]/gu, '')
    return { kind: 'text', text, truncated }
  }
  if (runningDecodes >= 2) return { kind: 'busy' }
  runningDecodes++
  try {
    const image = sharp(bytes, { pages: 1, failOn: 'warning', limitInputPixels: maximumInputPixels }).timeout({ seconds: 3 })
    const { width, height, pageHeight } = await image.metadata()
    const frameHeight = pageHeight ?? height
    if (!width || !frameHeight || width > maximumImageSide || frameHeight > maximumImageSide ||
        width * frameHeight > maximumInputPixels) return null
    const data = await image.rotate().resize(768, 768, { fit: 'inside', withoutEnlargement: true }).png().toBuffer()
    return data.length <= 3 * 1024 * 1024 ? { kind: 'image', data: Uint8Array.from(data) } : null
  } catch {
    return null
  } finally {
    runningDecodes--
  }
}
