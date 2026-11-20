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

function escapeXml(line: string) {
  const entities: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
  return line.replace(/[&<>"']/g, char => entities[char])
}

export async function renderSharedAttachmentPreview(
  filename: string, bytes: Buffer, watermark: boolean,
): Promise<FilePreview | null> {
  const preview = await renderFilePreview(filename, bytes)
  if (!preview || preview.kind === 'offline' || preview.kind === 'busy' ||
      (preview.kind === 'image' && !watermark)) return preview
  if (runningDecodes >= 2) return { kind: 'busy' }
  runningDecodes++
  try {
    let image: Buffer
    if (preview.kind === 'text') {
      const lines = preview.text.split(/\r?\n/).flatMap(line => {
        const characters = Array.from(line.replace(/\t/g, '    '))
        return characters.length ? Array.from({ length: Math.ceil(characters.length / 64) }, (_, index) =>
          characters.slice(index * 64, (index + 1) * 64).join('')) : ['']
      }).slice(0, 24)
      const height = 30 + lines.length * 20
      const text = lines.map((line, index) =>
        `<text x="16" y="${28 + index * 20}">${escapeXml(line)}</text>`).join('')
      const page = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="768" height="${height}">
        <rect width="768" height="${height}" fill="#ffffff"/>
        <g font-family="monospace" font-size="15" fill="#111827" xml:space="preserve">${text}</g></svg>`)
      image = await sharp(page).timeout({ seconds: 7 }).png().toBuffer()
    } else image = Buffer.from(preview.data)
    if (watermark) {
      const { width, height } = await sharp(image).metadata()
      if (!width || !height) return null
      const canvasWidth = Math.max(185, width)
      const banner = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${canvasWidth}" height="30">
        <rect width="${canvasWidth}" height="30" fill="#172435"/>
        <text x="8" y="20" fill="#ffffff" font-family="sans-serif" font-size="13">SecTalk · View-only</text></svg>`)
      image = await sharp({ create: { width: canvasWidth, height: height + 30, channels: 4, background: '#ffffff' } })
        .composite([{ input: image, left: Math.floor((canvasWidth - width) / 2), top: 0 },
          { input: banner, left: 0, top: height }]).timeout({ seconds: 7 }).png().toBuffer()
    }
    return image.length <= 3 * 1024 * 1024 ? { kind: 'image', data: Uint8Array.from(image) } : null
  } catch {
    return null
  } finally {
    runningDecodes--
  }
}
