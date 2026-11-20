import { validAttachmentInspectionReason, type AttachmentInspectionReason } from './attachment-inspection'

type ScanResult = {
  verdict: 'clean' | 'malware' | 'unavailable'
  reason?: AttachmentInspectionReason
  unsupported?: boolean
  validatedFormat?: string
}
const unavailable: ScanResult = { verdict: 'unavailable' }

export function attachmentScannerConfigured() {
  return Boolean(process.env.SECTALK_MALWARE_SCANNER_URL || process.env.SECTALK_MALWARE_SCANNER_SECRET)
}

export async function scanAttachment(bytes: Buffer, hash: string, format?: string): Promise<ScanResult> {
  const address = process.env.SECTALK_MALWARE_SCANNER_URL
  const key = process.env.SECTALK_MALWARE_SCANNER_SECRET
  if (!address || !key || Buffer.byteLength(key) < 32 || bytes.length === 0 || bytes.length > 4 * 1024 * 1024) {
    return unavailable
  }
  try {
    const origin = new URL(address)
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)
    if (!(origin.protocol === 'https:' || (origin.protocol === 'http:' && loopback)) ||
        origin.username || origin.password || origin.search || origin.hash) return unavailable
    const headers: Record<string, string> = { Authorization: 'Bearer ' + key, 'Content-Type': 'application/octet-stream' }
    if (format) headers['X-SecTalk-Document-Format'] = format
    const response = await fetch(new URL('/scan', origin), {
      method: 'POST', redirect: 'error', cache: 'no-store',
      headers, body: Uint8Array.from(bytes), signal: AbortSignal.timeout(format ? 17000 : 11000),
    })
    if (!response.ok || response.headers.get('content-type') !== 'application/json') return unavailable
    const reader = response.body?.getReader()
    if (!reader) return unavailable
    const chunks: Uint8Array[] = []
    let size = 0
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        size += value.length
        if (size > 512) {
          void reader.cancel().catch(() => undefined)
          return unavailable
        }
        chunks.push(value)
      }
    } finally {
      reader.releaseLock()
    }
    const result = JSON.parse(Buffer.concat(chunks, size).toString('utf8'))
    if (result.sha256 !== hash || (result.verdict !== 'clean' && result.verdict !== 'malware')) return unavailable
    if (result.verdict === 'malware') return { verdict: 'malware' }
    if (!format || (format === 'pdf' && !result.inspection)) return { verdict: 'clean' }
    if (result.inspection?.format !== format) return unavailable
    if (result.inspection.status === 'unsupported') return { verdict: 'clean', unsupported: true }
    if (result.inspection.status !== 'inspected') return unavailable
    const reason = result.inspection.reason
    if (reason === null) return { verdict: 'clean', validatedFormat: format }
    return validAttachmentInspectionReason(reason) ? { verdict: 'clean', reason, validatedFormat: format } : unavailable
  } catch {
    return unavailable
  }
}
