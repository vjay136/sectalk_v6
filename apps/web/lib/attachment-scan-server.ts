type Verdict = 'clean' | 'malware' | 'unavailable'

export function attachmentScannerConfigured() {
  return Boolean(process.env.SECTALK_MALWARE_SCANNER_URL || process.env.SECTALK_MALWARE_SCANNER_SECRET)
}

export async function scanAttachment(bytes: Buffer, hash: string): Promise<Verdict> {
  const address = process.env.SECTALK_MALWARE_SCANNER_URL
  const key = process.env.SECTALK_MALWARE_SCANNER_SECRET
  if (!address || !key || Buffer.byteLength(key) < 32 || bytes.length === 0 || bytes.length > 4 * 1024 * 1024) {
    return 'unavailable'
  }
  try {
    const origin = new URL(address)
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)
    if (!(origin.protocol === 'https:' || (origin.protocol === 'http:' && loopback)) ||
        origin.username || origin.password || origin.search || origin.hash) return 'unavailable'
    const response = await fetch(new URL('/scan', origin), {
      method: 'POST', redirect: 'error', cache: 'no-store',
      headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/octet-stream' },
      body: Uint8Array.from(bytes), signal: AbortSignal.timeout(11000),
    })
    if (!response.ok || response.headers.get('content-type') !== 'application/json') return 'unavailable'
    const reader = response.body?.getReader()
    if (!reader) return 'unavailable'
    const chunks: Uint8Array[] = []
    let size = 0
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        size += value.length
        if (size > 512) {
          void reader.cancel().catch(() => undefined)
          return 'unavailable'
        }
        chunks.push(value)
      }
    } finally {
      reader.releaseLock()
    }
    const result = JSON.parse(Buffer.concat(chunks, size).toString('utf8'))
    if (result.sha256 !== hash || (result.verdict !== 'clean' && result.verdict !== 'malware')) return 'unavailable'
    return result.verdict
  } catch {
    return 'unavailable'
  }
}
