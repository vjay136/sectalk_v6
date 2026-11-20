import { createHash } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fileAuthOptions, fileHeaders } from './authenticated-file-request'

const maximumExportBytes = 1024 * 1024
export const exportBucket = 'sectalk-exports'
export const exportIdPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
type ExportSource =
  | { kind: 'audit' | 'operations' | 'compliance' | 'evidence'; scope_id: string; period?: null }
  | { kind: 'security'; scope_id?: null; period: 'daily' | 'weekly' }
type ExportFormat = { filename: string; media_type: 'application/json' | 'text/csv' | 'application/pdf' }
export type StoredExport = ExportSource & ExportFormat & { bytes: number; sha256: string }

export function exportStorage() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SECTALK_FILE_STORAGE_KEY
  if (!url || !key) return null
  return createClient(url, key, { ...fileAuthOptions, global: {
    fetch: (input, options) => fetch(input, { ...options, signal: AbortSignal.timeout(5000) }),
  } })
}

export function exportDigest(bytes: Buffer) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function exportResponse(bytes: Buffer, format: ExportFormat, artifact?: string) {
  const headers = new Headers(fileHeaders)
  headers.set('Content-Type', format.media_type === 'text/csv' ? 'text/csv; charset=utf-8' : format.media_type)
  headers.set('Content-Disposition', 'attachment; filename="' + format.filename + '"')
  if (artifact) headers.set('X-SecTalk-Export-Location', '/api/exports/' + artifact)
  return new Response(Uint8Array.from(bytes), { headers })
}

export async function storeExport(actor: string, source: ExportSource, format: ExportFormat, bytes: Buffer) {
  const storage = exportStorage()
  if (!storage || bytes.length < 1 || bytes.length > maximumExportBytes) return undefined
  const reservation = await storage.rpc('st_v6_begin_export_object', {
    p_actor: actor, p_kind: source.kind, p_scope: source.scope_id ?? null, p_period: source.period ?? null,
    p_filename: format.filename, p_media: format.media_type, p_bytes: bytes.length, p_sha256: exportDigest(bytes),
  })
  if (reservation.error || typeof reservation.data !== 'string' || !exportIdPattern.test(reservation.data)) return undefined
  const artifact = reservation.data
  const upload = await storage.storage.from(exportBucket).upload(artifact, bytes, {
    contentType: format.media_type, upsert: false, cacheControl: '0',
  })
  if (upload.error) return undefined
  const finished = await storage.rpc('st_v6_finish_export_object', { p_artifact: artifact })
  return !finished.error && finished.data === true ? artifact : undefined
}

export async function saveExportResponse(actor: string, source: ExportSource, format: ExportFormat, content: Buffer | string) {
  const bytes = typeof content === 'string' ? Buffer.from(content) : content
  const artifact = await storeExport(actor, source, format, bytes).catch(() => undefined)
  return exportResponse(bytes, format, artifact)
}
