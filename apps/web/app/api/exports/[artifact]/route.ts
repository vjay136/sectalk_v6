import { fileHeaders } from '../../../../lib/authenticated-file-request'
import { exportBucket, exportDigest, exportIdPattern, exportResponse, exportStorage, type StoredExport } from '../../../../lib/export-storage-server'
import { operationalReportViewer } from '../../../../lib/operational-report-server'

export const runtime = 'nodejs'
export const maxDuration = 30

function auditReferences(bytes: Buffer) {
  try {
    const payload = JSON.parse(JSON.parse(bytes.toString('utf8')).payload)
    if (!Array.isArray(payload.entries) || payload.entries.length > 100) return null
    return payload.entries.map((entry: { id: number; source: 'workspace' | 'room' }) => ({
      id: entry.id, source: entry.source,
    }))
  } catch {
    return null
  }
}

export async function GET(request: Request, context: { params: Promise<{ artifact: string }> }) {
  const unavailable = (status: number) => new Response(null, { status, headers: fileHeaders })
  const viewer = await operationalReportViewer(request)
  if (!viewer) return unavailable(401)
  const { artifact } = await context.params
  if (!exportIdPattern.test(artifact)) return unavailable(404)
  const storage = exportStorage()
  if (!storage) return unavailable(503)
  const record = await storage.rpc('st_v6_get_export_object', { p_artifact: artifact, p_actor: viewer.actor })
  if (record.error) return unavailable(503)
  if (!record.data) return unavailable(404)
  const metadata = record.data as StoredExport

  let authorized = false
  if (metadata.kind === 'audit') {
    const result = await viewer.client.rpc('st_v6_audit_integrity_status', { p_workspace: metadata.scope_id, p_rows: [] })
    authorized = !result.error && result.data?.can_export === true
  } else if (metadata.kind === 'operations') {
    const result = await viewer.client.rpc('st_v6_operational_report_export', { p_run: metadata.scope_id })
    authorized = !result.error && Boolean(result.data)
  } else if (metadata.kind === 'security') {
    const result = await viewer.client.rpc('st_v6_security_report', { p_period: metadata.period })
    authorized = !result.error && Boolean(result.data)
  }
  if (!authorized) return unavailable(404)

  const download = await storage.storage.from(exportBucket).download(artifact)
  if (download.error || download.data.size !== metadata.bytes) return unavailable(404)
  const bytes = Buffer.from(await download.data.arrayBuffer())
  if (exportDigest(bytes) !== metadata.sha256) return unavailable(404)
  if (metadata.kind === 'audit') {
    const references = auditReferences(bytes)
    if (!references) return unavailable(404)
    if (references.length > 0) {
      const result = await viewer.client.rpc('st_v6_audit_integrity_status', {
        p_workspace: metadata.scope_id, p_rows: references,
      })
      if (result.error || result.data?.can_export !== true || result.data.state !== 'matched') return unavailable(404)
    }
  }
  return exportResponse(bytes, metadata)
}
