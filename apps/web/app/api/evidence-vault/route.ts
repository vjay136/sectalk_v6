import { fileFailure, fileHeaders } from '../../../lib/authenticated-file-request'
import { readAttachmentUpload } from '../../../lib/attachment-upload-body'
import { exportBucket, exportDigest, exportIdPattern, exportResponse, exportStorage, storeExport } from '../../../lib/export-storage-server'
import { operationalReportViewer } from '../../../lib/operational-report-server'

export const runtime = 'nodejs'
export const maxDuration = 30

const format = { filename: 'sectalk-evidence-snapshot.json', media_type: 'application/json' } as const
const unavailable = () => fileFailure(404, 'The requested evidence is unavailable for this session.')
const failed = () => fileFailure(503, 'The private evidence operation could not be completed.')
const invalid = () => fileFailure(400, 'Choose an exact case, report, and preservation hold.')
const validId = (value: unknown): value is string => typeof value === 'string' && exportIdPattern.test(value)
type Capture = { caseId: string; report: string; hold: string; reason: string }
type Material = { snapshot: string; actor: string; sha256: string; bytes: number; payload?: string; artifact?: string }

async function execute(request: Request, input: Capture | string) {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return fileFailure(401, 'Sign in to access the evidence vault.')
  const storage = exportStorage()
  if (!storage) return failed()
  const capture = typeof input !== 'string'
  const operation = capture ? {
    p_operation: 'capture', p_case: input.caseId, p_report: input.report, p_hold: input.hold, p_reason: input.reason,
  } : { p_operation: 'download', p_snapshot: input }
  const permission = await viewer.client.rpc('st_v7_begin_evidence_operation', operation)
  if (permission.error?.code === '42501') return unavailable()
  if (permission.error?.code === '22023') return fileFailure(400, permission.error.message)
  if (permission.error?.code === 'PT409') return fileFailure(409, permission.error.message)
  if (permission.error || !validId(permission.data)) return failed()
  const ticket = permission.data
  const finish = (artifact: string | null) => storage.rpc('st_v7_finish_evidence_operation', { p_ticket: ticket, p_artifact: artifact })
  let completed = false
  try {
    const read = await storage.rpc('st_v7_read_evidence_operation', { p_ticket: ticket })
    if (read.error) return failed()
    const material = read.data as Material | null
    if (!material || material.actor !== viewer.actor || !validId(material.snapshot) ||
      (!capture && material.snapshot !== input.toLowerCase())) return unavailable()
    if (capture) {
      if (typeof material.payload !== 'string') return failed()
      const bytes = Buffer.from(material.payload, 'utf8')
      if (bytes.length !== material.bytes || exportDigest(bytes) !== material.sha256) return failed()
      const artifact = await storeExport(viewer.actor, { kind: 'evidence', scope_id: material.snapshot }, format, bytes)
      if (!artifact) return failed()
      const result = await finish(artifact)
      if (result.error) return failed()
      if (result.data !== true) return unavailable()
      completed = true
      return Response.json({ id: material.snapshot, sha256: material.sha256 }, { status: 201, headers: fileHeaders })
    }
    if (!validId(material.artifact)) return unavailable()
    const object = await storage.storage.from(exportBucket).download(material.artifact)
    if (object.error || object.data.size !== material.bytes) return unavailable()
    const bytes = Buffer.from(await object.data.arrayBuffer())
    if (exportDigest(bytes) !== material.sha256) return unavailable()
    const result = await finish(material.artifact)
    if (result.error) return failed()
    if (result.data !== true) return unavailable()
    completed = true
    return exportResponse(bytes, format)
  } catch {
    return failed()
  } finally {
    if (!completed) await finish(null).then(undefined, () => undefined)
  }
}

export async function POST(request: Request) {
  if (Number(request.headers.get('content-length')) > 2048) return invalid()
  let input
  try {
    const body = await readAttachmentUpload(request,2048)
    if (!body) return invalid()
    input = JSON.parse(body.toString('utf8'))
  } catch { return invalid() }
  if (!validId(input?.caseId) || !validId(input?.report) || !validId(input?.hold) ||
    typeof input?.reason !== 'string' || [...input.reason.trim()].length > 300) return invalid()
  return execute(request, input)
}

export function GET(request: Request) {
  const snapshot = new URL(request.url).searchParams.get('snapshot')
  return validId(snapshot) ? execute(request, snapshot) : unavailable()
}
