import { fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'
import { exportBucket, exportDigest, exportIdPattern, exportResponse, exportStorage, storeExport } from '../../../../lib/export-storage-server'
import { operationalReportViewer } from '../../../../lib/operational-report-server'

export const runtime = 'nodejs'
export const maxDuration = 30

type Context = { params: Promise<{ caseId: string }> }
type Operation = 'build' | 'download'
type Material = {
  case: string; actor: string; sha256: string; bytes: number; bundle?: string; artifact?: string
}
const format = { filename: 'sectalk-compliance-export.json', media_type: 'application/json' } as const
const unavailable = () => fileFailure(404, 'An approved export is unavailable for this session.')
const failed = () => fileFailure(503, 'The private export could not be completed.')

async function execute(request: Request, { params }: Context, operation: Operation) {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return fileFailure(401, 'Sign in to access compliance exports.')
  const { caseId } = await params
  if (!exportIdPattern.test(caseId)) return unavailable()
  const storage = exportStorage()
  if (!storage) return failed()
  const authorization = await viewer.client.rpc('st_v7_begin_compliance_operation', {
    p_case: caseId, p_operation: operation,
  })
  if (authorization.error?.code === 'PT409') return fileFailure(409, 'Refresh the case before trying this operation again.')
  if (authorization.error?.code === '42501' || !authorization.error && !authorization.data) return unavailable()
  if (authorization.error || typeof authorization.data !== 'string' || !exportIdPattern.test(authorization.data)) return failed()
  const ticket = authorization.data
  const finish = (artifact: string | null) => storage.rpc('st_v7_finish_compliance_operation', { p_ticket: ticket, p_artifact: artifact })
  let completed = false
  try {
    const read = await storage.rpc('st_v7_read_compliance_operation', { p_ticket: ticket })
    if (read.error) return failed()
    const material = read.data as Material | null
    if (!material || material.actor !== viewer.actor || material.case !== caseId.toLowerCase()) return unavailable()
    if (operation === 'build') {
      if (typeof material.bundle !== 'string') return failed()
      const bytes = Buffer.from(material.bundle, 'utf8')
      if (bytes.length !== material.bytes || exportDigest(bytes) !== material.sha256) return failed()
      const artifact = await storeExport(viewer.actor, { kind: 'compliance', scope_id: material.case }, format, bytes)
      if (!artifact) return failed()
      const result = await finish(artifact)
      if (result.error) return failed()
      if (result.data !== true) return unavailable()
      completed = true
      return Response.json({ sha256: material.sha256 }, { headers: fileHeaders })
    }
    if (!material.artifact || !exportIdPattern.test(material.artifact)) return unavailable()
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

export function POST(request: Request, context: Context) {
  return execute(request, context, 'build')
}

export function GET(request: Request, context: Context) {
  return execute(request, context, 'download')
}
