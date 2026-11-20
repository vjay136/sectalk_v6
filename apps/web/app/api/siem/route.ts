import { operationalReportViewer } from '../../../lib/operational-report-server'
import { readBoundedText } from '../../../lib/request-body'
import { siemConnectors, siemEnvelope, siemUuid, signingKey } from '../../../lib/siem-export-server'

export const runtime = 'nodejs'
const headers = {'Cache-Control': 'no-store'}
const invalid = () => new Response(null, {status: 400, headers})
const unavailable = () => new Response(null, {status: 503, headers})
const forbidden = () => new Response('Fresh MFA and enterprise workspace ownership are required.', {status: 403, headers})

export async function GET(request: Request) {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return new Response(null, {status: 401, headers})
  const params = new URL(request.url).searchParams
  const workspace = params.get('workspace')?.toLowerCase() ?? ''
  const batch = params.get('batch')
  if (!siemUuid.test(workspace) || (batch !== null && !siemUuid.test(batch))) return invalid()
  const result = await viewer.client.rpc('st_v7_siem_batch_read', {p_workspace: workspace, p_batch: batch})
  if (result.error) return result.error.code === '42501' ? forbidden() : unavailable()
  try {
    if (!batch) {
      const payment = await viewer.client.rpc('st_v7_workspace_payment_state', {p_workspace:workspace})
      const channels = payment.error || payment.data?.mode === 'read_only' ? [] :
        siemConnectors().filter(row => row.workspace === workspace).map(row => row.channel)
      return Response.json({batches: result.data, channels}, {headers})
    }
    if (!result.data) return new Response(null, {status: 404, headers})
    return new Response(siemEnvelope(result.data), {headers: {...headers, 'Content-Type': 'application/json',
      'Content-Disposition': 'attachment; filename="sectalk-siem-' + result.data.id + '.json"'}})
  } catch { return unavailable() }
}

export async function POST(request: Request) {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return new Response(null, {status: 401, headers})
  let workspace, period, channel
  try {
    const text = await readBoundedText(request, 512)
    if (text === undefined) return new Response(null, {status: 413, headers})
    ;({workspace, period, channel} = JSON.parse(text ?? 'null'))
  } catch { return invalid() }
  if (typeof workspace !== 'string' || !siemUuid.test(workspace) || typeof period !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z$/.test(period)
    || !['download', 'webhook', 'syslog', 's3'].includes(channel)) return invalid()
  workspace = workspace.toLowerCase()
  const scope = await viewer.client.rpc('st_v7_siem_batch_read', {p_workspace: workspace})
  if (scope.error) return scope.error.code === '42501' ? forbidden() : unavailable()
  try {
    signingKey()
    if (channel !== 'download' && !siemConnectors().some(row => row.workspace === workspace && row.channel === channel)) {
      return unavailable()
    }
  } catch { return unavailable() }
  const result = await viewer.client.rpc('st_v7_siem_batch', {p_workspace: workspace, p_period: period, p_channel: channel})
  if (result.error) {
    if (result.error.code === '42501') return forbidden()
    if (result.error.code === 'PT423') return new Response(null,{status:423,headers})
    if (['22007', '22008', '22023'].includes(result.error.code)) return invalid()
    return unavailable()
  }
  return Response.json({id: result.data}, {headers})
}
