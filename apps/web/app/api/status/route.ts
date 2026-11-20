import { checkConfiguredDatabase } from '../../../lib/readiness'

export async function GET() {
  const ready = await checkConfiguredDatabase()
  return Response.json({
    web: 'reachable',
    database: ready ? 'ready' : 'unavailable',
    checkedAt: new Date().toISOString(),
  }, {
    status: ready ? 200 : 503,
    headers: { 'Cache-Control': 'no-store' },
  })
}
