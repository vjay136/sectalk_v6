export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export function GET() {
  return Response.json({ status:'ok', service:'sectalk-workers' }, {
    headers:{ 'Cache-Control':'no-store' },
  })
}
