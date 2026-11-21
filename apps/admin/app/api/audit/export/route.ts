import { GET as publicKey, POST as exportAudit } from '../../../../../web/app/api/audit/export/route'
import { operatorAccess } from '../../../../lib/operator-access'

export const runtime = 'nodejs'
export const maxDuration = 30

async function authorized(request: Request, handler: (request: Request) => Response | Promise<Response>) {
  const access = await operatorAccess(request)
  if (access.access !== 'verified') {
    return Response.json({error: 'Operator verification is required.'}, {
      status: access.status === 200 ? 403 : access.status, headers: {'Cache-Control': 'no-store'},
    })
  }
  return handler(request)
}

export function GET(request: Request) {return authorized(request, publicKey)}
export function POST(request: Request) {return authorized(request, exportAudit)}
