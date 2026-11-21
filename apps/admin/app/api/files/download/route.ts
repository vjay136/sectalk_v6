import { GET as download, POST as grant } from '../../../../../web/app/api/files/download/route'
import { fileFailure } from '../../../../../web/lib/authenticated-file-request'
import { operatorAccess } from '../../../../lib/operator-access'

export const runtime = 'nodejs'

async function evidence(request: Request, handler: (request: Request) => Promise<Response>) {
  const access = await operatorAccess(request)
  if (access.access !== 'verified' || !access.moderation) {
    return fileFailure(access.status === 200 ? 403 : access.status, 'Staff verification is required to download evidence.')
  }
  return handler(request)
}

export function GET(request: Request) {return evidence(request, download)}
export function POST(request: Request) {return evidence(request, grant)}
