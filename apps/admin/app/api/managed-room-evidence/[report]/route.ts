import { GET as evidence } from '../../../../../web/app/api/managed-room-evidence/[report]/route'

export const runtime = 'nodejs'

export function GET(request: Request, context: {params: Promise<{report: string}>}) {
  return evidence(request, context)
}
