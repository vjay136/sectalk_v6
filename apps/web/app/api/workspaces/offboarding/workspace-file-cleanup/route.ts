import { handleFileRegistrationCleanup } from '../../../../../lib/offboarding-file-cleanup'

export const runtime = 'nodejs'
export const maxDuration = 30

export function POST(request: Request) {
  return handleFileRegistrationCleanup(request, 'workspace')
}
