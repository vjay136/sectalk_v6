import { readinessResponse } from '../../../../web/lib/readiness'

export function GET() {
  return readinessResponse('admin')
}
