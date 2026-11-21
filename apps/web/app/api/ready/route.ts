import { readinessResponse } from '../../../lib/readiness'

export function GET() {
  return readinessResponse('web')
}
