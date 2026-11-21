import { GET as readiness } from '../../../../web/app/api/ready/route'

export function GET() {
  return readiness()
}
