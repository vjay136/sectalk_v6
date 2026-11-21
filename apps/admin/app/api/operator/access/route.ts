import { operatorAccess } from '../../../../lib/operator-access'

export async function GET(request: Request) {
  const {status, ...access} = await operatorAccess(request)
  return Response.json(access, {status, headers: {'Cache-Control': 'private, no-store'}})
}
